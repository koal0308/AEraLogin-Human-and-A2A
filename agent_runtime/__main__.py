"""Agent Runtime CLI.

    python -m agent_runtime enroll CODE pair with the dashboard (generates the key locally)
    python -m agent_runtime keygen     generate a local keypair, print the PUBLIC key
    python -m agent_runtime run        start the runtime and serve the gateway
    python -m agent_runtime health     query a running runtime over its socket

`keygen` deliberately prints only the public key. The private key is written to
the local key file and is never displayed, logged or transmitted -- the operator
copies the public key into the dashboard, and the owner approves registration
with their wallet. The runtime never touches the owner's wallet key.
"""
from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import time

from .config import ConfigError, RuntimeConfig
from .identity import IdentityError, RevokedError, RuntimeIdentity
from .keystore import KeyStoreError, LocalKeyStore
from .lifecycle import LifecycleStatus, RuntimeState
from .provider import ProviderFailure, build_adapter
from .server import RuntimeServer

#: How often to re-check with AEra that we are still a valid agent.
LIVENESS_INTERVAL_SECONDS = 5 * 60


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def cmd_keygen(config: RuntimeConfig, args) -> int:
    store = LocalKeyStore(config.resolved_key_path)
    try:
        public_key = store.create(overwrite=args.force)
    except KeyStoreError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    info = store.describe()
    print(f"key file : {info.path}")
    print(f"mode     : {info.mode}")
    print(f"encrypted: {'yes (scrypt + AES-256-GCM)' if info.encrypted else 'NO'}")
    if not info.encrypted:
        print("           ^ set AERA_RUNTIME_KEY_PASSPHRASE to encrypt at rest")
    print()
    print("Register THIS public key in the AEra dashboard.")
    print("The private key stays in the file above and is never sent to AEra.")
    print()
    print(public_key)
    return 0


def cmd_enroll(config: RuntimeConfig, args) -> int:
    from .enroll import EnrollError, enroll

    try:
        enroll(code=args.code, base_url=config.aera_base_url,
               key_path=config.resolved_key_path, reuse_key=args.reuse_key,
               timeout=args.timeout)
    except (EnrollError, KeyStoreError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


def _build_runtime(config: RuntimeConfig) -> RuntimeServer:
    config.require_identity()

    store = LocalKeyStore(config.resolved_key_path)
    store.load()
    if not store.permissions_are_safe():
        logging.warning("key file %s is readable beyond its owner",
                        config.resolved_key_path)

    identity = RuntimeIdentity(
        base_url=config.aera_base_url,
        agent_id=config.agent_id,           # type: ignore[arg-type]
        key_id=config.key_id,               # type: ignore[arg-type]
        keystore=store,
        timeout=config.request_timeout,
    )
    provider = build_adapter(config.provider, model=config.model)
    return RuntimeServer(identity=identity, provider=provider,
                         status=LifecycleStatus(),
                         max_reply_chars=config.max_reply_chars)


def cmd_run(config: RuntimeConfig, args) -> int:
    from .internal_auth import internal_secret

    if not internal_secret():
        print("error: AERA_RUNTIME_INTERNAL_SECRET is not set. The runtime "
              "refuses to serve an unauthenticated internal channel.",
              file=sys.stderr)
        return 2

    try:
        runtime = _build_runtime(config)
    except (ConfigError, KeyStoreError, ProviderFailure) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    status = runtime.status
    status.set(RuntimeState.READY)
    logging.info("runtime configured %s", config.safe_dict())

    status.set(RuntimeState.AUTHENTICATING)
    try:
        runtime.identity.authenticate()
    except RevokedError as exc:
        status.set(RuntimeState.REVOKED, str(exc))
        print(f"error: {exc}", file=sys.stderr)
        return 3
    except IdentityError as exc:
        print(f"error: cannot authenticate with AEra: {exc}", file=sys.stderr)
        return 1

    status.set(RuntimeState.RUNNING)
    runtime.start()
    print(f"runtime RUNNING agent_id={config.agent_id} "
          f"provider={config.provider} socket={runtime.socket_path}")

    stopping = {"flag": False}

    def _stop(_signum, _frame):
        stopping["flag"] = True

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    last_check = time.monotonic()
    try:
        while not stopping["flag"]:
            time.sleep(0.5)
            if time.monotonic() - last_check < LIVENESS_INTERVAL_SECONDS:
                continue
            last_check = time.monotonic()
            # Revocation is discovered by AEra refusing us. The runtime never
            # decides for itself that it is still authorised.
            try:
                runtime.identity.check_liveness()
                if status.get() is RuntimeState.DEGRADED:
                    status.set(RuntimeState.RUNNING)
            except RevokedError as exc:
                logging.error("agent revoked: %s", exc)
                status.set(RuntimeState.REVOKED, "revoked by AEra")
                break
            except IdentityError as exc:
                logging.warning("liveness check failed: %s", exc)
                status.set(RuntimeState.DEGRADED, "aera unreachable")
    finally:
        runtime.stop()
        runtime.identity.close()

    print(f"runtime stopped ({status.get().value})")
    return 3 if status.is_revoked else 0


def cmd_health(config: RuntimeConfig, args) -> int:
    import socket as _socket
    import uuid

    from .internal_auth import build_envelope, internal_secret, socket_path_for

    config.require_identity()
    secret = internal_secret()
    if not secret:
        print("error: AERA_RUNTIME_INTERNAL_SECRET is not set", file=sys.stderr)
        return 2

    path = socket_path_for(config.agent_id)  # type: ignore[arg-type]
    if not path.is_socket():
        print(f"no runtime listening at {path}", file=sys.stderr)
        return 1

    envelope = build_envelope(agent_id=config.agent_id,  # type: ignore[arg-type]
                              request_id=str(uuid.uuid4()),
                              body={"op": "health"}, secret=secret)
    client = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
    client.settimeout(10)
    try:
        client.connect(str(path))
        client.sendall(json.dumps(envelope).encode("utf-8") + b"\n")
        data = client.recv(65536)
    finally:
        client.close()

    print(json.dumps(json.loads(data.decode("utf-8")).get("result", {}), indent=2))
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="agent_runtime",
                                     description="AEra packaged Agent Runtime")
    sub = parser.add_subparsers(dest="command", required=True)

    keygen = sub.add_parser("keygen", help="generate a local Ed25519 keypair")
    keygen.add_argument("--force", action="store_true",
                        help="overwrite an existing key (destroys the identity)")
    keygen.set_defaults(func=cmd_keygen)

    enroll_p = sub.add_parser(
        "enroll", help="pair with an AEra dashboard enrollment code (recommended)")
    enroll_p.add_argument("code", help="aera-enroll-… code from the dashboard")
    enroll_p.add_argument("--reuse-key", action="store_true",
                          help="enroll an existing, not yet registered local key")
    enroll_p.add_argument("--timeout", type=float, default=15 * 60,
                          help="seconds to wait for owner approval")
    enroll_p.set_defaults(func=cmd_enroll)

    run = sub.add_parser("run", help="run the agent runtime")
    run.set_defaults(func=cmd_run)

    health = sub.add_parser("health", help="query a running runtime")
    health.set_defaults(func=cmd_health)

    args = parser.parse_args(argv)
    config = RuntimeConfig.from_env()
    _configure_logging(config.log_level)
    try:
        return args.func(config, args)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
