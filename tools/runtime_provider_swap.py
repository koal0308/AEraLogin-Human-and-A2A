"""Provider-independence proof against real models (brief §24, §25).

The end-to-end harness so far has only exercised the `mock` provider, which
proves the plumbing but proves nothing about the claim that the agent's
identity is independent of the model behind it. A mock cannot fail to answer,
cannot be slow, and cannot be swapped for a different vendor.

So this runs the *same* runtime, with the *same* Ed25519 key, against every
provider that has real credentials, and asserts that:

  * the agent id, key id and public key are byte-identical throughout
  * every reply is signed by that one key and verifies
  * the replies genuinely differ (i.e. a real model actually answered, rather
    than something quietly falling back to the mock)
  * a provider outage degrades the runtime without touching its identity

Credentials are read from AEra's .env for convenience of running this probe.
The runtime itself never does that -- see test_43.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "aera-agent-security-lab"))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(ROOT / ".env")

from agent.crypto import verify_signature  # noqa: E402
from agent_runtime.keystore import LocalKeyStore  # noqa: E402
from agent_runtime.lifecycle import RuntimeState  # noqa: E402
from agent_runtime.provider import (  # noqa: E402
    ProviderAdapter,
    ProviderFailure,
    build_adapter,
    resolve_provider_credentials,
)
from agent_runtime.server import RuntimeServer  # noqa: E402
from agent_runtime.internal_auth import build_envelope  # noqa: E402

PROMPT = "In exactly one short sentence: what is the capital of Portugal?"
SECRET = "b" * 64

passed = failed = 0


def check(label: str, condition: bool, detail: str = "") -> None:
    global passed, failed
    if condition:
        passed += 1
        print(f"  PASS  {label}" + (f" [{detail}]" if detail else ""))
    else:
        failed += 1
        print(f"  FAIL  {label}" + (f" [{detail}]" if detail else ""))


class StubIdentity:
    def __init__(self, keystore):
        self.keystore = keystore
        self.agent_id = "did:aera:agent:provider-swap-probe"
        self.key_id = "key-probe-1"


def ask(server, text):
    envelope = build_envelope(agent_id=server.identity.agent_id,
                              request_id=f"r{time.time_ns()}",
                              body={"op": "message", "text": text}, secret=SECRET)
    return server.handle_payload(json.dumps(envelope).encode())


def main() -> int:
    os.environ["AERA_RUNTIME_INTERNAL_SECRET"] = SECRET

    resolved = resolve_provider_credentials()
    print(f"credential variables resolved: {resolved or '(none)'}")

    from src.config.settings import get_settings
    from src.providers.registry import available_providers

    available = available_providers(get_settings())
    real = [name for name, ok in available.items() if ok and name != "mock"]
    print(f"providers with real credentials: {real or '(none)'}\n")

    if len(real) < 2:
        print("NOTE: fewer than two real providers configured; the swap claim "
              "cannot be fully demonstrated.")

    key_path = Path("/tmp/aera-provider-swap-probe.json")
    key_path.unlink(missing_ok=True)
    keystore = LocalKeyStore(key_path)
    public_key = keystore.create()
    identity = StubIdentity(keystore)

    print(f"one identity for the whole run: {identity.agent_id}")
    print(f"public key: {public_key[:28]}…\n")

    fingerprint = (identity.agent_id, identity.key_id, public_key)
    answers: dict[str, str] = {}
    models: dict[str, str] = {}

    for name in real:
        print(f"--- provider: {name}")
        try:
            adapter = build_adapter(name)
        except ProviderFailure as exc:
            check(f"{name}: adapter builds", False, exc.kind)
            continue

        server = RuntimeServer(identity=identity, provider=adapter)
        server.status.set(RuntimeState.RUNNING)

        started = time.perf_counter()
        response = ask(server, PROMPT)
        elapsed = (time.perf_counter() - started) * 1000

        result = response.get("result", {})
        if not result.get("ok"):
            check(f"{name}: real model answered", False,
                  str(result.get("error", {}).get("code")))
            continue

        data = result["data"]
        text = data["text"]
        answers[name] = text
        models[name] = str(data.get("model"))
        check(f"{name}: real model answered", bool(text.strip()),
              f"{elapsed:.0f} ms, model={data.get('model')}")
        check(f"{name}: answer is on topic",
              "lisbon" in text.lower() or "lissabon" in text.lower(),
              text.strip()[:60].replace("\n", " "))
        check(f"{name}: not silently the mock",
              not text.startswith("MOCK:") and data["provider"] == name,
              f"provider={data['provider']}")

        canonical = json.dumps(result, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=True).encode()
        check(f"{name}: reply signed by the one agent key",
              verify_signature(public_key, response["agent_signature"], canonical))
        check(f"{name}: identity unchanged after the call",
              (identity.agent_id, identity.key_id, keystore.public_key) == fingerprint)

        blob = json.dumps(response)
        leaked = [m for m in ("sk-", "xai-", "api_key", "Bearer ") if m in blob]
        check(f"{name}: no provider credential in the reply", not leaked, str(leaked))
        print()

    # -- the actual swap claim ----------------------------------------------
    print("--- provider independence")
    check("identity survived every provider",
          (identity.agent_id, identity.key_id, keystore.public_key) == fingerprint)
    if len(answers) >= 2:
        # Note: the *text* of two answers is not a useful discriminator. Asked
        # a factual question, two good models legitimately produce the same
        # sentence. What must differ is the attribution: which vendor and
        # which model actually served the request.
        names = list(answers)
        check("two distinct vendors and models served the requests",
              len(set(names)) > 1 and len(set(models.values())) > 1,
              " vs ".join(f"{n}/{models[n]}" for n in names))
    else:
        check("two real providers were exercised", False,
              f"only {list(answers) or 'none'}")

    # -- outage isolation ----------------------------------------------------
    # A real outage, not a simulated one: a genuine HTTP call to the real
    # endpoint with a credential the vendor will reject.
    print("\n--- outage isolation")
    if real:
        from src.config.settings import get_settings as _settings
        from src.providers.registry import build_provider as _build

        vendor = real[0]
        settings = _settings()
        for attribute in ("deepseek_api_key", "xai_api_key", "anthropic_api_key"):
            if hasattr(settings, attribute):
                object.__setattr__(settings, attribute, "sk-deliberately-invalid")
        broken = ProviderAdapter(vendor, _build(vendor, settings))

        server = RuntimeServer(identity=identity, provider=broken)
        server.status.set(RuntimeState.RUNNING)
        response = ask(server, PROMPT)
        error = response["result"].get("error", {})
        check("a failing provider is refused cleanly",
              not response["result"]["ok"], str(error.get("code")))
        check("the runtime is DEGRADED, not REVOKED",
              server.status.get() is RuntimeState.DEGRADED
              and not server.status.is_revoked,
              server.status.get().value)
        check("identity still intact after the outage",
              (identity.agent_id, identity.key_id, keystore.public_key) == fingerprint)
        check("the failure text carries no credential",
              "sk-deliberately-invalid" not in json.dumps(response))

    key_path.unlink(missing_ok=True)
    print(f"\n{passed} passed / {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
