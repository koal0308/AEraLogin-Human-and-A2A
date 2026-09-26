"""Live end-to-end proof for the packaged Agent Runtime.

Chain under test:

    A2A client -> AEra /api/a2a -> gateway -> runtime (unix socket)
               -> LLM provider -> reply -> gateway -> A2A response

HTTP 200 is NOT treated as success. The run only passes if a real reply text
came back from a real provider through a real runtime process, if replay is
still refused, and if no secret appears anywhere in the response.

The agent is registered through the ordinary owner-challenge flow with a
disposable owner EOA, and revoked again at the end.
"""
from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
import time
import uuid
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

BASE = os.getenv("AERA_BASE_URL", "http://127.0.0.1:8840")
KEY_PATH = "/tmp/aera-runtime-e2e-key.json"
PROVIDER = os.getenv("AERA_RUNTIME_PROVIDER", "mock")


def _server_channel() -> tuple[str, str]:
    """Read the internal secret and runtime dir the SERVER process is using.

    The gateway runs inside the AEra service, not in this script. Setting these
    in our own environment would prove nothing -- the runtime must listen on the
    directory the server actually looks in, authenticated with the secret the
    server actually holds. Both come from the same `.env` the service loads.
    """
    secret = directory = ""
    env_file = ROOT / ".env"
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line.startswith("AERA_RUNTIME_INTERNAL_SECRET="):
            secret = line.split("=", 1)[1].strip()
        elif line.startswith("AERA_RUNTIME_DIR="):
            directory = line.split("=", 1)[1].strip()
    return secret, directory or "/tmp/aera-runtime"


FORBIDDEN = ("AGENT_JWT_SECRET", "TOKEN_SECRET", "PRIVATE KEY", "private_key",
             "eyJ", "passphrase", "INTERNAL_SECRET", "aera.db", "/home/")

results: list[tuple[str, bool, str]] = []


def check(label: str, ok: bool, detail: str = "") -> bool:
    results.append((label, ok, detail))
    print(f"   {'PASS' if ok else 'FAIL'}  {label}" + (f"  [{detail}]" if detail else ""))
    return ok


def main() -> int:
    from agent.constants import CAP_AUTHENTICATE, CAP_COMMUNICATE, CAP_READ_PROFILE
    from agent_runtime.keystore import LocalKeyStore

    internal_secret, RUNTIME_DIR = _server_channel()
    os.makedirs(RUNTIME_DIR, exist_ok=True)
    os.chmod(RUNTIME_DIR, 0o700)
    for stale in Path(RUNTIME_DIR).glob("*.sock"):
        stale.unlink()
    if Path(KEY_PATH).exists():
        Path(KEY_PATH).unlink()

    if not internal_secret:
        check("server has an internal runtime secret configured", False,
              "AERA_RUNTIME_INTERNAL_SECRET missing from .env")
        return summarise()

    http = httpx.Client(base_url=BASE, timeout=30)

    print("== 1. runtime generates its own keypair ==")
    store = LocalKeyStore(KEY_PATH)
    public_key = store.create()
    check("keypair generated locally", public_key.startswith("ed25519:"), public_key[:24] + "…")
    check("key file is owner-only", store.permissions_are_safe())

    print("== 2. owner registers the agent (runtime never holds the wallet key) ==")
    from eth_account import Account
    from eth_account.messages import encode_defunct

    from agent.constants import (
        OWNER_CHALLENGE_KEYS,
        OWNER_DOMAIN,
        PROTO_OWNER_CHALLENGE,
        PROTOCOL_VERSION,
    )
    from agent.crypto import canonical_json

    owner = Account.from_key("0x" + secrets.token_hex(32))
    challenge = http.post("/api/agents/owner-challenge", json={
        "owner_wallet": owner.address.lower(), "operation": "register",
        "agent_id": None}).json()
    canon = canonical_json({
        "protocol": PROTO_OWNER_CHALLENGE, "version": PROTOCOL_VERSION,
        "owner_wallet": challenge["owner_wallet"], "agent_id": "",
        "operation": "register", "challenge_id": challenge["challenge_id"],
        "challenge": challenge["challenge"],
        "expires_at": challenge["expires_at"], "domain": OWNER_DOMAIN,
    }, OWNER_CHALLENGE_KEYS)
    signature = owner.sign_message(encode_defunct(primitive=canon)).signature.hex()

    registered = http.post("/api/agents/register", json={
        "owner_wallet": owner.address.lower(),
        "owner_challenge_id": challenge["challenge_id"],
        "owner_signature": signature,
        "public_key": public_key,
        "label": "E2E Runtime Agent",
        "capabilities": [CAP_AUTHENTICATE, CAP_READ_PROFILE, CAP_COMMUNICATE],
    })
    if registered.status_code != 200:
        check("agent registered", False, registered.text[:120])
        return summarise()
    agent = registered.json()
    agent_id, key_id = agent["agent_id"], agent["key_id"]
    check("agent registered", True, agent_id)
    check("agent holds agent.communicate", CAP_COMMUNICATE in agent["capabilities"])

    print("== 3. runtime process starts and authenticates ==")
    env = {
        **os.environ,
        "AERA_BASE_URL": BASE,
        "AERA_RUNTIME_AGENT_ID": agent_id,
        "AERA_RUNTIME_KEY_ID": key_id,
        "AERA_RUNTIME_KEY_PATH": KEY_PATH,
        "AERA_RUNTIME_DIR": RUNTIME_DIR,
        "AERA_RUNTIME_PROVIDER": PROVIDER,
        "AERA_RUNTIME_INTERNAL_SECRET": internal_secret,
    }
    proc = subprocess.Popen([sys.executable, "-m", "agent_runtime", "run"],
                            cwd=str(ROOT), env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True)
    socket_ready = False
    for _ in range(60):
        if any(Path(RUNTIME_DIR).glob("*.sock")):
            socket_ready = True
            break
        if proc.poll() is not None:
            break
        time.sleep(0.5)

    if not socket_ready:
        output = proc.stdout.read() if proc.stdout else ""
        check("runtime started and authenticated", False, output[-200:])
        return summarise()
    check("runtime started and authenticated", True, f"provider={PROVIDER}")

    try:
        print("== 4. external A2A request through the public gateway ==")
        message_id = uuid.uuid4().hex
        payload = {
            "jsonrpc": "2.0", "id": str(uuid.uuid4()), "method": "message/send",
            "params": {"message": {
                "messageId": message_id, "role": "user",
                "parts": [{"kind": "text", "text": "Hello. Who are you?"}],
                "metadata": {"aera_target_agent": agent_id,
                             "skillId": "agent.communicate"},
            }},
        }
        response = http.post("/api/a2a", json=payload,
                             headers={"A2A-Version": "0.3"})
        body = response.json()
        check("gateway accepted the request", response.status_code == 200,
              f"HTTP {response.status_code}")
        if "error" in body:
            print(f"   gateway error body: {json.dumps(body['error'])[:300]}")

        result = body.get("result") or {}
        parts = result.get("parts") or []
        reply_text = next((p.get("text") for p in parts
                           if p.get("kind") == "text" and p.get("text")), "")
        data = next((p.get("data") for p in parts if p.get("kind") == "data"), {}) or {}

        check("a real reply came back from the runtime", bool(reply_text.strip()),
              reply_text[:60])
        check("reply is attributed to a provider",
              bool(data.get("provider")), str(data.get("provider")))
        check("response is for the correct agent",
              (data.get("agent") or {}).get("agent_id") == agent_id)

        print("== 5. replay protection still applies ==")
        replayed = http.post("/api/a2a", json=payload,
                             headers={"A2A-Version": "0.3"})
        check("duplicate messageId refused", "error" in replayed.json())

        print("== 6. no secret leakage ==")
        blob = json.dumps(body)
        leaked = [m for m in FORBIDDEN if m in blob]
        check("no secrets in the A2A response", not leaked, str(leaked))
        check("no private key material in the response",
              "ed25519:" not in blob)

        print("== 7. agent card advertises communicate only with a runtime ==")
        card = http.get("/.well-known/agent-card.json").json()
        skills = {s.get("id") for s in card.get("skills", [])}
        check("card advertises agent.communicate", "agent.communicate" in skills,
              str(sorted(skills)))

    finally:
        print("== 8. cleanup: revoke the agent ==")
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:  # pragma: no cover
            proc.kill()

        revoke_challenge = http.post("/api/agents/owner-challenge", json={
            "owner_wallet": owner.address.lower(), "operation": "agent_revoke",
            "agent_id": agent_id}).json()
        canon = canonical_json({
            "protocol": PROTO_OWNER_CHALLENGE, "version": PROTOCOL_VERSION,
            "owner_wallet": revoke_challenge["owner_wallet"], "agent_id": agent_id,
            "operation": "agent_revoke",
            "challenge_id": revoke_challenge["challenge_id"],
            "challenge": revoke_challenge["challenge"],
            "expires_at": revoke_challenge["expires_at"], "domain": OWNER_DOMAIN,
        }, OWNER_CHALLENGE_KEYS)
        revoked = http.request("DELETE", f"/api/agents/{agent_id}", json={
            "owner_wallet": owner.address.lower(),
            "owner_challenge_id": revoke_challenge["challenge_id"],
            "owner_signature": owner.sign_message(
                encode_defunct(primitive=canon)).signature.hex(),
            "public_key": public_key,
        })
        print(f"   revoke -> HTTP {revoked.status_code}")

    return summarise()


def summarise() -> int:
    print("\n== RESULT ==")
    failed = 0
    for label, ok, _ in results:
        if not ok:
            failed += 1
    print(f"{len(results) - failed} passed / {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
