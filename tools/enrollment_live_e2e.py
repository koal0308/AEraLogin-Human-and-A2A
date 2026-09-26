"""Live E2E for agent enrollment against an ISOLATED instance.

    AERA_E2E_URL=http://127.0.0.1:8891 ./venv/bin/python tools/enrollment_live_e2e.py

Uses a disposable owner wallet (fresh random key), the real
`python -m agent_runtime enroll` CLI as a subprocess, and then
`python -m agent_runtime run` to prove the enrolled identity authenticates.
Never point this at production data.
"""
from __future__ import annotations

import os
import pathlib
import re
import secrets
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone

import httpx
import jwt
from dotenv import dotenv_values
from eth_account import Account
from eth_account.messages import encode_defunct

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from agent.constants import OWNER_CHALLENGE_KEYS  # noqa: E402
from agent.crypto import canonical_json  # noqa: E402

URL = os.getenv("AERA_E2E_URL", "http://127.0.0.1:8891")
assert ":8840" not in URL, "refusing to run against the production port"

results: list[tuple[str, bool]] = []


def check(name, ok):
    results.append((name, bool(ok)))
    print(f"{'PASS' if ok else 'FAIL'}  {name}")


def owner_sign(acct, rec):
    canon = canonical_json({k: rec[k] if k != "agent_id" else (rec.get("agent_id") or "")
                            for k in OWNER_CHALLENGE_KEYS}, OWNER_CHALLENGE_KEYS)
    sig = acct.sign_message(encode_defunct(primitive=canon)).signature
    return sig.hex() if isinstance(sig, (bytes, bytearray)) else sig


def main() -> int:
    secret = dotenv_values(REPO / ".env").get("TOKEN_SECRET") or os.environ["TOKEN_SECRET"]
    acct = Account.create()
    owner = acct.address.lower()
    now = datetime.now(timezone.utc)
    session = jwt.encode({"iss": "aeralogin.com", "sub": owner, "address": owner,
                          "iat": int(now.timestamp()),
                          "exp": int((now + timedelta(hours=1)).timestamp()),
                          "jti": secrets.token_hex(16), "type": "dashboard"},
                         secret, algorithm="HS256")
    H = {"Authorization": f"Bearer {session}"}
    http = httpx.Client(base_url=URL, timeout=30)

    # 1. dashboard creates enrollment
    r = http.post("/api/dashboard/agents/enrollments", headers=H,
                  json={"label": "Live E2E Agent", "capabilities": None})
    check("create enrollment (session)", r.status_code == 200)
    e = r.json()["enrollment"]
    code, eid = e["enrollment_code"], e["enrollment_id"]
    check("unauthenticated create rejected",
          http.post("/api/dashboard/agents/enrollments", json={"label": "abc"}).status_code == 401)

    work = pathlib.Path(tempfile.mkdtemp(prefix="aera-enroll-"))
    key_path = work / "agent_key.json"
    env = dict(os.environ, AERA_BASE_URL=URL, AERA_RUNTIME_KEY_PATH=str(key_path),
               AERA_RUNTIME_KEY_PASSPHRASE="e2e-" + secrets.token_hex(8),
               AERA_RUNTIME_DIR=str(work / "run"),
               AERA_RUNTIME_INTERNAL_SECRET=secrets.token_hex(32),
               PYTHONUNBUFFERED="1")
    env.pop("AERA_RUNTIME_AGENT_ID", None)
    env.pop("AERA_RUNTIME_KEY_ID", None)

    # 2. real runtime CLI, in the background
    proc = subprocess.Popen([sys.executable, "-m", "agent_runtime", "enroll", code,
                             "--timeout", "120"], cwd=REPO, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    view = None
    for _ in range(60):
        view = http.get(f"/api/dashboard/agents/enrollments/{eid}", headers=H).json()["enrollment"]
        if view["status"] == "key_submitted":
            break
        time.sleep(0.5)
    check("runtime claimed with PoP", view and view["status"] == "key_submitted")

    # 3. a second claim (attacker with the code) is refused
    from agent.crypto import Ed25519Signer, b64u_encode
    from agent.enrollment import build_pop_payload
    atk = Ed25519Signer.generate()
    r = http.post("/api/agents/enrollments/claim", json={
        "enrollment_code": code, "public_key": atk.public_key_encoded(),
        "signature": b64u_encode(atk.sign(build_pop_payload(eid, atk.public_key_encoded())))})
    check("second claim refused (409)", r.status_code == 409)

    # 4. owner approves with wallet signature
    ch = http.post("/api/agents/owner-challenge", json={
        "owner_wallet": owner, "operation": "register", "agent_id": f"enrollment:{eid}"}).json()
    r = http.post(f"/api/agents/enrollments/{eid}/complete", json={
        "owner_wallet": owner, "owner_challenge_id": ch["challenge_id"],
        "owner_signature": owner_sign(acct, ch)})
    check("owner approval creates agent", r.status_code == 200)
    agent_id = r.json().get("agent_id")

    out, _ = proc.communicate(timeout=60)
    check("runtime enroll exited 0", proc.returncode == 0)
    check("runtime printed matching fingerprint", view["key_fingerprint"] in out)
    check("runtime printed agent_id", agent_id in out)
    import json as _json
    blob = _json.loads(key_path.read_text())
    check("key sealed at rest (scrypt-aesgcm)", blob.get("format") == "scrypt-aesgcm-v1")
    check("no key material in CLI output", blob["ciphertext"] not in out
          and not re.search(r"[0-9a-f]{64}", out))
    check("identity file written 0600",
          oct((work / "agent_key.identity.json").stat().st_mode)[-3:] == "600")

    # 5. dashboard list shows the agent
    agents = http.get("/api/dashboard/agents", headers=H).json()["agents"]
    check("agent visible in dashboard", [a["agent_id"] for a in agents] == [agent_id])

    # 6. runtime `run` authenticates with the enrolled identity, no manual config
    run = subprocess.Popen([sys.executable, "-m", "agent_runtime", "run"], cwd=REPO, env=env,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    started = False
    deadline = time.time() + 30
    while time.time() < deadline:
        line = run.stdout.readline()
        if "runtime RUNNING" in line:
            started = agent_id in line
            break
        if not line and run.poll() is not None:
            break
    run.terminate()
    try:
        run.wait(timeout=10)
    except subprocess.TimeoutExpired:
        run.kill()
    check("runtime run authenticates with enrolled identity", started)

    ok = all(v for _, v in results)
    print(f"\n{sum(v for _, v in results)}/{len(results)} checks passed")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
