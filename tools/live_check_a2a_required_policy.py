#!/usr/bin/env python3
"""Live verification of AERA_A2A_AUTH_POLICY=required (Part H, final gap).

Run against an ISOLATED instance only. The shared/public service deliberately
stays on `optional`, because flipping it there would reject every existing
anonymous peer. This script therefore refuses to run unless the service it is
pointed at genuinely reports `required` on its agent card -- otherwise a green
run would prove nothing about the mode it claims to verify.

    ./venv/bin/python tools/live_check_a2a_required_policy.py \
        --base http://127.0.0.1:8899 --db ./test_aera_reqpolicy.db

Everything it creates is thrown away again in `cleanup()`, including on failure.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import sqlite3
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PASS, FAIL = [], []
DB = "./test_aera_reqpolicy.db"


def check(name: str, ok: bool, detail: str = "") -> None:
    (PASS if ok else FAIL).append(name)
    print(f"[{'ok  ' if ok else 'FAIL'}] {name}"
          + (f"  -- {detail}" if detail and not ok else ""))


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #
def http(method: str, url: str, *, body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        raw = exc.read() or b"{}"
        try:
            return exc.code, json.loads(raw)
        except ValueError:
            return exc.code, {"raw": raw.decode("utf-8", "replace")}


def rpc(target: str, *, skill: str = "agent.read.profile", message_id=None) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": "message/send",
        "params": {"message": {
            "role": "user",
            "messageId": message_id or str(uuid.uuid4()),
            "parts": [{"kind": "text", "text": "required-policy live check"}],
            "metadata": {"aera_target_agent": target, "skillId": skill},
        }},
    }


def a2a(base: str, payload: dict, headers=None, *, attempts: int = 8):
    """POST, yielding to the rate limiter rather than misreporting it.

    A 429 is not an answer to any question this script asks, so it waits and
    retries. It never retries any other status -- a 401 must stay a 401.
    """
    status, body = 0, {}
    for attempt in range(attempts):
        status, body = http("POST", f"{base}/api/a2a", body=payload, headers=headers)
        limited = status == 429 or (isinstance(body, dict)
                                    and (body.get("error") or {}).get("code") == -32010)
        if not limited:
            return status, body
        time.sleep(1 + attempt * 0.5)
    return status, body


# --------------------------------------------------------------------------- #
# throwaway fixtures (written straight to the isolated database)
# --------------------------------------------------------------------------- #
def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def make_agent(owner: str, capabilities) -> str:
    agent_id = "did:aera:agent:" + secrets.token_hex(16)
    now = iso(datetime.now(timezone.utc))
    conn = connect()
    try:
        conn.execute(
            "INSERT INTO agents (agent_id, owner_wallet, status, capabilities, "
            "label, created_at, updated_at) VALUES (?,?,?,?,?,?,?)",
            (agent_id, owner, "active", json.dumps(list(capabilities)),
             "parth-required-throwaway", now, now))
        conn.execute(
            "INSERT INTO agent_keys (key_id, agent_id, algorithm, public_key, "
            "status, created_at, activated_at) VALUES (?,?,?,?,?,?,?)",
            (secrets.token_hex(8), agent_id, "Ed25519", secrets.token_hex(32),
             "active", now, now))
        conn.commit()
    finally:
        conn.close()
    return agent_id


def dashboard_jwt(address: str) -> str:
    import jwt as pyjwt
    from server import TOKEN_SECRET
    now = datetime.now(timezone.utc)
    return pyjwt.encode({
        "iss": "aeralogin.com", "sub": address.lower(), "address": address.lower(),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=1)).timestamp()),
        "jti": secrets.token_hex(16), "has_nft": False, "type": "dashboard",
    }, TOKEN_SECRET, algorithm="HS256")


def plant_expired_credential(owner: str, agent_id: str) -> str:
    """Insert an already-expired credential directly.

    There is deliberately no API that issues one, so this is the only way to
    obtain the artefact. The secret is generated here and only its SHA-256 is
    written, exactly as the issuance path does.
    """
    cred_id = secrets.token_hex(16)
    secret = secrets.token_hex(32)
    past = datetime.now(timezone.utc) - timedelta(days=2)
    conn = connect()
    try:
        conn.execute(
            "INSERT INTO a2a_peer_credentials (cred_id, peer_id, peer_label, "
            "secret_hash, status, issued_at, expires_at, scoped_agents, "
            "scoped_skills, audience, issuer, owner_address) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (cred_id, "peer_" + secrets.token_hex(12), "expired-throwaway",
             hashlib.sha256(secret.encode()).hexdigest(), "active",
             iso(past - timedelta(days=90)), iso(past),
             json.dumps([agent_id]), json.dumps([]),
             "aera-a2a-gateway", "aeralogin.com", owner.lower()))
        conn.commit()
    finally:
        conn.close()
    return f"aera_a2a_{cred_id}_{secret}"


def cleanup(owners, agent_ids) -> tuple[int, int]:
    conn = connect()
    try:
        for address in owners:
            conn.execute("DELETE FROM a2a_peer_credentials WHERE owner_address = ?",
                         (address.lower(),))
        for agent_id in agent_ids:
            conn.execute("DELETE FROM agent_keys WHERE agent_id = ?", (agent_id,))
            conn.execute("DELETE FROM agents WHERE agent_id = ?", (agent_id,))
        conn.commit()
        creds = conn.execute(
            "SELECT COUNT(*) FROM a2a_peer_credentials").fetchone()[0]
        agents = conn.execute(
            "SELECT COUNT(*) FROM agents WHERE label = 'parth-required-throwaway'"
        ).fetchone()[0]
        return creds, agents
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
def main() -> int:
    global DB
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="http://127.0.0.1:8899")
    parser.add_argument("--db", default="./test_aera_reqpolicy.db")
    parser.add_argument("--log", default="/tmp/iso_required.log")
    args = parser.parse_args()
    base, DB = args.base.rstrip("/"), args.db

    owner = "0x" + secrets.token_hex(20)
    other_owner = "0x" + secrets.token_hex(20)
    owners, agents = [owner, other_owner], []

    # --- guard: refuse to "verify" the wrong mode -------------------------- #
    status, card = http("GET", f"{base}/.well-known/agent-card.json")
    if status != 200:
        print(f"isolated instance not reachable at {base} ({status})")
        return 2
    if not (card or {}).get("security"):
        print("ABORT: this instance is NOT running AERA_A2A_AUTH_POLICY=required.")
        print("       Refusing to report a green run for a mode that is not active.")
        return 2

    try:
        check("1  card advertises bearer authentication as REQUIRED",
              card["security"] == [{"aeraPeerCredential": []}]
              and "aeraPeerCredential" in (card.get("securitySchemes") or {}),
              json.dumps(card.get("security")))

        agent_id = make_agent(owner, ["agent.read.profile", "agent.communicate"])
        agents.append(agent_id)
        foreign_agent = make_agent(other_owner, ["agent.read.profile"])
        agents.append(foreign_agent)
        session = {"Authorization": f"Bearer {dashboard_jwt(owner)}"}

        # --- 2/3 anonymous is refused under `required` --------------------- #
        status, body = a2a(base, rpc(agent_id))
        check("2  anonymous POST /api/a2a is rejected", status == 401, str(status))
        check("3  missing Authorization header is rejected",
              status == 401 and "error" in (body or {}), json.dumps(body)[:160])

        # --- issue a real credential --------------------------------------- #
        status, issued = http("POST", f"{base}/api/dashboard/a2a-credentials",
                              body={"peer_label": "required-live",
                                    "scoped_agents": [agent_id],
                                    "scoped_skills": ["agent.read.profile"]},
                              headers=session)
        credential = (issued or {}).get("credential") or ""
        cred_id = (issued or {}).get("cred_id") or ""
        auth = {"Authorization": f"Bearer {credential}"}
        if not credential:
            check("4  valid bearer credential succeeds", False,
                  f"issuance failed: {status}")
            raise SystemExit(1)

        status, body = a2a(base, rpc(agent_id), auth)
        check("4  valid bearer credential succeeds",
              status == 200 and "result" in (body or {}), json.dumps(body)[:200])

        # --- 5/6/7 the three ways a credential stops working --------------- #
        status, _ = a2a(base, rpc(agent_id),
                        {"Authorization": f"Bearer {credential[:-4]}dead"})
        check("5  invalid bearer credential is rejected", status == 401, str(status))

        expired = plant_expired_credential(owner, agent_id)
        status, expired_body = a2a(base, rpc(agent_id),
                                   {"Authorization": f"Bearer {expired}"})
        check("6  expired credential is rejected", status == 401, str(status))

        status, throwaway = http("POST", f"{base}/api/dashboard/a2a-credentials",
                                 body={"scoped_agents": [agent_id]},
                                 headers=session)
        doomed = (throwaway or {}).get("credential") or ""
        doomed_id = (throwaway or {}).get("cred_id") or ""
        http("POST", f"{base}/api/dashboard/a2a-credentials/{doomed_id}/revoke",
             body={"reason": "required-policy live check"}, headers=session)
        status, _ = a2a(base, rpc(agent_id), {"Authorization": f"Bearer {doomed}"})
        check("7  revoked credential is rejected", status == 401, str(status))

        # --- 8/9/10 nothing else is a Level-3 credential -------------------- #
        agent_jwt = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                     "eyJzdWIiOiJkaWQ6YWVyYTphZ2VudDphYmMiLCJhdWQiOiJhZXJhLWFnZW50"
                     "LWFwaSJ9.bm90LWEtcmVhbC1zaWduYXR1cmU")
        status, _ = a2a(base, rpc(agent_id), {"Authorization": f"Bearer {agent_jwt}"})
        check("8  Agent JWT is still rejected as a Level-3 credential",
              status == 401, str(status))

        status, _ = a2a(base, rpc(agent_id),
                        {"Authorization": f"Bearer {dashboard_jwt(owner)}"})
        check("9  dashboard JWT is still rejected", status == 401, str(status))

        malformed = 0
        for value in ("Bearer", "Bearer   ", "Bearer not-a-credential",
                      "Basic aera_a2a_x", f"Bearer aera_a2a_{'z' * 10}"):
            status, _ = a2a(base, rpc(agent_id), {"Authorization": value})
            malformed += 1 if status == 401 else 0
        check("10 malformed bearer is rejected", malformed == 5,
              f"{malformed}/5 rejected")

        # --- 11/12/13 authorisation is still a separate question ----------- #
        status, body = a2a(base, rpc(agent_id, skill="agent.read.profile"), auth)
        check("11 correct peer/agent/skill scope succeeds",
              status == 200 and "result" in (body or {}), json.dumps(body)[:160])

        status, body = a2a(base, rpc(foreign_agent), auth)
        check("12 out-of-scope agent fails", "error" in (body or {}),
              json.dumps(body)[:160])

        status, body = a2a(base, rpc(agent_id, skill="agent.communicate"), auth)
        check("13 out-of-scope skill fails", "error" in (body or {}),
              json.dumps(body)[:160])

        # --- 14 replay semantics unchanged under `required` ---------------- #
        replayed = str(uuid.uuid4())
        first_status, _ = a2a(base, rpc(agent_id, message_id=replayed), auth)
        second_status, second = a2a(base, rpc(agent_id, message_id=replayed), auth)
        fresh_status, _ = a2a(base, rpc(agent_id), auth)
        check("14 replay protection remains unchanged",
              first_status == 200 and "error" in (second or {})
              and fresh_status == 200,
              f"first={first_status} dup={json.dumps(second)[:80]} new={fresh_status}")

        # --- 15 rate limiting still fires ---------------------------------- #
        limited = False
        for _ in range(40):
            status, body = http("POST", f"{base}/api/a2a", body=rpc(agent_id),
                                headers=auth)
            if status == 429 or (body.get("error") or {}).get("code") == -32010:
                limited = True
                break
        check("15 rate limiting remains active", limited,
              "no 429 within 40 authenticated requests")
        time.sleep(3)

        # --- 16 nothing leaked --------------------------------------------- #
        secret = credential.rsplit("_", 1)[-1]
        expired_secret = expired.rsplit("_", 1)[-1]
        blob = json.dumps([expired_body, second, card])
        leaked_response = any(s in blob for s in (secret, expired_secret, credential))

        log_leak = False
        if os.path.exists(args.log):
            with open(args.log, "r", errors="replace") as handle:
                log = handle.read()
            log_leak = any(s in log for s in (secret, expired_secret, credential))

        conn = connect()
        try:
            stored = json.dumps([dict(r) for r in conn.execute(
                "SELECT * FROM a2a_peer_credentials").fetchall()])
        finally:
            conn.close()
        db_leak = secret in stored or credential in stored

        check("16 no credential or secret leaked in responses, logs or store",
              not leaked_response and not log_leak and not db_leak,
              f"response={leaked_response} log={log_leak} db={db_leak}")

        # --- bonus: cred_id is safe metadata and IS present ---------------- #
        check("17 cred_id remains usable as safe audit metadata",
              bool(cred_id) and bool(doomed_id))

    finally:
        creds_left, agents_left = cleanup(owners, agents)
        print(f"\ncleanup: {creds_left} credentials, {agents_left} throwaway agents "
              f"remaining in the isolated database")

    print(f"\nRESULT: {len(PASS)} passed, {len(FAIL)} failed")
    for name in FAIL:
        print(f"  failed: {name}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
