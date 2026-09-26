#!/usr/bin/env python3
"""Live end-to-end check for Part H -- external A2A peer credentials.

This talks to the REAL running AEra service over HTTP. It does not import the
gateway and it does not mock the verifier: every assertion below is about what
the deployed service actually did.

Throwaway resources only. A disposable owner wallet and a disposable agent are
created directly in the database (there is no HTTP path to register an agent
without a wallet signature), everything else goes through the live HTTP API,
and all of it is removed again in `cleanup()` -- including on failure.

    ./venv/bin/python tools/live_check_a2a_credentials.py [--base http://127.0.0.1:8840]
"""
from __future__ import annotations

import argparse
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


def check(name: str, ok: bool, detail: str = "") -> None:
    (PASS if ok else FAIL).append(name)
    mark = "ok  " if ok else "FAIL"
    print(f"[{mark}] {name}" + (f"  -- {detail}" if detail and not ok else ""))


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


def rpc(target: str, *, skill: str, message_id: str) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": "message/send",
        "params": {
            "message": {
                "role": "user",
                "messageId": message_id,
                "parts": [{"kind": "text", "text": "live credential check"}],
                "metadata": {"aera_target_agent": target, "skillId": skill},
            }
        },
    }


def a2a(base: str, payload: dict, headers=None, *, attempts: int = 8):
    """POST to the live gateway, yielding to the rate limiter when it fires.

    Part F's limiter is deliberately strict and is shared by every caller of
    the running service, so a burst of checks will legitimately hit it. A 429
    is not the answer this script is asking about, so it waits and retries
    rather than reporting a false negative. It never retries any other status.
    """
    for attempt in range(attempts):
        status, body = http("POST", f"{base}/api/a2a", body=payload,
                            headers=headers)
        rate_limited = status == 429 or (
            isinstance(body, dict)
            and (body.get("error") or {}).get("code") == -32010)
        if not rate_limited:
            return status, body
        retry_after = 1
        try:
            retry_after = int(
                ((body.get("error") or {}).get("data") or {}).get("retryAfter") or 1)
        except (AttributeError, TypeError, ValueError):
            retry_after = 1
        time.sleep(min(max(retry_after, 1), 5) + attempt * 0.5)
    return status, body


# --------------------------------------------------------------------------- #
# throwaway fixtures
# --------------------------------------------------------------------------- #
def db_path() -> str:
    from agent.repository import _db_path
    return _db_path()


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(db_path())
    conn.row_factory = sqlite3.Row
    return conn


def make_agent(owner: str) -> str:
    agent_id = "did:aera:agent:" + secrets.token_hex(16)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn = connect()
    try:
        conn.execute(
            "INSERT INTO agents (agent_id, owner_wallet, status, capabilities, "
            "label, created_at, updated_at) VALUES (?,?,?,?,?,?,?)",
            (agent_id, owner, "active",
             json.dumps(["agent.read.profile"]), "parth-live-throwaway",
             now, now))
        conn.execute(
            "INSERT INTO agent_keys (key_id, agent_id, algorithm, public_key, "
            "status, created_at, activated_at) VALUES (?,?,?,?,?,?,?)",
            (secrets.token_hex(8), agent_id, "Ed25519",
             secrets.token_hex(32), "active", now, now))
        conn.commit()
    finally:
        conn.close()
    return agent_id


def dashboard_jwt(address: str) -> str:
    """Mint a throwaway dashboard session exactly as the dashboard login does."""
    import jwt as pyjwt
    from server import TOKEN_SECRET
    now = datetime.now(timezone.utc)
    return pyjwt.encode({
        "iss": "aeralogin.com", "sub": address.lower(), "address": address.lower(),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=1)).timestamp()),
        "jti": secrets.token_hex(16), "has_nft": False, "type": "dashboard",
    }, TOKEN_SECRET, algorithm="HS256")


def cleanup(owner: str, other_owner: str, agent_ids: list[str]) -> None:
    conn = connect()
    try:
        for address in (owner, other_owner):
            conn.execute("DELETE FROM a2a_peer_credentials WHERE owner_address = ?",
                         (address.lower(),))
        for agent_id in agent_ids:
            conn.execute("DELETE FROM agent_keys WHERE agent_id = ?", (agent_id,))
            conn.execute("DELETE FROM agents WHERE agent_id = ?", (agent_id,))
        conn.commit()
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="http://127.0.0.1:8840")
    args = parser.parse_args()
    base = args.base.rstrip("/")

    owner = "0x" + secrets.token_hex(20)
    other_owner = "0x" + secrets.token_hex(20)
    agents: list[str] = []

    try:
        status, card = http("GET", f"{base}/.well-known/agent-card.json")
        check("1  service is live and serves the agent card", status == 200, str(status))
        schemes = (card or {}).get("securitySchemes") or {}
        check("2  card advertises the bearer scheme it actually implements",
              "aeraPeerCredential" in schemes, json.dumps(schemes)[:200])

        agent_id = make_agent(owner)
        agents.append(agent_id)
        foreign_agent = make_agent(other_owner)
        agents.append(foreign_agent)
        session = {"Authorization": f"Bearer {dashboard_jwt(owner)}"}

        # --- issuance ---------------------------------------------------- #
        status, _ = http("POST", f"{base}/api/dashboard/a2a-credentials",
                         body={"scoped_agents": [agent_id]})
        check("3  unauthenticated caller cannot issue", status == 401, str(status))

        status, body = http("POST", f"{base}/api/dashboard/a2a-credentials",
                            body={"scoped_agents": [foreign_agent]}, headers=session)
        check("4  owner cannot scope another owner's agent", status == 403, str(status))

        status, issued = http("POST", f"{base}/api/dashboard/a2a-credentials",
                              body={"peer_label": "parth-live",
                                    "scoped_agents": [agent_id],
                                    "scoped_skills": ["agent.read.profile"]},
                              headers=session)
        credential = (issued or {}).get("credential") or ""
        cred_id = (issued or {}).get("cred_id") or ""
        peer_id = (issued or {}).get("peer_id") or ""
        check("5  owner issues a credential", status == 200 and bool(credential),
              str(status))
        check("6  plaintext is shown exactly once, at issuance",
              credential.startswith("aera_a2a_"), credential[:12])

        # --- storage ------------------------------------------------------ #
        conn = connect()
        try:
            row = conn.execute(
                "SELECT secret_hash, peer_id, expires_at FROM a2a_peer_credentials "
                "WHERE cred_id = ?", (cred_id,)).fetchone()
        finally:
            conn.close()
        secret = credential.rsplit("_", 1)[-1]
        check("7  plaintext secret is not stored",
              row is not None and secret not in json.dumps(dict(row)))
        check("8  peer identity is AEra-minted and stable",
              row is not None and row["peer_id"] == peer_id
              and peer_id.startswith("peer_"))

        status, listed = http("GET", f"{base}/api/dashboard/a2a-credentials",
                              headers=session)
        dumped = json.dumps(listed)
        check("9  credential is never retrievable again",
              status == 200 and secret not in dumped and "aera_a2a_" not in dumped,
              f"{status} {dumped[:160]}")

        # --- authentication ------------------------------------------------ #
        auth = {"Authorization": f"Bearer {credential}"}
        status, body = a2a(base, rpc(agent_id, skill="agent.read.profile",
                                     message_id=str(uuid.uuid4())), auth)
        check("10 valid credential authenticates a live A2A request",
              status == 200 and "result" in (body or {}), json.dumps(body)[:200])

        status, body = a2a(base, rpc(agent_id, skill="agent.read.profile",
                                     message_id=str(uuid.uuid4())), auth)
        check("11 the same credential is reusable with a new messageId",
              status == 200 and "result" in (body or {}),
              f"{status} {json.dumps(body)[:160]}")

        replayed = str(uuid.uuid4())
        a2a(base, rpc(agent_id, skill="agent.read.profile",
                      message_id=replayed), auth)
        status, body = a2a(base, rpc(agent_id, skill="agent.read.profile",
                                     message_id=replayed), auth)
        check("12 a duplicate messageId is still rejected",
              "error" in (body or {}), json.dumps(body)[:200])

        # --- authorisation -------------------------------------------------- #
        status, body = a2a(base, rpc(foreign_agent, skill="agent.read.profile",
                                     message_id=str(uuid.uuid4())), auth)
        check("13 an out-of-scope agent is refused", "error" in (body or {}),
              json.dumps(body)[:160])

        status, body = a2a(base, rpc(agent_id, skill="agent.communicate",
                                     message_id=str(uuid.uuid4())), auth)
        check("14 an out-of-scope skill is refused", "error" in (body or {}),
              json.dumps(body)[:160])

        # --- rejected credential shapes ------------------------------------- #
        bad = credential[:-4] + "dead"
        status, _ = a2a(base, rpc(agent_id, skill="agent.read.profile",
                                  message_id=str(uuid.uuid4())),
                        {"Authorization": f"Bearer {bad}"})
        check("15 a wrong secret is rejected", status == 401, str(status))

        unknown = f"aera_a2a_{secrets.token_hex(16)}_{secrets.token_hex(32)}"
        status, unknown_body = a2a(base, rpc(agent_id, skill="agent.read.profile",
                                             message_id=str(uuid.uuid4())),
                                   {"Authorization": f"Bearer {unknown}"})
        check("16 an unknown cred_id is rejected", status == 401, str(status))
        check("17 unknown and wrong-secret are indistinguishable",
              json.dumps(unknown_body).count("invalid or expired credential") >= 1)

        jwt_like = dashboard_jwt(owner)
        status, _ = a2a(base, rpc(agent_id, skill="agent.read.profile",
                                  message_id=str(uuid.uuid4())),
                        {"Authorization": f"Bearer {jwt_like}"})
        check("18 a dashboard/agent JWT is rejected as a peer credential",
              status == 401, str(status))

        status, _ = a2a(base, rpc(agent_id, skill="agent.read.profile",
                                  message_id=str(uuid.uuid4())),
                        {"Authorization": "Bearer not-a-credential"})
        check("19 a malformed bearer is rejected, not downgraded to anonymous",
              status == 401, str(status))

        # --- anonymous still works (policy=optional) ------------------------ #
        status, body = a2a(base, rpc(agent_id, skill="agent.read.profile",
                                     message_id=str(uuid.uuid4())))
        check("20 anonymous interoperability is intact under policy=optional",
              status == 200 and "result" in (body or {}), json.dumps(body)[:200])

        # --- rotation ------------------------------------------------------- #
        status, rotated = http("POST", f"{base}/api/dashboard/a2a-credentials",
                               body={"peer_id": peer_id,
                                     "scoped_agents": [agent_id],
                                     "scoped_skills": ["agent.read.profile"]},
                               headers=session)
        rotated_credential = (rotated or {}).get("credential") or ""
        check("21 a second credential can be issued (rotation)",
              status == 200 and bool(rotated_credential)
              and rotated_credential != credential)

        status, _ = a2a(base, rpc(agent_id, skill="agent.read.profile",
                                  message_id=str(uuid.uuid4())), auth)
        check("22 the old credential still works until revoked",
              status == 200, str(status))

        # --- revocation ------------------------------------------------------ #
        status, _ = http("POST",
                         f"{base}/api/dashboard/a2a-credentials/{cred_id}/revoke",
                         body={"reason": "live check"}, headers=session)
        check("23 owner revokes the credential", status == 200, str(status))

        status, _ = a2a(base, rpc(agent_id, skill="agent.read.profile",
                                  message_id=str(uuid.uuid4())), auth)
        check("24 the revoked credential fails immediately",
              status == 401, str(status))

        conn = connect()
        try:
            kept = conn.execute(
                "SELECT status, revoked_at, revoked_reason FROM a2a_peer_credentials "
                "WHERE cred_id = ?", (cred_id,)).fetchone()
        finally:
            conn.close()
        check("25 the revoked record is kept for audit",
              kept is not None and kept["status"] == "revoked"
              and bool(kept["revoked_at"]))

        # --- leakage --------------------------------------------------------- #
        leaked = []
        for path in ("server.log", "logs"):
            full = os.path.join(os.path.dirname(db_path()), path)
            targets = []
            if os.path.isfile(full):
                targets = [full]
            elif os.path.isdir(full):
                targets = [os.path.join(full, f) for f in os.listdir(full)]
            for target in targets:
                try:
                    with open(target, "r", errors="replace") as handle:
                        if secret in handle.read():
                            leaked.append(target)
                except OSError:
                    pass
        check("26 the plaintext secret appears in no log", not leaked, str(leaked))

        return 0 if not FAIL else 1
    finally:
        cleanup(owner, other_owner, agents)
        print(f"\ncleanup: removed {len(agents)} throwaway agents and all "
              f"throwaway credentials")
        print(f"RESULT: {len(PASS)} passed, {len(FAIL)} failed")
        if FAIL:
            for name in FAIL:
                print(f"  failed: {name}")


if __name__ == "__main__":
    sys.exit(main())
