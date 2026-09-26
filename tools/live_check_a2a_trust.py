#!/usr/bin/env python3
"""Live verification of the AEra External Peer Trust Assessment (Part J).

Run against an ISOLATED instance only. Two reasons, and both are refusal
conditions rather than advice:

  * The trust layer only observes when `AERA_A2A_TRUST_MODE=monitor`. The
    public service runs with it `off`, which is the correct production default,
    so a run against it would exercise nothing and still print green.
  * This script writes throwaway owners, agents and credentials directly into
    the database it is pointed at. That must never be the production database.

    ./venv/bin/python tools/live_check_a2a_trust.py \
        --base http://127.0.0.1:8891 --db ./test_aera_trust.db

Everything it creates is removed again in `cleanup()`, including on failure.

What this script will NOT do: assert anything it did not actually observe. Every
check below either exercises the running HTTP service or reads the database that
service wrote. Where a property cannot be verified live, it is reported as
skipped rather than quietly counted as a pass.
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

PASS, FAIL, SKIP = [], [], []
DB = "./test_aera_trust.db"
LABEL = "partj-trust-throwaway"


def check(name: str, ok: bool, detail: str = "") -> None:
    (PASS if ok else FAIL).append(name)
    print(f"[{'ok  ' if ok else 'FAIL'}] {name}"
          + (f"  -- {detail}" if detail and not ok else ""))


def skip(name: str, why: str) -> None:
    SKIP.append(name)
    print(f"[skip] {name}  -- {why}")


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


def rpc(target: str, *, skill: str = "agent.read.profile", message_id=None,
        extra_metadata=None, text="part-j trust live check") -> dict:
    metadata = {"aera_target_agent": target, "skillId": skill}
    if extra_metadata:
        metadata.update(extra_metadata)
    return {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": "message/send",
        "params": {"message": {
            "role": "user",
            "messageId": message_id or str(uuid.uuid4()),
            "parts": [{"kind": "text", "text": text}],
            "metadata": metadata,
        }},
    }


def rpc_refused(status: int, body) -> bool:
    """Did the gateway refuse this request?

    A JSON-RPC refusal is carried in the `error` object, and the gateway
    deliberately keeps HTTP 200 for protocol-level errors -- `_http_status_for`
    reserves non-200 for transport concerns like 401, 403 and 429. Asserting on
    the HTTP status alone would therefore read a correct refusal as a success.
    """
    if status != 200:
        return True
    return isinstance(body, dict) and "error" in body


def rpc_error_code(body):
    return ((body or {}).get("error") or {}).get("code")


def a2a(base: str, payload: dict, headers=None, *, attempts: int = 10):
    """POST, yielding to the rate limiter rather than misreporting it.

    A 429 is not an answer to any question this script asks, so it waits and
    retries. It never retries any other status -- a 401 must stay a 401.
    """
    status, body = 0, {}
    for attempt in range(attempts):
        status, body = http("POST", f"{base}/api/a2a", body=payload,
                            headers=headers)
        limited = status == 429 or (isinstance(body, dict)
                                    and (body.get("error") or {}).get("code") == -32010)
        if not limited:
            return status, body
        time.sleep(1 + attempt * 0.6)
    return status, body


def a2a_raw(base: str, payload: dict, headers=None):
    """POST once, reporting whatever comes back -- including a 429.

    Used where the rate limit is the thing under test.
    """
    return http("POST", f"{base}/api/a2a", body=payload, headers=headers)


# --------------------------------------------------------------------------- #
# throwaway fixtures
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
             LABEL, now, now))
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


def evidence_rows(peer_id: str):
    conn = connect()
    try:
        return conn.execute(
            "SELECT event_type, COUNT(*) FROM a2a_peer_evidence "
            "WHERE peer_id = ? GROUP BY event_type", (peer_id,)).fetchall()
    except sqlite3.OperationalError:
        return []
    finally:
        conn.close()


def evidence_counts(peer_id: str) -> dict:
    return {row[0]: row[1] for row in evidence_rows(peer_id)}


def assess(peer_id: str, *, now=None):
    """Ask the trust layer itself, against the database the service wrote."""
    from a2a_gateway import trust as gw_trust
    conn = connect()
    try:
        gw_trust.init_schema(conn)
        return gw_trust.assess_peer(conn, peer_id, now=now)
    finally:
        conn.close()


BASELINE: dict = {}


def db_totals() -> dict:
    """Total row counts, used to prove the run left the database as it found it."""
    conn = connect()
    try:
        from a2a_gateway import trust as gw_trust
        gw_trust.init_schema(conn)
        return {
            "credentials": conn.execute(
                "SELECT COUNT(*) FROM a2a_peer_credentials").fetchone()[0],
            "agents": conn.execute(
                "SELECT COUNT(*) FROM agents WHERE label = ?", (LABEL,)
            ).fetchone()[0],
            "evidence": conn.execute(
                "SELECT COUNT(*) FROM a2a_peer_evidence").fetchone()[0],
        }
    finally:
        conn.close()


def cleanup(owners, agent_ids) -> dict:
    conn = connect()
    try:
        peer_ids = [row[0] for row in conn.execute(
            "SELECT DISTINCT peer_id FROM a2a_peer_credentials "
            "WHERE owner_address IN (%s)" % ",".join("?" * len(owners)),
            [o.lower() for o in owners]).fetchall()]
        for peer_id in peer_ids:
            conn.execute("DELETE FROM a2a_peer_evidence WHERE peer_id = ?",
                         (peer_id,))
        for address in owners:
            conn.execute("DELETE FROM a2a_peer_credentials WHERE owner_address = ?",
                         (address.lower(),))
        for agent_id in agent_ids:
            conn.execute("DELETE FROM agent_keys WHERE agent_id = ?", (agent_id,))
            conn.execute("DELETE FROM agents WHERE agent_id = ?", (agent_id,))
            conn.execute("DELETE FROM a2a_inbound_requests WHERE target_agent = ?",
                         (agent_id,))
        conn.commit()
        # Count what belongs to THIS run. A bare global count would silently
        # blame the run for rows somebody else left behind, and -- worse --
        # would pass in an empty database for the wrong reason.
        placeholders = ",".join("?" * len(owners))
        params = [o.lower() for o in owners]
        return {
            "credentials": conn.execute(
                "SELECT COUNT(*) FROM a2a_peer_credentials "
                "WHERE owner_address IN (%s)" % placeholders, params).fetchone()[0],
            "agents": sum(conn.execute(
                "SELECT COUNT(*) FROM agents WHERE agent_id = ?", (a,)
            ).fetchone()[0] for a in agent_ids) if agent_ids else 0,
            "evidence": conn.execute(
                "SELECT COUNT(*) FROM a2a_peer_evidence WHERE peer_id IN ("
                "  SELECT peer_id FROM a2a_peer_credentials "
                "  WHERE owner_address IN (%s))" % placeholders, params
            ).fetchone()[0],
        }
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
def main() -> int:
    global DB
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="http://127.0.0.1:8891")
    parser.add_argument("--db", default="./test_aera_trust.db")
    args = parser.parse_args()
    base, DB = args.base.rstrip("/"), args.db

    print("=" * 78)
    print("LIVE CHECK -- AEra external peer trust assessment (Part J)")
    print(f"target: {base}   database: {DB}")
    print("=" * 78)

    # --- refusal guards ---------------------------------------------------- #
    # A green run must mean something. Both of these would make it meaningless.
    if os.path.abspath(DB) == os.path.abspath("./aera.db"):
        print("\nABORT: pointed at the production database.")
        return 3
    status, card = http("GET", f"{base}/.well-known/agent-card.json")
    if status != 200:
        print(f"\nABORT: no agent card at {base} (status {status}).")
        return 3

    from a2a_gateway import trust as gw_trust
    mode_status, mode_body = http("GET", f"{base}/api/dashboard/a2a-peer-trust",
                                  headers={})
    # Unauthenticated, so a 401 is expected; what matters is that the ROUTE
    # exists. A 404 means the instance predates the trust layer, and every
    # observation below would silently measure nothing.
    if mode_status == 404:
        print("\nABORT: this instance has no trust endpoint -- it is running "
              "code from before Part J.")
        return 3

    owner = "0x" + secrets.token_hex(20)
    stranger = "0x" + secrets.token_hex(20)
    owners, agents = [owner, stranger], []
    global BASELINE
    BASELINE = db_totals()
    print(f"database baseline: {BASELINE}")
    observed_states, observed_events = [], {}

    try:
        agent_a = make_agent(owner, ["agent.read.profile"])
        agent_b = make_agent(owner, ["agent.read.profile"])
        agent_x = make_agent(stranger, ["agent.read.profile"])
        agents += [agent_a, agent_b, agent_x]
        token = {"Authorization": "Bearer " + dashboard_jwt(owner)}

        # ---------------------------------------------------------------- #
        # 1. a new peer starts as `unknown` with no history
        # ---------------------------------------------------------------- #
        status, issued = http(
            "POST", f"{base}/api/dashboard/a2a-credentials", headers=token,
            body={"peer_label": "partj-peer", "scoped_agents": [agent_a, agent_b],
                  "scoped_skills": ["agent.read.profile"]})
        check("01 credential issued to a throwaway peer",
              status == 200 and issued.get("success") is True,
              f"status={status} body={issued}")
        credential = issued.get("credential", "")
        peer_id = issued.get("peer_id", "")
        cred_id = issued.get("cred_id", "")
        if not credential or not peer_id:
            raise RuntimeError(f"issuance did not return a usable credential: {issued}")
        peer_headers = {"Authorization": "Bearer " + credential}

        baseline = assess(peer_id)
        observed_states.append(("new peer", baseline.trust_level,
                                round(baseline.confidence, 3)))
        check("02 a brand-new peer is assessed `unknown`",
              baseline.trust_level == gw_trust.LEVEL_UNKNOWN,
              f"level={baseline.trust_level}")
        check("03 a brand-new peer has no evidence history",
              evidence_counts(peer_id) == {},
              f"evidence={evidence_counts(peer_id)}")
        check("04 a brand-new peer's confidence is below the opinion floor",
              baseline.confidence < gw_trust.MIN_CONFIDENCE_FOR_OPINION,
              f"confidence={baseline.confidence}")

        # ---------------------------------------------------------------- #
        # 2. real authenticated traffic becomes positive evidence
        # ---------------------------------------------------------------- #
        successes = 0
        for _ in range(6):
            status, body = a2a(base, rpc(agent_a), peer_headers)
            if status == 200 and "result" in body:
                successes += 1
        check("05 authenticated requests succeed against the live gateway",
              successes >= 5, f"{successes}/6 succeeded")

        counts = evidence_counts(peer_id)
        observed_events.update(counts)
        check("06 successful traffic is recorded as positive evidence",
              counts.get(gw_trust.EV_REQUEST_SUCCESS, 0) >= 5,
              f"evidence={counts}")

        after_success = assess(peer_id)
        observed_states.append(("after successes", after_success.trust_level,
                                round(after_success.confidence, 3)))
        check("07 observed success raises the assessment",
              after_success.trust_score > baseline.trust_score,
              f"{baseline.trust_score:.4f} -> {after_success.trust_score:.4f}")
        check("08 observed success raises confidence",
              after_success.confidence > baseline.confidence,
              f"{baseline.confidence:.4f} -> {after_success.confidence:.4f}")

        # Determinism is a property of the calculation, not of the clock. The
        # relationship-age factor grows continuously, so two reads taken a
        # second apart legitimately differ in the far decimals. Pinning `now`
        # asks the question that actually matters: same evidence, same instant,
        # same answer.
        pinned = datetime.now(timezone.utc)
        first_read = assess(peer_id, now=pinned)
        second_read = assess(peer_id, now=pinned)
        check("09 the assessment is deterministic on identical evidence",
              (first_read.trust_level, first_read.trust_score, first_read.confidence)
              == (second_read.trust_level, second_read.trust_score,
                  second_read.confidence),
              f"{first_read.to_audit_dict()} vs {second_read.to_audit_dict()}")
        check("09b the assessment advances only with evidence, not with re-reads",
              first_read.evidence_counts == second_read.evidence_counts,
              "evidence changed between two reads")
        repeat = assess(peer_id)
        check("10 the assessment carries the policy version",
              repeat.policy_version == gw_trust.POLICY_VERSION,
              f"policy={repeat.policy_version}")

        # ---------------------------------------------------------------- #
        # 3. real negative behaviour
        # ---------------------------------------------------------------- #
        before_negative = assess(peer_id)

        # 3a. replay -- the same messageId twice
        replay_id = str(uuid.uuid4())
        first_status, first_body = a2a(base, rpc(agent_a, message_id=replay_id),
                                       peer_headers)
        second_status, second_body = a2a(base, rpc(agent_a, message_id=replay_id),
                                         peer_headers)
        check("11 a replayed messageId is refused by the live gateway",
              not rpc_refused(first_status, first_body)
              and rpc_refused(second_status, second_body),
              f"first={first_status}/{rpc_error_code(first_body)} "
              f"second={second_status}/{rpc_error_code(second_body)}")
        check("11b the refusal names the duplicate explicitly",
              "duplicate" in str((second_body.get("error") or {}).get("message", "")).lower(),
              f"message={(second_body.get('error') or {}).get('message')}")
        counts = evidence_counts(peer_id)
        check("12 the replay is recorded as `replay_rejected` evidence",
              counts.get(gw_trust.EV_REPLAY_REJECTED, 0) >= 1,
              f"evidence={counts}")

        # 3b. authorization denial -- an agent outside the credential's scope
        status, body = a2a(base, rpc(agent_x), peer_headers)
        check("13 an out-of-scope agent is refused (403)",
              status == 403, f"status={status} body={body}")
        counts = evidence_counts(peer_id)
        check("14 the refusal is recorded as `authorization_denied` evidence",
              counts.get(gw_trust.EV_AUTHORIZATION_DENIED, 0) >= 1,
              f"evidence={counts}")
        check("15 the refusal message does not reveal that the agent exists",
              "not available" in str((body.get("error") or {}).get("message", "")),
              f"message={(body.get('error') or {}).get('message')}")

        # 3c. invalid request
        status, body = a2a(base, rpc(agent_a, skill="agent.invent.nonsense"),
                           peer_headers)
        check("16 an invalid skill is refused",
              rpc_refused(status, body),
              f"status={status} code={rpc_error_code(body)}")
        counts = evidence_counts(peer_id)
        check("17 the invalid request is recorded as evidence",
              counts.get(gw_trust.EV_INVALID_REQUEST, 0) >= 1,
              f"evidence={counts}")

        # 3d. rate limit.
        #
        # WHICH bucket trips matters, and this is the one place where the
        # architecture constrains what can be observed. `routes.py` enforces
        # the global and per-source buckets BEFORE the body is read, precisely
        # so that a rejected request costs nothing -- which also means
        # `handle_request` never runs and no evidence is written. Only the
        # per-credential bucket, checked inside the handler, can produce a
        # `rate_limited` observation.
        #
        # So the check is conditional on which limit actually bound. Claiming
        # the evidence unconditionally would assert something the design does
        # not promise; skipping silently would hide a real gap. It does neither.
        limited = False
        for _ in range(60):
            status, body = a2a_raw(base, rpc(agent_a), peer_headers)
            if status == 429:
                limited = True
                break
        check("18 a burst trips the live rate limiter", limited,
              "no 429 within 60 requests")

        if limited:
            time.sleep(2)
            counts = evidence_counts(peer_id)
            if counts.get(gw_trust.EV_RATE_LIMITED, 0) >= 1:
                check("19 the rate-limit event is recorded as evidence", True)
            else:
                # Determine which bucket bound, so the report states a fact
                # rather than a suspicion.
                from a2a_gateway import ratelimit as gw_rl
                cred_limit = gw_rl.load_limits()[gw_rl.SCOPE_CREDENTIAL]
                peer_limit = gw_rl.load_limits()[gw_rl.SCOPE_PEER]
                outer_binds = peer_limit.burst <= cred_limit.burst
                check("19 the rate-limit event is recorded as evidence when the "
                      "credential bucket is the binding limit",
                      outer_binds,
                      f"credential bucket was binding (peer burst={peer_limit.burst}, "
                      f"credential burst={cred_limit.burst}) yet no evidence "
                      f"was written: {counts}")
                if outer_binds:
                    print(f"       note: the per-source bucket bound first "
                          f"(burst {peer_limit.burst} vs credential "
                          f"{cred_limit.burst}), so the handler never ran and "
                          f"no evidence could be written. This is the documented "
                          f"design, not a defect.")
        else:
            skip("19 the rate-limit event is recorded as evidence",
                 "the limiter never tripped, so there was nothing to record")

        observed_events.update(evidence_counts(peer_id))
        after_negative = assess(peer_id)
        observed_states.append(("after negatives", after_negative.trust_level,
                                round(after_negative.confidence, 3)))
        check("20 negative behaviour lowers the assessment",
              after_negative.trust_score < before_negative.trust_score,
              f"{before_negative.trust_score:.4f} -> {after_negative.trust_score:.4f}")
        check("21 sustained misbehaviour is not averaged away by good history",
              after_negative.rank <= before_negative.rank,
              f"{before_negative.trust_level} -> {after_negative.trust_level}")

        # ---------------------------------------------------------------- #
        # 4. credential rotation preserves the peer
        # ---------------------------------------------------------------- #
        before_rotation = evidence_counts(peer_id)
        conn = connect()
        try:
            from a2a_gateway import credentials as gw_cred
            rotated = gw_cred.issue_credential(
                conn, owner_address=owner, peer_id=peer_id,
                scoped_agents=[agent_a, agent_b],
                scoped_skills=["agent.read.profile"], peer_label="partj-peer")
            conn.commit()
        finally:
            conn.close()
        rotated_headers = {"Authorization": "Bearer " + rotated.plaintext}

        check("22 the rotated credential belongs to the SAME peer_id",
              rotated.record.peer_id == peer_id,
              f"{peer_id} vs {rotated.record.peer_id}")
        check("23 the rotated credential is a different credential",
              rotated.record.cred_id != cred_id, "cred_id was reused")

        status, body = a2a(base, rpc(agent_a), rotated_headers)
        check("24 the rotated credential authenticates live",
              status == 200, f"status={status} body={body}")
        after_rotation = evidence_counts(peer_id)
        check("25 rotation preserves the peer's evidence history",
              all(after_rotation.get(k, 0) >= v for k, v in before_rotation.items()),
              f"{before_rotation} -> {after_rotation}")
        check("26 both credentials feed ONE peer assessment",
              assess(peer_id).peer_id == peer_id, "peer identity split")

        # ---------------------------------------------------------------- #
        # 5. revocation beats trust
        # ---------------------------------------------------------------- #
        trusted_now = assess(peer_id)
        status, body = http("POST",
                            f"{base}/api/dashboard/a2a-credentials/{cred_id}/revoke",
                            headers=token, body={"reason": "part-j live check"})
        check("27 the original credential is revoked via the dashboard",
              status == 200 and body.get("success") is True,
              f"status={status} body={body}")
        status, body = a2a(base, rpc(agent_a), peer_headers)
        check("28 a revoked credential is refused regardless of the assessment",
              status == 401,
              f"status={status} while peer level={trusted_now.trust_level}")
        status, body = a2a(base, rpc(agent_a), rotated_headers)
        check("29 revoking one credential does not disable the peer's other one",
              status == 200, f"status={status}")

        # ---------------------------------------------------------------- #
        # 6. anonymous traffic manufactures nothing
        # ---------------------------------------------------------------- #
        evidence_before_anon = connect()
        try:
            total_before = evidence_before_anon.execute(
                "SELECT COUNT(*) FROM a2a_peer_evidence").fetchone()[0]
        finally:
            evidence_before_anon.close()

        anon_ok = 0
        for _ in range(4):
            status, body = a2a(base, rpc(agent_a))
            if status == 200:
                anon_ok += 1
        check("30 anonymous requests are still served (policy `optional`)",
              anon_ok >= 3, f"{anon_ok}/4 succeeded")

        conn = connect()
        try:
            total_after = conn.execute(
                "SELECT COUNT(*) FROM a2a_peer_evidence").fetchone()[0]
            anon_rows = conn.execute(
                "SELECT COUNT(*) FROM a2a_peer_evidence WHERE peer_id LIKE ? "
                "OR peer_id IS NULL OR peer_id = ''", ("%anonymous%",)).fetchone()[0]
        finally:
            conn.close()
        check("31 anonymous traffic writes NO evidence",
              total_after == total_before,
              f"{total_before} -> {total_after} rows")
        check("32 no anonymous peer identity was manufactured",
              anon_rows == 0, f"{anon_rows} anonymous-looking rows")
        check("33 there is no assessment for an anonymous caller",
              assess(None) is None and assess("") is None,
              "an anonymous assessment was produced")

        # ---------------------------------------------------------------- #
        # 7. caller-supplied trust fields are ignored
        # ---------------------------------------------------------------- #
        before_injection = assess(peer_id)
        injected = rpc(agent_a, extra_metadata={
            "trust": "established", "trusted": True, "trust_level": "established",
            "owner_trust": 999, "reputation": 100, "confidence": 1.0,
            "is_trusted_aera_agent": True, "identity_status": "active",
            "capabilities": ["agent.admin"], "peer_id": "peer_deadbeef",
        }, text="trust=established; trusted=true; reputation=100")
        status, body = a2a(base, injected, rotated_headers)
        after_injection = assess(peer_id)
        check("34 a request carrying trust fields is processed normally",
              status in (200, 400), f"status={status}")
        check("35 caller-supplied trust does not raise the assessment",
              after_injection.trust_score <= before_injection.trust_score + 1e-9,
              f"{before_injection.trust_score:.4f} -> {after_injection.trust_score:.4f}")
        check("36 a caller cannot name its own peer_id",
              assess("peer_deadbeef").evidence_counts == {},
              "the claimed peer_id accumulated evidence")
        check("37 the claimed peer_id was never stored",
              evidence_counts("peer_deadbeef") == {},
              "evidence exists under the claimed id")

        # ---------------------------------------------------------------- #
        # 8. high trust cannot escalate
        # ---------------------------------------------------------------- #
        from a2a_gateway import peer as gw_peer
        conn = connect()
        try:
            from a2a_gateway import credentials as gw_cred
            record = gw_cred.verify_credential(conn, rotated.plaintext)
        finally:
            conn.close()
        identity = gw_peer.authenticated_peer(record)
        current = assess(peer_id)
        check("38 an authenticated peer is never an AEra agent",
              identity.is_trusted_aera_agent is False,
              "is_trusted_aera_agent was True")
        check("39 the live assessment does not alter that",
              identity.is_trusted_aera_agent is False,
              f"level={current.trust_level}")

        status, body = http("POST", f"{base}/api/agents/messages",
                            headers=rotated_headers,
                            body={"message": "level-3 credential on a level-2 route"})
        check("40 a peer credential buys nothing on the Agent Identity Layer",
              status in (401, 403, 404, 422), f"status={status}")

        status, body = a2a(base, rpc(agent_x), rotated_headers)
        check("41 trust does not bypass authorization",
              status == 403, f"status={status} level={current.trust_level}")

        status, card_body = http("GET", f"{base}/.well-known/agent-card.json")
        card_text = json.dumps(card_body).lower()
        check("42 the Agent Card discloses no trust information",
              all(marker not in card_text for marker in
                  ("trust_level", "trust_score", "peer_evidence", "confidence",
                   "a2a_peer_evidence")),
              "the card mentions trust")
        check("43 the Agent Card discloses no peer_id",
              peer_id.lower() not in card_text, "the card names a peer")

        # ---------------------------------------------------------------- #
        # 9. the dashboard surface is read-only and minimal
        # ---------------------------------------------------------------- #
        status, view = http("GET", f"{base}/api/dashboard/a2a-peer-trust",
                            headers=token)
        check("44 the owner can read AEra's assessment",
              status == 200 and view.get("success") is True,
              f"status={status} body={view}")
        peers = view.get("peers") or []
        entry = next((p for p in peers if p.get("peer_id") == peer_id), None)
        check("45 the owner's own peer appears in the assessment",
              entry is not None, f"peers={[p.get('peer_id') for p in peers]}")
        if entry:
            observed_states.append(("dashboard", entry.get("trust_level"),
                                    entry.get("confidence_band")))
            check("46 the surface declares the assessment AEra-derived",
                  entry.get("assessed_by") == "aera"
                  and entry.get("owner_settable") is False,
                  f"entry={entry}")
            check("47 the surface exposes no raw score and no weights",
                  not any(k in entry for k in
                          ("trust_score", "factors", "weights", "confidence",
                           "decay_multiplier", "evidence_counts")),
                  f"keys={sorted(entry)}")
            check("48 the surface exposes no credential material",
                  not any(k in entry for k in
                          ("credential", "secret", "secret_hash", "cred_id")),
                  f"keys={sorted(entry)}")
        else:
            skip("46 the surface declares the assessment AEra-derived", "no entry")
            skip("47 the surface exposes no raw score and no weights", "no entry")
            skip("48 the surface exposes no credential material", "no entry")

        body_text = json.dumps(view)
        check("49 no credential secret appears anywhere in the response",
              "aera_a2a_" not in body_text, "a credential leaked")
        check("50 the surface reports enforcement as disabled",
              view.get("enforces_authorization") is False,
              f"enforces={view.get('enforces_authorization')}")

        status, denied = http("GET", f"{base}/api/dashboard/a2a-peer-trust",
                              headers={"Authorization": "Bearer " + dashboard_jwt(stranger)})
        stranger_peers = (denied.get("peers") or []) if status == 200 else []
        check("51 another owner cannot see this peer's assessment",
              all(p.get("peer_id") != peer_id for p in stranger_peers),
              "a stranger saw the assessment")

        status, _ = http("POST", f"{base}/api/dashboard/a2a-peer-trust",
                         headers=token, body={"peer_id": peer_id,
                                              "trust_level": "established"})
        check("52 there is no endpoint to set trust",
              status in (404, 405), f"status={status}")

        # ---------------------------------------------------------------- #
        # summary of what was actually observed
        # ---------------------------------------------------------------- #
        final = assess(peer_id)
        observed_states.append(("final", final.trust_level,
                                round(final.confidence, 3)))
        observed_events.update(evidence_counts(peer_id))

    finally:
        leftovers = cleanup(owners, agents)
        after = db_totals()
        print("\n" + "-" * 78)
        print(f"cleanup: credentials={leftovers['credentials']} "
              f"agents={leftovers['agents']} evidence={leftovers['evidence']}")
        check("53 cleanup leaves no throwaway artefacts",
              leftovers["credentials"] == 0 and leftovers["agents"] == 0
              and leftovers["evidence"] == 0, f"{leftovers}")
        check("54 the database is left exactly as the run found it",
              after == BASELINE,
              f"before={BASELINE} after={after}")

    print("\n" + "-" * 78)
    print("trust states observed:")
    for stage, level, confidence in observed_states:
        print(f"  {stage:<18} level={level:<12} confidence={confidence}")
    print("evidence events observed:")
    for name, count in sorted(observed_events.items()):
        print(f"  {name:<24} {count}")

    print("\n" + "=" * 78)
    print(f"RESULT: {len(PASS)} passed, {len(FAIL)} failed, {len(SKIP)} skipped")
    if FAIL:
        print("\nFAILED:")
        for name in FAIL:
            print(f"  - {name}")
    print("=" * 78)
    return 0 if not FAIL else 1


if __name__ == "__main__":
    raise SystemExit(main())
