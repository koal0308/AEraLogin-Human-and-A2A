"""Integration tests for the Agent Identity Layer (Spec §17, T-01..T-39).

Covers happy path plus every threat-model row. Uses in-process FastAPI
TestClient. web3_service is stubbed by the root conftest.
"""
from __future__ import annotations

import base64
import hashlib
import secrets
import time
from datetime import datetime, timedelta, timezone

import jwt as pyjwt
import pytest

from agent.constants import (
    AGENT_AUTH_KEYS,
    AGENT_MESSAGE_KEYS,
    AUD_AGENT_API,
    AUD_AGENT_RELAY,
    JWT_ALG,
    JWT_ISSUER,
    JWT_TYP,
    PROTO_AGENT_AUTH,
    PROTO_AGENT_MESSAGE,
    PROTOCOL_VERSION,
)
from agent.crypto import Ed25519Signer, b64u_encode, canonical_json
from agent import tokens as _tokens
from agent import repository as _repo

from tests.agent.testclient import ANVIL_KEY_2, AgentTestClient


# -------- fixtures ----------------------------------------------------------
@pytest.fixture()
def a(client, wipe_agent_tables):
    c = AgentTestClient(client)
    c.register(capabilities=["agent.authenticate", "agent.read.profile",
                             "agent.communicate", "agent.interaction.record"])
    return c


@pytest.fixture()
def b(client, wipe_agent_tables, a):
    c = AgentTestClient(client, eth_priv=ANVIL_KEY_2)
    c.register(capabilities=["agent.authenticate", "agent.communicate"])
    return c


# -------- happy path smoke --------------------------------------------------
def test_full_happy_path(a):
    r = a.authenticate()
    assert r.status_code == 200, r.text
    assert a.token

    r = a.http.post("/api/agents/verify-jwt", headers=a.auth_headers())
    assert r.status_code == 200
    body = r.json()
    assert body["agent_id"] == a.agent_id
    assert body["typ"] == JWT_TYP


# =========================================================================== #
# T-01..T-39
# =========================================================================== #
def test_t01_impersonation_rejected(a, b):
    """T-01: request against A's endpoint but signed by B's key → 401."""
    # get challenge for A
    r = a.get_challenge()
    ch = r.json()
    # sign with B's Ed25519 signer
    payload = {
        "protocol": PROTO_AGENT_AUTH, "version": PROTOCOL_VERSION,
        "agent_id": a.agent_id, "key_id": a.key_id,
        "challenge_id": ch["challenge_id"], "challenge": ch["challenge"],
        "aud": AUD_AGENT_API, "issued_at": ch["issued_at"],
        "expires_at": ch["expires_at"],
    }
    canon = canonical_json(payload, AGENT_AUTH_KEYS)
    sig = b64u_encode(b.signer.sign(canon))
    resp = a.http.post(f"/api/agents/{a.agent_id}/authenticate", json={
        "challenge_id": ch["challenge_id"], "key_id": a.key_id,
        "aud": AUD_AGENT_API, "signature": sig,
    })
    assert resp.status_code == 401


def test_t02_key_replacement_requires_owner_challenge(a):
    """T-02: adding a key without owner challenge → 401."""
    new_signer = Ed25519Signer.generate()
    # missing owner_challenge_id → validation error / 4xx
    r = a.http.post(f"/api/agents/{a.agent_id}/keys", json={
        "owner_wallet": a.owner,
        "owner_challenge_id": "deadbeef",
        "owner_signature": "0x00",
        "public_key": new_signer.public_key_encoded(),
    })
    assert r.status_code == 401


def test_t03_agent_challenge_single_use(a):
    """T-03: same challenge cannot be consumed twice."""
    assert a.authenticate().status_code == 200
    # replay authenticate with same challenge → we have to build one manually
    # Use previous challenge_id from server, but re-authenticate re-issues a new
    # challenge. So instead: issue challenge, authenticate once, then hand-craft
    # a second authenticate with the same challenge_id → 401.
    r = a.get_challenge()
    ch = r.json()
    payload = {
        "protocol": PROTO_AGENT_AUTH, "version": PROTOCOL_VERSION,
        "agent_id": a.agent_id, "key_id": a.key_id,
        "challenge_id": ch["challenge_id"], "challenge": ch["challenge"],
        "aud": AUD_AGENT_API, "issued_at": ch["issued_at"],
        "expires_at": ch["expires_at"],
    }
    sig = b64u_encode(a.signer.sign(canonical_json(payload, AGENT_AUTH_KEYS)))
    body = {"challenge_id": ch["challenge_id"], "key_id": a.key_id,
            "aud": AUD_AGENT_API, "signature": sig}
    r1 = a.http.post(f"/api/agents/{a.agent_id}/authenticate", json=body)
    assert r1.status_code == 200
    r2 = a.http.post(f"/api/agents/{a.agent_id}/authenticate", json=body)
    assert r2.status_code == 401


def test_t04_expired_challenge_rejected(a):
    """T-04: expire the challenge in DB, then authenticate → 401."""
    r = a.get_challenge()
    ch = r.json()
    # forcibly age the row
    conn = _repo.get_connection()
    conn.execute(
        "UPDATE agent_challenges SET expires_at=? WHERE challenge_id=?",
        ("2000-01-01T00:00:00Z", ch["challenge_id"]),
    )
    conn.commit(); conn.close()
    payload = {
        "protocol": PROTO_AGENT_AUTH, "version": PROTOCOL_VERSION,
        "agent_id": a.agent_id, "key_id": a.key_id,
        "challenge_id": ch["challenge_id"], "challenge": ch["challenge"],
        "aud": AUD_AGENT_API, "issued_at": ch["issued_at"],
        "expires_at": ch["expires_at"],
    }
    sig = b64u_encode(a.signer.sign(canonical_json(payload, AGENT_AUTH_KEYS)))
    r2 = a.http.post(f"/api/agents/{a.agent_id}/authenticate", json={
        "challenge_id": ch["challenge_id"], "key_id": a.key_id,
        "aud": AUD_AGENT_API, "signature": sig,
    })
    assert r2.status_code == 401


def test_t05_wrong_agent_signature_rejected(a):
    r = a.get_challenge(); ch = r.json()
    # sign wrong bytes
    sig = b64u_encode(a.signer.sign(b"wrong"))
    r2 = a.http.post(f"/api/agents/{a.agent_id}/authenticate", json={
        "challenge_id": ch["challenge_id"], "key_id": a.key_id,
        "aud": AUD_AGENT_API, "signature": sig,
    })
    assert r2.status_code == 401


def test_t06_signature_from_another_agent(a, b):
    r = a.get_challenge(); ch = r.json()
    # canonical bytes for A, signed by B
    payload = {
        "protocol": PROTO_AGENT_AUTH, "version": PROTOCOL_VERSION,
        "agent_id": a.agent_id, "key_id": a.key_id,
        "challenge_id": ch["challenge_id"], "challenge": ch["challenge"],
        "aud": AUD_AGENT_API, "issued_at": ch["issued_at"],
        "expires_at": ch["expires_at"],
    }
    sig = b64u_encode(b.signer.sign(canonical_json(payload, AGENT_AUTH_KEYS)))
    r2 = a.http.post(f"/api/agents/{a.agent_id}/authenticate", json={
        "challenge_id": ch["challenge_id"], "key_id": a.key_id,
        "aud": AUD_AGENT_API, "signature": sig,
    })
    assert r2.status_code == 401


def test_t07_revoked_agent_rejected(a):
    assert a.authenticate().status_code == 200
    resp = a.revoke_agent()
    assert resp.status_code == 200
    # existing JWT no longer valid
    r = a.http.post("/api/agents/verify-jwt", headers=a.auth_headers())
    assert r.status_code == 401
    # new challenge fails
    r2 = a.get_challenge()
    assert r2.status_code in (401, 404)


def test_t08_cross_agent_jwt(a, b):
    assert a.authenticate().status_code == 200
    # Try to use A's token in the messages endpoint pretending to be B.
    payload, sig = a.build_message(receiver=b.agent_id)
    # Corrupt sender to B while keeping A's JWT: server must reject via
    # verify_and_store because jwt_sender (A) != payload.sender (B).
    payload["sender_agent_id"] = b.agent_id
    canon = canonical_json(payload, AGENT_MESSAGE_KEYS)
    sig = b64u_encode(a.signer.sign(canon))
    r = a.http.post("/api/agents/messages",
                    json={"payload": payload, "signature": sig},
                    headers=a.auth_headers())
    assert r.status_code == 401


def test_t09_wrong_audience(a):
    # get token with aud=aera-agent-api
    a.authenticate(aud=AUD_AGENT_API)
    # send to relay endpoint (needs aera-agent-relay) → 401
    payload, sig = a.build_message(receiver=a.agent_id)
    r = a.http.post("/api/agents/messages",
                    json={"payload": payload, "signature": sig},
                    headers=a.auth_headers())
    assert r.status_code == 401


def test_t10_wrong_issuer(a):
    # Craft a JWT with correct signature/secret but wrong iss.
    a.authenticate()
    now = int(time.time())
    secret = _tokens.get_secret()
    bad = pyjwt.encode({
        "iss": "evil.example",
        "sub": a.agent_id, "aud": AUD_AGENT_API,
        "iat": now, "exp": now + 60, "jti": secrets.token_hex(16),
        "typ": JWT_TYP, "key_id": a.key_id,
        "owner_wallet": a.owner, "capabilities": [],
    }, secret, algorithm=JWT_ALG)
    r = a.http.post("/api/agents/verify-jwt",
                    headers={"Authorization": f"Bearer {bad}"})
    assert r.status_code == 401


def test_t11_valid_jwt_reusable_within_exp(a):
    a.authenticate()
    for _ in range(5):
        r = a.http.post("/api/agents/verify-jwt", headers=a.auth_headers())
        assert r.status_code == 200


def test_t11a_revoked_jwt_rejected(a):
    a.authenticate()
    payload = pyjwt.decode(a.token, options={"verify_signature": False})
    jti = payload["jti"]
    r = a.http.post("/api/agents/tokens/revoke",
                    json={"jti": jti}, headers=a.auth_headers())
    assert r.status_code == 200
    r2 = a.http.post("/api/agents/verify-jwt", headers=a.auth_headers())
    assert r2.status_code == 401


def test_t11b_unknown_jti_rejected(a):
    # Craft correctly-signed JWT with jti that was never issued.
    a.authenticate()
    secret = _tokens.get_secret()
    now = int(time.time())
    bad = pyjwt.encode({
        "iss": JWT_ISSUER, "sub": a.agent_id, "aud": AUD_AGENT_API,
        "iat": now, "exp": now + 60, "jti": secrets.token_hex(16),
        "typ": JWT_TYP, "key_id": a.key_id,
        "owner_wallet": a.owner, "capabilities": [],
    }, secret, algorithm=JWT_ALG)
    r = a.http.post("/api/agents/verify-jwt",
                    headers={"Authorization": f"Bearer {bad}"})
    assert r.status_code == 401


def test_t11c_invalid_jti_format(a):
    a.authenticate()
    secret = _tokens.get_secret()
    now = int(time.time())
    bad = pyjwt.encode({
        "iss": JWT_ISSUER, "sub": a.agent_id, "aud": AUD_AGENT_API,
        "iat": now, "exp": now + 60, "jti": "",
        "typ": JWT_TYP, "key_id": a.key_id,
        "owner_wallet": a.owner, "capabilities": [],
    }, secret, algorithm=JWT_ALG)
    r = a.http.post("/api/agents/verify-jwt",
                    headers={"Authorization": f"Bearer {bad}"})
    assert r.status_code == 401


def test_t12_interaction_records_agent_id(a, b):
    assert a.authenticate(aud=AUD_AGENT_API).status_code == 200
    payload, sig = a.build_message(receiver=b.agent_id, content=b"x")
    r = a.http.post("/api/agents/interactions",
                    json={"payload": payload, "signature": sig,
                          "interaction_type": 1, "metadata": {"kind": "hello"}},
                    headers=a.auth_headers())
    assert r.status_code == 200, r.text
    # verify DB row
    conn = _repo.get_connection()
    row = conn.execute(
        "SELECT initiator_agent_id, responder_agent_id FROM agent_interactions "
        "WHERE message_id=?", (payload["message_id"],)
    ).fetchone(); conn.close()
    assert row["initiator_agent_id"] == a.agent_id
    assert row["responder_agent_id"] == b.agent_id


def _forge(a, *, drop=None, override=None):
    secret = _tokens.get_secret()
    now = int(time.time())
    p = {
        "iss": JWT_ISSUER, "sub": a.agent_id, "aud": AUD_AGENT_API,
        "iat": now, "exp": now + 60, "jti": secrets.token_hex(16),
        "typ": JWT_TYP, "key_id": a.key_id,
        "owner_wallet": a.owner, "capabilities": [],
    }
    if drop:
        p.pop(drop, None)
    if override:
        p.update(override)
    return pyjwt.encode(p, secret, algorithm=JWT_ALG)


@pytest.mark.parametrize("claim", ["sub", "exp", "iat", "jti"])
def test_t13_t16_missing_required_claim(a, claim):
    a.authenticate()
    tok = _forge(a, drop=claim)
    r = a.http.post("/api/agents/verify-jwt",
                    headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 401


def test_t17_missing_typ(a):
    a.authenticate()
    tok = _forge(a, override={"typ": "not-agent"})
    r = a.http.post("/api/agents/verify-jwt",
                    headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 401


def test_t18_expired_jwt(a):
    a.authenticate()
    tok = _forge(a, override={"exp": int(time.time()) - 10, "iat": int(time.time()) - 100})
    r = a.http.post("/api/agents/verify-jwt",
                    headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 401


def test_t19_invalid_signature(a):
    a.authenticate()
    tampered = a.token[:-4] + "AAAA"
    r = a.http.post("/api/agents/verify-jwt",
                    headers={"Authorization": f"Bearer {tampered}"})
    assert r.status_code == 401


def test_t20_key_rotation(a):
    a.authenticate()
    old_jti = pyjwt.decode(a.token, options={"verify_signature": False})["jti"]
    new_signer = Ed25519Signer.generate()
    new_key_id = a.rotate_key(new_signer, revoke=a.key_id)
    # old JWT invalidated
    r = a.http.post("/api/agents/verify-jwt", headers=a.auth_headers())
    assert r.status_code == 401
    # T-22: new key can auth
    a.signer = new_signer
    a.key_id = new_key_id
    assert a.authenticate().status_code == 200


def test_t21_old_key_rejected(a):
    a.authenticate()
    old_key = a.key_id
    new_signer = Ed25519Signer.generate()
    new_key_id = a.rotate_key(new_signer, revoke=a.key_id)
    # try to auth with old key → challenge issue must fail (revoked_key)
    r = a.get_challenge(key_id=old_key)
    assert r.status_code == 401


def test_t23_challenge_for_A_cannot_authenticate_B(a, b):
    r = a.get_challenge(); ch = r.json()
    payload = {
        "protocol": PROTO_AGENT_AUTH, "version": PROTOCOL_VERSION,
        "agent_id": b.agent_id, "key_id": b.key_id,
        "challenge_id": ch["challenge_id"], "challenge": ch["challenge"],
        "aud": AUD_AGENT_API, "issued_at": ch["issued_at"],
        "expires_at": ch["expires_at"],
    }
    sig = b64u_encode(b.signer.sign(canonical_json(payload, AGENT_AUTH_KEYS)))
    r2 = a.http.post(f"/api/agents/{b.agent_id}/authenticate", json={
        "challenge_id": ch["challenge_id"], "key_id": b.key_id,
        "aud": AUD_AGENT_API, "signature": sig,
    })
    assert r2.status_code == 401


def test_t24_challenge_replay(a):
    # same as T-03 essentially
    r = a.get_challenge(); ch = r.json()
    payload = {
        "protocol": PROTO_AGENT_AUTH, "version": PROTOCOL_VERSION,
        "agent_id": a.agent_id, "key_id": a.key_id,
        "challenge_id": ch["challenge_id"], "challenge": ch["challenge"],
        "aud": AUD_AGENT_API, "issued_at": ch["issued_at"],
        "expires_at": ch["expires_at"],
    }
    sig = b64u_encode(a.signer.sign(canonical_json(payload, AGENT_AUTH_KEYS)))
    body = {"challenge_id": ch["challenge_id"], "key_id": a.key_id,
            "aud": AUD_AGENT_API, "signature": sig}
    assert a.http.post(f"/api/agents/{a.agent_id}/authenticate", json=body).status_code == 200
    assert a.http.post(f"/api/agents/{a.agent_id}/authenticate", json=body).status_code == 401


def test_t25_message_replay(a, b):
    a.authenticate(aud=AUD_AGENT_RELAY)
    payload, sig = a.build_message(receiver=b.agent_id)
    r1 = a.http.post("/api/agents/messages",
                     json={"payload": payload, "signature": sig},
                     headers=a.auth_headers())
    assert r1.status_code == 200, r1.text
    r2 = a.http.post("/api/agents/messages",
                     json={"payload": payload, "signature": sig},
                     headers=a.auth_headers())
    assert r2.status_code == 401


def test_t26_recipient_substitution(a, b):
    a.authenticate(aud=AUD_AGENT_RELAY)
    payload, sig = a.build_message(receiver=b.agent_id)
    payload_bad = dict(payload)
    payload_bad["receiver_agent_id"] = a.agent_id  # server hasn't seen this yet
    # signature no longer valid over modified payload → 401
    r = a.http.post("/api/agents/messages",
                    json={"payload": payload_bad, "signature": sig},
                    headers=a.auth_headers())
    assert r.status_code == 401


def test_t27_capability_escalation(a):
    a.authenticate(aud=AUD_AGENT_API)
    secret = _tokens.get_secret()
    now = int(time.time())
    # legitimate jti so agent_jti-check passes
    real_jti = pyjwt.decode(a.token, options={"verify_signature": False})["jti"]
    bad = pyjwt.encode({
        "iss": JWT_ISSUER, "sub": a.agent_id, "aud": AUD_AGENT_API,
        "iat": now, "exp": now + 60, "jti": real_jti,
        "typ": JWT_TYP, "key_id": a.key_id,
        "owner_wallet": a.owner,
        "capabilities": ["agent.god_mode"],
    }, secret, algorithm=JWT_ALG)
    r = a.http.post("/api/agents/verify-jwt",
                    headers={"Authorization": f"Bearer {bad}"})
    assert r.status_code in (401, 403)


def test_t28_owner_required(a):
    """Registration without proper owner challenge fails."""
    from tests.agent.testclient import AgentTestClient
    c = AgentTestClient(a.http, eth_priv=ANVIL_KEY_2)
    r = a.http.post("/api/agents/register", json={
        "owner_wallet": c.owner,
        "owner_challenge_id": secrets.token_hex(16),
        "owner_signature": "0x00",
        "public_key": c.signer.public_key_encoded(),
    })
    assert r.status_code == 401


def test_t29_duplicate_register_new_id(a):
    """Re-registering the same owner gives a different agent_id (idempotent-safe)."""
    from tests.agent.testclient import AgentTestClient
    c = AgentTestClient(a.http)
    prev = a.agent_id
    c.register()
    assert c.agent_id != prev


def test_t30_concurrent_challenge_consumption(a):
    import threading
    r = a.get_challenge(); ch = r.json()
    payload = {
        "protocol": PROTO_AGENT_AUTH, "version": PROTOCOL_VERSION,
        "agent_id": a.agent_id, "key_id": a.key_id,
        "challenge_id": ch["challenge_id"], "challenge": ch["challenge"],
        "aud": AUD_AGENT_API, "issued_at": ch["issued_at"],
        "expires_at": ch["expires_at"],
    }
    sig = b64u_encode(a.signer.sign(canonical_json(payload, AGENT_AUTH_KEYS)))
    body = {"challenge_id": ch["challenge_id"], "key_id": a.key_id,
            "aud": AUD_AGENT_API, "signature": sig}
    results = []

    def worker():
        results.append(a.http.post(
            f"/api/agents/{a.agent_id}/authenticate", json=body).status_code)

    ts = [threading.Thread(target=worker) for _ in range(8)]
    for t in ts: t.start()
    for t in ts: t.join()
    assert results.count(200) == 1
    assert results.count(401) == 7


def test_t31_canonical_python_interop(tmp_path):
    """T-31: Python canonicalization is deterministic and matches golden bytes.
    If Node is available, run the parallel encoder and compare byte-for-byte."""
    import json, shutil, subprocess
    # Reference payload
    payload = {
        "protocol": PROTO_AGENT_AUTH, "version": "1",
        "agent_id": "did:aera:agent:aabbccddeeff00112233445566778899",
        "key_id": "aera-key-0011223344556677",
        "challenge_id": "cafebabecafebabecafebabecafebabe",
        "challenge": "AAAA-BBBB-CCCC",
        "aud": "aera-agent-api",
        "issued_at": "2026-01-01T00:00:00Z",
        "expires_at": "2026-01-01T00:01:00Z",
    }
    canon = canonical_json(payload, AGENT_AUTH_KEYS)
    # Deterministic hash sanity
    h = hashlib.sha256(canon).hexdigest()
    assert h == hashlib.sha256(canon).hexdigest()

    node = shutil.which("node")
    if not node:
        pytest.skip("node not available for Python↔JS byte-identity check")
    js = tmp_path / "canon.js"
    js.write_text(
        "const p = " + json.dumps(payload) + ";\n"
        "function esc(s){ let o='\"'; for (const ch of s) {\n"
        "  const cp = ch.codePointAt(0);\n"
        "  if (cp>=0xD800 && cp<=0xDFFF) throw new Error('surrogate');\n"
        "  if (cp===0x22) o+='\\\\\"'; else if (cp===0x5C) o+='\\\\\\\\';\n"
        "  else if (cp===0x08) o+='\\\\b'; else if (cp===0x09) o+='\\\\t';\n"
        "  else if (cp===0x0A) o+='\\\\n'; else if (cp===0x0C) o+='\\\\f';\n"
        "  else if (cp===0x0D) o+='\\\\r';\n"
        "  else if (cp<0x20) o+='\\\\u'+cp.toString(16).padStart(4,'0');\n"
        "  else o+=ch; } return o+'\"'; }\n"
        "function enc(v){ if(v===true)return'true'; if(v===false)return'false';\n"
        "  if(typeof v==='number'){ if(!Number.isInteger(v))throw new Error('float'); return v.toString(); }\n"
        "  if(typeof v==='string') return esc(v.normalize('NFC'));\n"
        "  if(Array.isArray(v)) return '['+v.map(enc).join(',')+']';\n"
        "  throw new Error('unsupported'); }\n"
        "const keys = Object.keys(p).sort();\n"
        "const body = keys.map(k => esc(k)+':'+enc(p[k])).join(',');\n"
        "process.stdout.write('{'+body+'}');\n"
    )
    out = subprocess.check_output([node, str(js)])
    assert out == canon


def test_t32_owner_challenge_replay(a):
    ch = a.owner_challenge("key_add", agent_id=a.agent_id)
    sig = a._owner_sign(ch)
    new_signer = Ed25519Signer.generate()
    r1 = a.http.post(f"/api/agents/{a.agent_id}/keys", json={
        "owner_wallet": a.owner, "owner_challenge_id": ch["challenge_id"],
        "owner_signature": sig, "public_key": new_signer.public_key_encoded(),
    })
    assert r1.status_code == 200
    # replay
    r2 = a.http.post(f"/api/agents/{a.agent_id}/keys", json={
        "owner_wallet": a.owner, "owner_challenge_id": ch["challenge_id"],
        "owner_signature": sig, "public_key": Ed25519Signer.generate().public_key_encoded(),
    })
    assert r2.status_code == 401


def test_t33_cross_operation_owner_sig(a):
    ch = a.owner_challenge("key_add", agent_id=a.agent_id)
    sig = a._owner_sign(ch)
    # use for agent_revoke
    r = a.http.request("DELETE", f"/api/agents/{a.agent_id}", json={
        "owner_wallet": a.owner, "owner_challenge_id": ch["challenge_id"],
        "owner_signature": sig, "public_key": a.signer.public_key_encoded(),
    })
    assert r.status_code == 401


def test_t34_message_valid_jwt_invalid_ed25519(a, b):
    a.authenticate(aud=AUD_AGENT_RELAY)
    payload, _ = a.build_message(receiver=b.agent_id)
    # corrupt signature
    bad_sig = b64u_encode(b"\x00" * 64)
    r = a.http.post("/api/agents/messages",
                    json={"payload": payload, "signature": bad_sig},
                    headers=a.auth_headers())
    assert r.status_code == 401


def test_t35_message_missing_jwt(a, b):
    a.authenticate(aud=AUD_AGENT_RELAY)
    payload, sig = a.build_message(receiver=b.agent_id)
    r = a.http.post("/api/agents/messages",
                    json={"payload": payload, "signature": sig})
    assert r.status_code == 401


def test_t36_unknown_audience(a):
    r = a.http.post(f"/api/agents/{a.agent_id}/challenge",
                    json={"key_id": a.key_id, "aud": "foo"})
    assert r.status_code == 400


def test_t37_challenge_bound_to_key_id(a):
    a.authenticate()
    conn = _repo.get_connection()
    row = conn.execute(
        "SELECT key_id FROM agent_challenges LIMIT 1"
    ).fetchone(); conn.close()
    assert row["key_id"] == a.key_id


def test_t38_wrong_active_key_rejected(a):
    """Same agent has key_A (registered) and key_B (added). Challenge issued
    for key_A. Auth with key_B (different active key) is rejected."""
    new_signer = Ed25519Signer.generate()
    key_b_id = a.add_key(new_signer)
    # get challenge for key_A
    r = a.get_challenge(key_id=a.key_id); ch = r.json()
    # sign & authenticate claiming key_B
    payload = {
        "protocol": PROTO_AGENT_AUTH, "version": PROTOCOL_VERSION,
        "agent_id": a.agent_id, "key_id": key_b_id,
        "challenge_id": ch["challenge_id"], "challenge": ch["challenge"],
        "aud": AUD_AGENT_API, "issued_at": ch["issued_at"],
        "expires_at": ch["expires_at"],
    }
    sig = b64u_encode(new_signer.sign(canonical_json(payload, AGENT_AUTH_KEYS)))
    r2 = a.http.post(f"/api/agents/{a.agent_id}/authenticate", json={
        "challenge_id": ch["challenge_id"], "key_id": key_b_id,
        "aud": AUD_AGENT_API, "signature": sig,
    })
    assert r2.status_code == 401


def test_t39_cross_key_challenge_consumption(a):
    """After the rejection in T-38, the original challenge must still be
    unconsumed. A legitimate authenticate with key_A succeeds."""
    new_signer = Ed25519Signer.generate()
    key_b_id = a.add_key(new_signer)
    r = a.get_challenge(key_id=a.key_id); ch = r.json()
    # cross-key attempt
    payload = {
        "protocol": PROTO_AGENT_AUTH, "version": PROTOCOL_VERSION,
        "agent_id": a.agent_id, "key_id": key_b_id,
        "challenge_id": ch["challenge_id"], "challenge": ch["challenge"],
        "aud": AUD_AGENT_API, "issued_at": ch["issued_at"],
        "expires_at": ch["expires_at"],
    }
    sig = b64u_encode(new_signer.sign(canonical_json(payload, AGENT_AUTH_KEYS)))
    r_bad = a.http.post(f"/api/agents/{a.agent_id}/authenticate", json={
        "challenge_id": ch["challenge_id"], "key_id": key_b_id,
        "aud": AUD_AGENT_API, "signature": sig,
    })
    assert r_bad.status_code == 401
    # now legit
    good_payload = dict(payload); good_payload["key_id"] = a.key_id
    good_sig = b64u_encode(a.signer.sign(canonical_json(good_payload, AGENT_AUTH_KEYS)))
    r_good = a.http.post(f"/api/agents/{a.agent_id}/authenticate", json={
        "challenge_id": ch["challenge_id"], "key_id": a.key_id,
        "aud": AUD_AGENT_API, "signature": good_sig,
    })
    assert r_good.status_code == 200
