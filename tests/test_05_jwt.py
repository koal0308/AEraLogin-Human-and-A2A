"""Phase 8 + 9 + 10 + 11 – JWT tests, cross-audience, replay, revocation."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import jwt
import pytest

from _utils import register_token_lifecycle


def _decode_via_server_v1(client, token: str):
    return client.post("/api/v1/verify",
                       headers={"Authorization": f"Bearer {token}"}).json()


@pytest.fixture()
def registered_client(server_module):
    """A real, active OAuth client row - N3 requires `aud` to be registered."""
    import hashlib, json, secrets
    conn = server_module.get_db_connection()
    cur = conn.cursor()
    cid = "client_A_" + secrets.token_hex(4)
    cur.execute("""
        INSERT INTO oauth_clients
            (client_id, client_secret_hash, client_name, redirect_uris,
             allowed_origins, min_score, require_nft, created_at, is_active,
             owner_address, website_url, description)
        VALUES (?, ?, ?, ?, ?, 0, 0, ?, 1, NULL, NULL, NULL)
    """, (cid, hashlib.sha256(b"x").hexdigest(), "JWT Test App",
          json.dumps(["http://testserver/callback"]),
          json.dumps(["http://testserver"]),
          datetime.now(timezone.utc).isoformat()))
    conn.commit()
    conn.close()
    return cid


def _mint(server_module, *, sub="0x" + "aa" * 20, aud="client_A",
          score=42, has_nft=True, exp_delta_s=3600, extra=None,
          secret=None, algo="HS256", register_lifecycle=True):
    now = datetime.now(timezone.utc)
    payload = {
        "iss": "aeralogin.com",
        "sub": sub,
        "aud": aud,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=exp_delta_s)).timestamp()),
        "jti": "test-jti-" + str(int(time.time() * 1000)),
        "score": score,
        "has_nft": has_nft,
        "chain_id": 8453,
    }
    if extra:
        payload.update(extra)
    key = secret if secret is not None else server_module.OAUTH_JWT_SECRET
    token = jwt.encode(payload, key, algorithm=algo)
    if register_lifecycle:
        # S-02: production tokens always have a lifecycle row. Tests that
        # forge tokens must create it too, otherwise every assertion below
        # would collapse into "unknown jti" and stop testing what it claims.
        register_token_lifecycle(server_module, token)
    return token, payload


# ---------------------------------------------------------------------------
# Phase 8 – JWT test matrix
# ---------------------------------------------------------------------------
def test_valid_token_accepted(server_module, client, registered_client):
    tok, _ = _mint(server_module, aud=registered_client)
    r = _decode_via_server_v1(client, tok)
    assert r.get("valid") is True, r


def test_expired_token_rejected(server_module, client):
    tok, _ = _mint(server_module, exp_delta_s=-60)
    r = _decode_via_server_v1(client, tok)
    assert r.get("valid") is False
    assert "expired" in r.get("error", "").lower()


def test_manipulated_signature_rejected(server_module, client):
    tok, _ = _mint(server_module)
    tampered = tok[:-4] + ("AAAA" if tok[-4:] != "AAAA" else "BBBB")
    r = _decode_via_server_v1(client, tampered)
    assert r.get("valid") is False


def test_wrong_secret_rejected(server_module, client):
    tok, _ = _mint(server_module, secret="totally-different-secret")
    r = _decode_via_server_v1(client, tok)
    assert r.get("valid") is False


def test_missing_exp_still_decoded_or_rejected(server_module, client):
    now = datetime.now(timezone.utc)
    payload = {"iss": "aeralogin.com", "sub": "0x" + "aa" * 20,
               "aud": "client_A", "iat": int(now.timestamp()),
               "jti": "no-exp", "score": 1, "has_nft": False,
               "chain_id": 8453}
    tok = jwt.encode(payload, server_module.OAUTH_JWT_SECRET, algorithm="HS256")
    r = _decode_via_server_v1(client, tok)
    # PyJWT default requires exp when present; when absent it usually accepts.
    # We record what actually happens.
    test_missing_exp_still_decoded_or_rejected.result = r  # type: ignore[attr-defined]


def test_missing_sub_still_processed(server_module, client):
    now = datetime.now(timezone.utc)
    payload = {"iss": "aeralogin.com", "aud": "client_A",
               "iat": int(now.timestamp()),
               "exp": int((now + timedelta(hours=1)).timestamp()),
               "jti": "no-sub", "score": 1, "has_nft": False,
               "chain_id": 8453}
    tok = jwt.encode(payload, server_module.OAUTH_JWT_SECRET, algorithm="HS256")
    r = _decode_via_server_v1(client, tok)
    # Current code does payload.get("sub", "") ⇒ empty wallet field.
    test_missing_sub_still_processed.result = r  # type: ignore[attr-defined]


def test_manipulated_jti_does_not_matter(server_module, client, registered_client):
    tok, _ = _mint(server_module, aud=registered_client,
                   extra={"jti": "attacker-controlled"})
    r = _decode_via_server_v1(client, tok)
    assert r.get("valid") is True  # jti is not consulted by the server


def test_alg_none_rejected(server_module, client):
    now = datetime.now(timezone.utc)
    payload = {"iss": "aeralogin.com", "sub": "0x" + "aa" * 20,
               "aud": "client_A", "iat": int(now.timestamp()),
               "exp": int((now + timedelta(hours=1)).timestamp()),
               "jti": "alg-none"}
    tok = jwt.encode(payload, key="", algorithm="none")
    r = _decode_via_server_v1(client, tok)
    assert r.get("valid") is False, "alg=none must not be accepted"


# ---------------------------------------------------------------------------
# Phase 9 – Cross-audience
# ---------------------------------------------------------------------------
def test_cross_audience_token_rejected(server_module, client, registered_client):
    """Audit finding S-01 - NOW CLOSED (N3).

    Historically /api/v1/verify ran with `verify_aud: False`, so a token
    minted for client A was accepted no matter which client presented it.
    This test used to assert that vulnerable behaviour; it now asserts the
    hardened contract instead:

      * a caller that identifies itself as the token's own audience  -> OK
      * a caller that identifies itself as a DIFFERENT client        -> reject
      * an audience that is not a registered active client           -> reject
    """
    tok, _ = _mint(server_module, aud=registered_client)

    same = client.post("/api/v1/verify",
                       headers={"Authorization": f"Bearer {tok}",
                                "X-AEra-Client-Id": registered_client}).json()
    assert same.get("valid") is True, same
    assert same.get("client_id") == registered_client

    other = client.post("/api/v1/verify",
                        headers={"Authorization": f"Bearer {tok}",
                                 "X-AEra-Client-Id": "client_B"}).json()
    assert other.get("valid") is False, "cross-audience confusion must be rejected"

    unregistered, _ = _mint(server_module, aud="client_A")
    r = _decode_via_server_v1(client, unregistered)
    assert r.get("valid") is False, "unregistered audience must be rejected"


def test_forged_issuer_rejected(server_module, client, registered_client):
    """Audit finding S-08 - NOW CLOSED (N3): issuer is validated strictly."""
    tok, _ = _mint(server_module, aud=registered_client,
                   extra={"iss": "not-aeralogin.com"})
    r = _decode_via_server_v1(client, tok)
    assert r.get("valid") is False, "forged issuer must be rejected"

    good, _ = _mint(server_module, aud=registered_client)
    assert _decode_via_server_v1(client, good).get("valid") is True


# ---------------------------------------------------------------------------
# Phase 10 – JWT replay
# ---------------------------------------------------------------------------
def test_jwt_replay_second_use(server_module, client, registered_client):
    """Audit finding S-02: no revocation, no jti tracking (still open)."""
    tok, _ = _mint(server_module, aud=registered_client)
    r1 = _decode_via_server_v1(client, tok)
    r2 = _decode_via_server_v1(client, tok)
    replay_ok = r1.get("valid") and r2.get("valid")
    test_jwt_replay_second_use.replay_accepted = bool(replay_ok)  # type: ignore[attr-defined]
    assert replay_ok


# ---------------------------------------------------------------------------
# Phase 11 – Revocation probe
# ---------------------------------------------------------------------------
def test_no_revocation_endpoint_exists(server_module):
    """There is no /oauth/revoke or /oauth/logout endpoint in production.

    Note: `/api/agents/tokens/revoke` belongs to the additive Agent Identity
    Layer (Spec v1.2 §9.4) and is intentionally excluded from this S-02
    baseline probe, which targets the *OAuth* subsystem.

    Likewise `/api/dashboard/a2a-credentials/{cred_id}/revoke`, which revokes
    an EXTERNAL A2A peer credential. It is a different credential type, held by
    a different principal, with a different audience (`aera-a2a-gateway`), and
    it cannot revoke an OAuth token. Its existence therefore says nothing about
    the OAuth finding this probe records, which remains open and unchanged.
    """
    paths = {getattr(r, "path", "") for r in server_module.app.routes}
    oauth_paths = {
        p for p in paths
        if not p.startswith("/api/agents")
        and not p.startswith("/api/dashboard/a2a-credentials")
    }
    has_revoke = any("revoke" in p or "logout" in p for p in oauth_paths)
    test_no_revocation_endpoint_exists.has_revoke = has_revoke  # type: ignore[attr-defined]
    assert not has_revoke, f"unexpected revoke endpoint(s): {oauth_paths}"


def test_oauth_jti_is_persisted(server_module):
    """Audit finding S-02 - NOW CLOSED.

    This test previously asserted that no OAuth jti store existed, which was
    the whole problem: a leaked token stayed usable until exp with no way to
    revoke it. It now asserts the opposite - the lifecycle table exists and
    is separate from the Agent Layer's own `agent_jti` register.
    """
    conn = server_module.get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cur.fetchall()]
    conn.close()

    assert "oauth_token_jti" in tables, "S-02 lifecycle store is missing"
    assert "agent_jti" in tables, "Agent Layer register must stay untouched"
    assert "oauth_token_jti" != "agent_jti"
