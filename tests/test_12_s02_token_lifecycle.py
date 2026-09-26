"""
S-02 - OAuth access-token lifecycle / revocation.

Model under test
----------------
`oauth_token_jti` is the authoritative server-side lifecycle record for every
issued OAuth access token:

    jti (PK) | sub | client_id | issued_at | expires_at | status
             | revoked_at | revocation_reason

It is NOT an anti-replay nonce store: a valid token stays reusable until it
expires or is explicitly revoked (test C).

The Agent Layer's own `agent_jti` register is a different table and is never
touched here.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import time
from datetime import datetime, timedelta, timezone

import jwt
import pytest

from _utils import register_token_lifecycle


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _client(server_module, active=True):
    conn = server_module.get_db_connection()
    cur = conn.cursor()
    cid = "s02_client_" + secrets.token_hex(4)
    csec = "s02_secret_" + secrets.token_hex(8)
    cur.execute(
        """INSERT INTO oauth_clients
           (client_id, client_secret_hash, client_name, redirect_uris,
            allowed_origins, min_score, require_nft, created_at, is_active,
            owner_address, website_url, description)
           VALUES (?, ?, ?, ?, ?, 0, 0, ?, ?, NULL, NULL, NULL)""",
        (cid, hashlib.sha256(csec.encode()).hexdigest(), "S02 App",
         json.dumps(["http://testserver/callback"]),
         json.dumps(["http://testserver"]),
         datetime.now(timezone.utc).isoformat(), 1 if active else 0))
    conn.commit()
    conn.close()
    return cid, csec


def _row(server_module, jti):
    conn = server_module.get_db_connection()
    try:
        return conn.execute(
            "SELECT * FROM oauth_token_jti WHERE jti = ?", (jti,)).fetchone()
    finally:
        conn.close()


def _jti_of(token):
    return jwt.decode(token, options={"verify_signature": False})["jti"]


def _accepts(server_module, token, expected_client_id=None):
    try:
        server_module.verify_oauth_access_token(
            token, expected_client_id=expected_client_id)
        return True
    except jwt.InvalidTokenError:
        return False


# ==========================================================================
# A - issuance creates a lifecycle row
# ==========================================================================
def test_a_issued_token_has_lifecycle_row(server_module):
    cid, _ = _client(server_module)
    addr = "0x" + "a1" * 20
    token = server_module.issue_oauth_access_token(cid, addr, 50, True)
    row = _row(server_module, _jti_of(token))

    assert row is not None, "no lifecycle row was created"
    assert row["status"] == "active"
    assert row["sub"] == addr.lower()
    assert row["client_id"] == cid
    assert row["revoked_at"] is None
    assert row["revocation_reason"] is None
    assert datetime.fromisoformat(row["expires_at"]) > datetime.now(timezone.utc)


def test_a2_issued_via_http_creates_row(client, server_module):
    """The real /oauth/token endpoint - not just the helper - persists."""
    from test_11_n10_no_token_output import _issue_code, _register_client

    cid, csec = _register_client(server_module)
    code, addr = _issue_code(client, server_module, cid)
    token = client.post("/oauth/token", json={
        "grant_type": "authorization_code", "code": code,
        "redirect_uri": "http://testserver/callback",
        "client_id": cid, "client_secret": csec,
    }).json()["access_token"]

    row = _row(server_module, _jti_of(token))
    assert row is not None and row["status"] == "active"
    assert row["client_id"] == cid
    assert row["sub"] == addr.lower()


# ==========================================================================
# B / C - acceptance and reusability
# ==========================================================================
def test_b_valid_token_accepted(server_module):
    cid, _ = _client(server_module)
    token = server_module.issue_oauth_access_token(cid, "0x" + "b1" * 20, 10, False)
    assert _accepts(server_module, token) is True
    assert _accepts(server_module, token, expected_client_id=cid) is True


def test_c_token_reusable_before_expiry(server_module):
    """S-02 must NOT turn jti into a single-use nonce."""
    cid, _ = _client(server_module)
    token = server_module.issue_oauth_access_token(cid, "0x" + "c1" * 20, 10, False)
    for _ in range(5):
        assert _accepts(server_module, token) is True


# ==========================================================================
# D-G - rejection matrix
# ==========================================================================
def test_d_unknown_jti_rejected(server_module):
    cid, _ = _client(server_module)
    token = server_module.issue_oauth_access_token(cid, "0x" + "d1" * 20, 10, False)
    conn = server_module.get_db_connection()
    conn.execute("DELETE FROM oauth_token_jti WHERE jti = ?", (_jti_of(token),))
    conn.commit()
    conn.close()
    assert _accepts(server_module, token) is False


def test_e_revoked_jti_rejected(server_module):
    cid, _ = _client(server_module)
    token = server_module.issue_oauth_access_token(cid, "0x" + "e1" * 20, 10, False)
    assert _accepts(server_module, token) is True

    assert server_module.revoke_oauth_token(_jti_of(token), "test") is True
    assert _accepts(server_module, token) is False

    row = _row(server_module, _jti_of(token))
    assert row["status"] == "revoked"
    assert row["revoked_at"] is not None
    assert row["revocation_reason"] == "test"


def test_f_expired_token_rejected(server_module):
    cid, _ = _client(server_module)
    addr = "0x" + "f1" * 20
    token = server_module.generate_oauth_session_token(cid, addr, 10, False)
    register_token_lifecycle(server_module, token)

    past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    conn = server_module.get_db_connection()
    conn.execute("UPDATE oauth_token_jti SET expires_at = ? WHERE jti = ?",
                 (past, _jti_of(token)))
    conn.commit()
    conn.close()
    assert _accepts(server_module, token) is False


def test_g_altered_jti_rejected(server_module):
    """Re-signing with a different jti yields an unknown lifecycle record."""
    cid, _ = _client(server_module)
    token = server_module.issue_oauth_access_token(cid, "0x" + "91" * 20, 10, False)
    payload = jwt.decode(token, server_module.OAUTH_JWT_SECRET,
                         algorithms=["HS256"], audience=cid)
    payload["jti"] = secrets.token_hex(16)
    forged = jwt.encode(payload, server_module.OAUTH_JWT_SECRET, algorithm="HS256")
    assert _accepts(server_module, forged) is False


# ==========================================================================
# H-J - stored record is authoritative
# ==========================================================================
def test_h_altered_sub_rejected(server_module):
    cid, _ = _client(server_module)
    token = server_module.issue_oauth_access_token(cid, "0x" + "11" * 20, 10, False)
    payload = jwt.decode(token, server_module.OAUTH_JWT_SECRET,
                         algorithms=["HS256"], audience=cid)
    payload["sub"] = "0x" + "22" * 20
    forged = jwt.encode(payload, server_module.OAUTH_JWT_SECRET, algorithm="HS256")
    assert _accepts(server_module, forged) is False


def test_i_altered_aud_rejected(server_module):
    cid_a, _ = _client(server_module)
    cid_b, _ = _client(server_module)
    token = server_module.issue_oauth_access_token(cid_a, "0x" + "33" * 20, 10, False)
    payload = jwt.decode(token, server_module.OAUTH_JWT_SECRET,
                         algorithms=["HS256"], audience=cid_a)
    payload["aud"] = cid_b
    forged = jwt.encode(payload, server_module.OAUTH_JWT_SECRET, algorithm="HS256")
    assert _accepts(server_module, forged) is False
    assert _accepts(server_module, forged, expected_client_id=cid_b) is False


def test_j_wallet_identity_must_match_record(server_module):
    """Tampering with the stored record must not let a token drift identity."""
    cid, _ = _client(server_module)
    addr = "0x" + "44" * 20
    token = server_module.issue_oauth_access_token(cid, addr, 10, False)

    conn = server_module.get_db_connection()
    conn.execute("UPDATE oauth_token_jti SET sub = ? WHERE jti = ?",
                 ("0x" + "55" * 20, _jti_of(token)))
    conn.commit()
    conn.close()
    assert _accepts(server_module, token) is False


# ==========================================================================
# K - fail closed on persistence failure
# ==========================================================================
def test_k_persistence_failure_returns_no_token(server_module, monkeypatch):
    cid, _ = _client(server_module)

    class _BrokenCursor:
        def execute(self, *a, **kw):
            raise sqlite3.OperationalError("disk I/O error (simulated)")

    with pytest.raises(server_module.OAuthTokenLifecycleError):
        server_module.issue_oauth_access_token(
            cid, "0x" + "66" * 20, 10, False, cursor=_BrokenCursor())


def test_k2_http_issuance_fails_closed(client, server_module, monkeypatch):
    """/oauth/token must not return a token if the lifecycle row fails."""
    from test_11_n10_no_token_output import _issue_code, _register_client

    cid, csec = _register_client(server_module)
    code, _ = _issue_code(client, server_module, cid)

    def _boom(*a, **kw):
        raise server_module.OAuthTokenLifecycleError("simulated")

    monkeypatch.setattr(server_module, "issue_oauth_access_token", _boom)
    body = client.post("/oauth/token", json={
        "grant_type": "authorization_code", "code": code,
        "redirect_uri": "http://testserver/callback",
        "client_id": cid, "client_secret": csec,
    }).json()

    assert "access_token" not in body
    assert body.get("error") == "server_error"


# ==========================================================================
# L - idempotent revocation
# ==========================================================================
def test_l_double_revocation_is_idempotent(server_module):
    cid, _ = _client(server_module)
    token = server_module.issue_oauth_access_token(cid, "0x" + "77" * 20, 10, False)
    jti = _jti_of(token)

    assert server_module.revoke_oauth_token(jti, "first") is True
    first = _row(server_module, jti)["revoked_at"]

    assert server_module.revoke_oauth_token(jti, "second") is True
    row = _row(server_module, jti)
    assert row["status"] == "revoked"
    assert row["revoked_at"] == first, "original revocation metadata overwritten"
    assert row["revocation_reason"] == "first"
    assert _accepts(server_module, token) is False


def test_l2_revoking_unknown_jti_is_safe(server_module):
    assert server_module.revoke_oauth_token("no-such-jti", "x") is False


def test_l3_client_cannot_revoke_another_clients_token(server_module):
    cid_a, _ = _client(server_module)
    cid_b, _ = _client(server_module)
    token = server_module.issue_oauth_access_token(cid_a, "0x" + "88" * 20, 10, False)
    jti = _jti_of(token)

    assert server_module.revoke_oauth_token(jti, "attack", client_id=cid_b) is False
    assert _accepts(server_module, token) is True, "foreign revocation succeeded"

    assert server_module.revoke_oauth_token(jti, "owner", client_id=cid_a) is True
    assert _accepts(server_module, token) is False


# ==========================================================================
# M / N - cascades and isolation
# ==========================================================================
def test_m_revoked_client_tokens_rejected(server_module):
    cid, _ = _client(server_module)
    token = server_module.issue_oauth_access_token(cid, "0x" + "99" * 20, 10, False)
    assert _accepts(server_module, token) is True

    n = server_module.revoke_oauth_tokens_for_client(cid, "client_disabled")
    assert n == 1
    assert _accepts(server_module, token) is False
    assert _row(server_module, _jti_of(token))["revocation_reason"] == "client_disabled"


def test_m2_deactivated_client_tokens_rejected(server_module):
    """Even without an explicit cascade, a disabled client cannot authenticate."""
    cid, _ = _client(server_module)
    token = server_module.issue_oauth_access_token(cid, "0x" + "aa" * 20, 10, False)
    conn = server_module.get_db_connection()
    conn.execute("UPDATE oauth_clients SET is_active = 0 WHERE client_id = ?", (cid,))
    conn.commit()
    conn.close()
    assert _accepts(server_module, token) is False
    assert _accepts(server_module, token, expected_client_id=cid) is False


def test_n_independent_client_token_stays_valid(server_module):
    cid_a, _ = _client(server_module)
    cid_b, _ = _client(server_module)
    tok_a = server_module.issue_oauth_access_token(cid_a, "0x" + "bb" * 20, 10, False)
    tok_b = server_module.issue_oauth_access_token(cid_b, "0x" + "cc" * 20, 10, False)

    server_module.revoke_oauth_tokens_for_client(cid_a, "client_disabled")
    assert _accepts(server_module, tok_a) is False
    assert _accepts(server_module, tok_b) is True, "collateral revocation"


def test_n2_subject_revocation_scoped(server_module):
    cid, _ = _client(server_module)
    addr = "0x" + "dd" * 20
    mine = server_module.issue_oauth_access_token(cid, addr, 10, False)
    other = server_module.issue_oauth_access_token(cid, "0x" + "ee" * 20, 10, False)

    assert server_module.revoke_oauth_tokens_for_subject(addr, "user_revoked") == 1
    assert _accepts(server_module, mine) is False
    assert _accepts(server_module, other) is True


def test_n3_agent_jti_table_untouched(server_module):
    """Revoking OAuth tokens must never touch the Agent Layer register."""
    conn = server_module.get_db_connection()
    before = conn.execute("SELECT COUNT(*) FROM agent_jti").fetchone()[0]
    conn.close()

    cid, _ = _client(server_module)
    token = server_module.issue_oauth_access_token(cid, "0x" + "ff" * 20, 10, False)
    server_module.revoke_oauth_token(_jti_of(token), "x")
    server_module.revoke_oauth_tokens_for_client(cid, "y")

    conn = server_module.get_db_connection()
    after = conn.execute("SELECT COUNT(*) FROM agent_jti").fetchone()[0]
    conn.close()
    assert before == after


# ==========================================================================
# O-R - N3 protections and crypto hygiene remain
# ==========================================================================
def test_o_n3_issuer_audience_still_enforced(server_module):
    cid, _ = _client(server_module)
    token = server_module.issue_oauth_access_token(cid, "0x" + "12" * 20, 10, False)
    payload = jwt.decode(token, server_module.OAUTH_JWT_SECRET,
                         algorithms=["HS256"], audience=cid)
    payload["iss"] = "evil.example"
    forged = jwt.encode(payload, server_module.OAUTH_JWT_SECRET, algorithm="HS256")
    assert _accepts(server_module, forged) is False


def test_p_alg_none_rejected(server_module):
    cid, _ = _client(server_module)
    token = server_module.issue_oauth_access_token(cid, "0x" + "13" * 20, 10, False)
    payload = jwt.decode(token, server_module.OAUTH_JWT_SECRET,
                         algorithms=["HS256"], audience=cid)
    assert _accepts(server_module, jwt.encode(payload, None, algorithm="none")) is False


def test_q_wrong_secret_rejected(server_module):
    cid, _ = _client(server_module)
    token = server_module.issue_oauth_access_token(cid, "0x" + "14" * 20, 10, False)
    payload = jwt.decode(token, server_module.OAUTH_JWT_SECRET,
                         algorithms=["HS256"], audience=cid)
    forged = jwt.encode(payload, "a-totally-different-secret-value-xxxx",
                        algorithm="HS256")
    assert _accepts(server_module, forged) is False


@pytest.mark.parametrize("bad", ["", "not-a-jwt", "a.b", "a.b.c", "x" * 50])
def test_r_malformed_jwt_rejected(server_module, bad):
    assert _accepts(server_module, bad) is False


# ==========================================================================
# concurrency
# ==========================================================================
def test_concurrent_issuance_unique_jti_one_row_each(server_module):
    import threading

    cid, _ = _client(server_module)
    tokens, errors = [], []
    lock = threading.Lock()

    def work(i):
        try:
            t = server_module.issue_oauth_access_token(
                cid, f"0x{i:040x}", 10, False)
            with lock:
                tokens.append(t)
        except Exception as exc:  # pragma: no cover
            with lock:
                errors.append(exc)

    threads = [threading.Thread(target=work, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"concurrent issuance failed: {errors[:3]}"
    jtis = [_jti_of(t) for t in tokens]
    assert len(jtis) == 20
    assert len(set(jtis)) == 20, "duplicate jti issued"

    conn = server_module.get_db_connection()
    try:
        for j in jtis:
            n = conn.execute(
                "SELECT COUNT(*) FROM oauth_token_jti WHERE jti = ?", (j,)
            ).fetchone()[0]
            assert n == 1, "expected exactly one lifecycle row per token"
    finally:
        conn.close()

    for t in tokens:
        assert _accepts(server_module, t) is True


def test_concurrent_revocation_no_resurrection(server_module):
    import threading

    cid, _ = _client(server_module)
    token = server_module.issue_oauth_access_token(cid, "0x" + "15" * 20, 10, False)
    jti = _jti_of(token)
    results = []
    lock = threading.Lock()

    def work(i):
        r = server_module.revoke_oauth_token(jti, f"reason-{i}")
        with lock:
            results.append(r)

    threads = [threading.Thread(target=work, args=(i,)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert all(results), "a concurrent revocation was lost"
    row = _row(server_module, jti)
    assert row["status"] == "revoked", "token was resurrected"
    assert _accepts(server_module, token) is False


def test_jti_primary_key_prevents_duplicates(server_module):
    cid, _ = _client(server_module)
    token = server_module.issue_oauth_access_token(cid, "0x" + "16" * 20, 10, False)
    conn = server_module.get_db_connection()
    try:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO oauth_token_jti "
                "(jti, sub, client_id, issued_at, expires_at, status) "
                "VALUES (?, 'x', 'y', 'z', 'w', 'active')", (_jti_of(token),))
            conn.commit()
    finally:
        conn.close()


# ==========================================================================
# migration safety
# ==========================================================================
def test_migration_is_idempotent(server_module):
    """init_db() must be safe to run repeatedly (restart-safe)."""
    conn = server_module.get_db_connection()
    before = conn.execute("SELECT COUNT(*) FROM oauth_token_jti").fetchone()[0]
    conn.close()

    server_module.init_db()

    conn = server_module.get_db_connection()
    after = conn.execute("SELECT COUNT(*) FROM oauth_token_jti").fetchone()[0]
    cols = [r[1] for r in conn.execute("PRAGMA table_info(oauth_token_jti)")]
    conn.close()

    assert after == before, "re-running the migration lost data"
    assert cols == ["jti", "sub", "client_id", "issued_at", "expires_at",
                    "status", "revoked_at", "revocation_reason"]


def test_legacy_oauth_tables_untouched(server_module):
    """The migration must be purely additive."""
    conn = server_module.get_db_connection()
    try:
        for table, expected in (
            ("oauth_sessions", {"id", "session_id", "client_id", "address",
                                "score", "has_nft", "created_at", "expires_at",
                                "is_active"}),
            ("oauth_codes", {"id", "code", "client_id", "address",
                             "redirect_uri", "state", "nonce", "created_at",
                             "expires_at", "used"}),
        ):
            cols = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
            assert expected.issubset(cols), f"{table} lost columns"
    finally:
        conn.close()
