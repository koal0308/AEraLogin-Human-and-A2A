"""
N3 — Legacy OAuth issuer + audience hardening.

Security model derived from the ACTUAL token producer
(`generate_oauth_session_token`, server.py):

    iss = "aeralogin.com"          (fixed, server-side constant)
    aud = <client_id>              (client-specific, string, never a list)

Verification rules under test:

  * signature: HS256 with OAUTH_JWT_SECRET only
  * iss: must equal the server-side expected issuer exactly
  * aud: must be a SINGLE STRING that is a registered, active client_id
  * aud: when the caller is authenticated (verify-nft) or opts in
         (X-AEra-Client-Id), aud must equal that client_id exactly
  * required claims: iss, sub, aud, iat, exp, jti
  * exp enforced, alg=none rejected

Nothing here mutates production state - the whole suite runs against the
ephemeral conftest DB.
"""
from __future__ import annotations

import json
import secrets
import time
from datetime import datetime, timedelta, timezone

import jwt
import pytest

from _utils import register_token_lifecycle


ISSUER = "aeralogin.com"


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _register_client(server_module, active=True):
    """Insert an oauth_clients row directly (test-only)."""
    import hashlib

    conn = server_module.get_db_connection()
    cur = conn.cursor()
    client_id = "n3_client_" + secrets.token_hex(4)
    client_secret = "n3_secret_" + secrets.token_hex(8)
    cur.execute(
        """
        INSERT INTO oauth_clients
            (client_id, client_secret_hash, client_name, redirect_uris,
             allowed_origins, min_score, require_nft, created_at, is_active,
             owner_address, website_url, description)
        VALUES (?, ?, ?, ?, ?, 0, 0, ?, ?, NULL, NULL, NULL)
        """,
        (
            client_id,
            hashlib.sha256(client_secret.encode()).hexdigest(),
            "N3 Test App " + client_id,
            json.dumps(["http://testserver/callback"]),
            json.dumps(["http://testserver"]),
            datetime.now(timezone.utc).isoformat(),
            1 if active else 0,
        ),
    )
    conn.commit()
    conn.close()
    return client_id, client_secret


def _mint(server_module, *, iss=ISSUER, aud="SET_ME", sub="0xabc",
          secret=None, drop=(), ttl=3600, alg="HS256", extra=None,
          register_lifecycle=True):
    """
    Build a token with surgical control over every claim.

    By default an S-02 lifecycle row is created, so each test still fails for
    the reason it is actually probing (bad issuer, bad audience, ...) rather
    than collapsing into a generic "unknown jti" rejection.
    """
    now = int(time.time())
    payload = {
        "iss": iss,
        "sub": sub.lower(),
        "aud": aud,
        "iat": now,
        "exp": now + ttl,
        "jti": secrets.token_hex(16),
        "score": 50,
        "has_nft": True,
        "chain_id": 8453,
    }
    for claim in drop:
        payload.pop(claim, None)
    if extra:
        payload.update(extra)
    key = secret if secret is not None else server_module.OAUTH_JWT_SECRET
    if alg == "none":
        return jwt.encode(payload, None, algorithm="none")
    token = jwt.encode(payload, key, algorithm=alg)
    if register_lifecycle and "jti" in payload and isinstance(aud, str):
        register_token_lifecycle(server_module, token)
    return token


def _verify(server_module, token, expected_client_id=None):
    """Call the hardened verifier, return (ok, error_type)."""
    try:
        server_module.verify_oauth_access_token(
            token, expected_client_id=expected_client_id
        )
        return True, None
    except jwt.InvalidTokenError as exc:
        return False, type(exc).__name__


# ==========================================================================
# PHASE 6 - producer / verifier consistency (regression guard)
# ==========================================================================
def test_producer_issuer_matches_verifier_expectation(server_module):
    """The issuer the system MINTS must equal the issuer it EXPECTS."""
    client_id, _ = _register_client(server_module)
    token = server_module.issue_oauth_access_token(client_id, "0xAbC", 50, True)
    payload = jwt.decode(
        token, server_module.OAUTH_JWT_SECRET,
        algorithms=["HS256"], options={"verify_aud": False},
    )
    assert payload["iss"] == server_module.OAUTH_EXPECTED_ISSUER


def test_producer_audience_matches_verifier_expectation(server_module):
    """The audience the system MINTS must be exactly the client_id."""
    client_id, _ = _register_client(server_module)
    token = server_module.issue_oauth_access_token(client_id, "0xAbC", 50, True)
    payload = jwt.decode(
        token, server_module.OAUTH_JWT_SECRET, audience=client_id,
        algorithms=["HS256"],
    )
    assert payload["aud"] == client_id
    assert isinstance(payload["aud"], str), "aud must never be a list"


def test_n_real_production_token_is_accepted(server_module):
    """N - a token from the real producer must pass the hardened verifier."""
    client_id, _ = _register_client(server_module)
    token = server_module.issue_oauth_access_token(client_id, "0xAbC", 50, True)
    assert _verify(server_module, token)[0] is True
    assert _verify(server_module, token, expected_client_id=client_id)[0] is True


# ==========================================================================
# PHASE 3 - claim validation matrix
# ==========================================================================
def test_a_correct_issuer_and_audience_accepted(server_module):
    client_id, _ = _register_client(server_module)
    ok, _ = _verify(server_module, _mint(server_module, aud=client_id),
                    expected_client_id=client_id)
    assert ok is True


def test_b_wrong_issuer_rejected(server_module):
    client_id, _ = _register_client(server_module)
    ok, err = _verify(server_module,
                      _mint(server_module, aud=client_id, iss="evil-issuer.example"),
                      expected_client_id=client_id)
    assert ok is False and err == "InvalidIssuerError"


def test_c_wrong_audience_rejected(server_module):
    client_a, _ = _register_client(server_module)
    client_b, _ = _register_client(server_module)
    ok, err = _verify(server_module, _mint(server_module, aud=client_b),
                      expected_client_id=client_a)
    assert ok is False and err == "InvalidAudienceError"


def test_d_missing_issuer_rejected(server_module):
    client_id, _ = _register_client(server_module)
    ok, err = _verify(server_module,
                      _mint(server_module, aud=client_id, drop=("iss",)),
                      expected_client_id=client_id)
    assert ok is False and err == "MissingRequiredClaimError"


def test_e_missing_audience_rejected(server_module):
    client_id, _ = _register_client(server_module)
    ok, err = _verify(server_module,
                      _mint(server_module, drop=("aud",)),
                      expected_client_id=client_id)
    assert ok is False and err == "MissingRequiredClaimError"


def test_f_list_audience_rejected_even_if_it_contains_expected(server_module):
    """
    F - PyJWT would happily accept aud=[expected, "anything-else"].

    Our producer NEVER emits a list. Accepting one would silently widen the
    trust boundary, so a list audience must be rejected outright - even when
    the expected value is contained in it.
    """
    client_id, _ = _register_client(server_module)
    token = _mint(server_module, aud=[client_id, "attacker-controlled"])
    # sanity: plain PyJWT really does accept this - that is the hazard
    jwt.decode(token, server_module.OAUTH_JWT_SECRET,
               audience=client_id, algorithms=["HS256"])
    ok, err = _verify(server_module, token, expected_client_id=client_id)
    assert ok is False and err == "InvalidAudienceError"
    ok, err = _verify(server_module, token)
    assert ok is False and err == "InvalidAudienceError"


def test_g_arbitrary_attacker_issuer_rejected(server_module):
    client_id, _ = _register_client(server_module)
    for bad in ("", "https://aeralogin.com", "aeralogin.com.evil.tld",
                "AERALOGIN.COM", "attacker"):
        ok, _ = _verify(server_module,
                        _mint(server_module, aud=client_id, iss=bad),
                        expected_client_id=client_id)
        assert ok is False, f"issuer {bad!r} must be rejected"


def test_h_arbitrary_attacker_audience_rejected(server_module):
    """H - an audience that is not a registered active client is rejected."""
    for bad in ("not-a-client", "aera_totally_made_up", ""):
        ok, _ = _verify(server_module, _mint(server_module, aud=bad))
        assert ok is False, f"audience {bad!r} must be rejected"


def test_h2_audience_of_deactivated_client_rejected(server_module):
    """A revoked client's tokens must stop verifying on the generic path."""
    client_id, _ = _register_client(server_module, active=False)
    ok, err = _verify(server_module, _mint(server_module, aud=client_id))
    assert ok is False and err == "InvalidAudienceError"


def test_i_valid_signature_wrong_issuer_rejected(server_module):
    """I - signature is genuine; only iss is off. Must still fail."""
    client_id, _ = _register_client(server_module)
    token = _mint(server_module, aud=client_id, iss="aeralogin.co")
    jwt.decode(token, server_module.OAUTH_JWT_SECRET,
               audience=client_id, algorithms=["HS256"])  # signature is fine
    assert _verify(server_module, token, expected_client_id=client_id)[0] is False


def test_j_valid_signature_wrong_audience_rejected(server_module):
    client_a, _ = _register_client(server_module)
    client_b, _ = _register_client(server_module)
    token = _mint(server_module, aud=client_b)
    jwt.decode(token, server_module.OAUTH_JWT_SECRET,
               audience=client_b, algorithms=["HS256"])  # signature is fine
    assert _verify(server_module, token, expected_client_id=client_a)[0] is False


def test_k_expired_token_rejected(server_module):
    client_id, _ = _register_client(server_module)
    ok, err = _verify(server_module,
                      _mint(server_module, aud=client_id, ttl=-10),
                      expected_client_id=client_id)
    assert ok is False and err == "ExpiredSignatureError"


def test_l_invalid_signature_rejected(server_module):
    client_id, _ = _register_client(server_module)
    ok, err = _verify(server_module,
                      _mint(server_module, aud=client_id,
                            secret="an-entirely-different-secret-value-xx"),
                      expected_client_id=client_id)
    assert ok is False and err == "InvalidSignatureError"


def test_l2_token_signed_with_token_secret_rejected(server_module):
    """Cross-secret confusion: dashboard JWTs must not verify as OAuth tokens."""
    client_id, _ = _register_client(server_module)
    ok, _ = _verify(server_module,
                    _mint(server_module, aud=client_id,
                          secret=server_module.TOKEN_SECRET),
                    expected_client_id=client_id)
    assert ok is False


def test_m_alg_none_rejected(server_module):
    client_id, _ = _register_client(server_module)
    ok, _ = _verify(server_module,
                    _mint(server_module, aud=client_id, alg="none"),
                    expected_client_id=client_id)
    assert ok is False


def test_missing_required_claims_rejected(server_module):
    client_id, _ = _register_client(server_module)
    for claim in ("sub", "iat", "exp", "jti"):
        ok, _ = _verify(server_module,
                        _mint(server_module, aud=client_id, drop=(claim,)),
                        expected_client_id=client_id)
        assert ok is False, f"missing {claim} must be rejected"


# ==========================================================================
# PHASE 4 - cross-client confusion (the actual N3 finding)
# ==========================================================================
def test_cross_client_token_rejected_on_authenticated_endpoint(
    client, server_module, monkeypatch
):
    """
    THE N3 REGRESSION TEST.

    /api/oauth/verify-nft authenticates the caller with client_id +
    client_secret, so the server knows exactly who is asking. A token minted
    for client A must therefore be rejected when client B presents it.
    """
    client_a, secret_a = _register_client(server_module)
    client_b, secret_b = _register_client(server_module)
    addr = "0x1111111111111111111111111111111111111111"
    token_for_a = server_module.issue_oauth_access_token(client_a, addr, 50, True)

    async def _fake_nft(_addr):
        return True

    monkeypatch.setattr(server_module.web3_service, "has_identity_nft", _fake_nft)

    # 1) client A verifies its own token -> accepted
    r = client.post("/api/oauth/verify-nft", json={
        "access_token": token_for_a,
        "client_id": client_a,
        "client_secret": secret_a,
    })
    assert r.json().get("valid") is True

    # 2) client B replays client A's token -> MUST be rejected
    r = client.post("/api/oauth/verify-nft", json={
        "access_token": token_for_a,
        "client_id": client_b,
        "client_secret": secret_b,
    })
    body = r.json()
    assert body.get("valid") is False, "cross-client token confusion still possible"
    assert "wallet" not in body


def test_cross_client_rejected_on_v1_verify_when_client_id_supplied(
    client, server_module
):
    """Opt-in strict binding on /api/v1/verify via X-AEra-Client-Id."""
    client_a, _ = _register_client(server_module)
    client_b, _ = _register_client(server_module)
    addr = "0x2222222222222222222222222222222222222222"
    token_for_a = server_module.issue_oauth_access_token(client_a, addr, 50, True)

    ok = client.post("/api/v1/verify",
                     headers={"Authorization": f"Bearer {token_for_a}",
                              "X-AEra-Client-Id": client_a}).json()
    assert ok.get("valid") is True
    assert ok.get("wallet", "").lower() == addr.lower()

    bad = client.post("/api/v1/verify",
                      headers={"Authorization": f"Bearer {token_for_a}",
                               "X-AEra-Client-Id": client_b}).json()
    assert bad.get("valid") is False
    assert "wallet" not in bad


# ==========================================================================
# /api/v1/verify endpoint-level hardening (backward-compatible path)
# ==========================================================================
def test_v1_verify_still_works_without_client_id(client, server_module):
    """Backward compatibility: existing SDKs send only the Bearer header."""
    client_id, _ = _register_client(server_module)
    addr = "0x3333333333333333333333333333333333333333"
    token = server_module.issue_oauth_access_token(client_id, addr, 50, True)
    body = client.post("/api/v1/verify",
                       headers={"Authorization": f"Bearer {token}"}).json()
    assert body.get("valid") is True
    assert body.get("wallet", "").lower() == addr.lower()
    assert body.get("client_id") == client_id


@pytest.mark.parametrize("mutation", [
    {"iss": "evil.example"},
    {"drop": ("iss",)},
    {"drop": ("aud",)},
])
def test_v1_verify_rejects_forged_claims(client, server_module, mutation):
    client_id, _ = _register_client(server_module)
    kwargs = {"aud": client_id, **mutation}
    token = _mint(server_module, **kwargs)
    body = client.post("/api/v1/verify",
                       headers={"Authorization": f"Bearer {token}"}).json()
    assert body.get("valid") is False
    assert "wallet" not in body


def test_v1_verify_rejects_unregistered_audience(client, server_module):
    token = _mint(server_module, aud="aera_not_registered_at_all")
    body = client.post("/api/v1/verify",
                       headers={"Authorization": f"Bearer {token}"}).json()
    assert body.get("valid") is False


def test_v1_verify_error_does_not_leak_token(client, server_module):
    """Error responses must never echo the token back."""
    client_id, _ = _register_client(server_module)
    token = _mint(server_module, aud=client_id, iss="evil.example")
    body = client.post("/api/v1/verify",
                       headers={"Authorization": f"Bearer {token}"}).json()
    assert token not in json.dumps(body)


# ==========================================================================
# source-level regression guard
# ==========================================================================
def test_oauth_verifiers_no_longer_disable_audience_validation():
    """
    Guard against a future regression re-introducing `verify_aud: False`
    on an OAUTH_JWT_SECRET code path.
    """
    import pathlib

    src = pathlib.Path(__file__).resolve().parent.parent / "server.py"
    text = src.read_text(encoding="utf-8")
    # the only permitted occurrence lives inside verify_oauth_access_token,
    # where the audience is validated explicitly right afterwards.
    assert text.count("verify_aud") <= 2, (
        "unexpected verify_aud usage - audience validation may have been "
        "disabled again"
    )
    assert "Skip audience validation" not in text
