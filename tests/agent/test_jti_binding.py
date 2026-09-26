"""Phase-3/Phase-4 release gate tests: JTI binding + secret-compromise model.

These tests deliberately assume the attacker OWNS AGENT_JWT_SECRET. They prove
that possession of the HS256 signing secret alone is NOT sufficient to mint a
usable Agent JWT, because every identity-bearing claim is additionally bound to
the server-side `agent_jti` registration record.

The JTI is a lifecycle / revocation register - NOT an anti-replay nonce.
Test J explicitly guards against anyone "fixing" that into one-time-use.
"""
from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timedelta, timezone

import jwt as pyjwt
import pytest

from agent.constants import (
    AUD_AGENT_API,
    AUD_AGENT_RELAY,
    JWT_ALG,
    JWT_ISSUER,
    JWT_TYP,
)
from agent.crypto import Ed25519Signer
from agent import tokens as _tokens
from agent import repository as _repo

from tests.agent.testclient import ANVIL_KEY_2, AgentTestClient


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _decode_no_verify(token: str) -> dict:
    return pyjwt.decode(token, options={"verify_signature": False,
                                        "verify_aud": False,
                                        "verify_exp": False},
                        algorithms=[JWT_ALG])


def _auth(c, *, aud: str = AUD_AGENT_API) -> str:
    """Authenticate and return the raw Agent JWT string."""
    r = c.authenticate(aud=aud)
    assert r.status_code == 200, r.text
    return c.token


def _remint(claims: dict, **overrides) -> str:
    """Attacker capability: re-sign arbitrary claims with the LEAKED secret."""
    payload = dict(claims)
    payload.update(overrides)
    return pyjwt.encode(payload, _tokens.get_secret(), algorithm=JWT_ALG)


def _verify(token: str, *, aud: str = AUD_AGENT_API):
    """Returns None on success, or the AgentJWTError code string on rejection."""
    try:
        _tokens.verify(token, expected_aud=aud)
        return None
    except _tokens.AgentJWTError as e:
        return e.code


@pytest.fixture()
def agent_a(client, wipe_agent_tables):
    c = AgentTestClient(client)
    c.register(capabilities=["agent.authenticate", "agent.read.profile",
                             "agent.communicate", "agent.interaction.record"])
    return c


@pytest.fixture()
def agent_b(client, agent_a):
    """A second, independently owned, active agent."""
    c = AgentTestClient(client, eth_priv=ANVIL_KEY_2)
    c.register(capabilities=["agent.authenticate", "agent.communicate"])
    return c


# ==========================================================================
# PHASE 3 - JTI BINDING
# ==========================================================================

def test_A_altered_sub_rejected(agent_a, agent_b):
    """TEST A: valid active JTI, only JWT.sub changed to another ACTIVE agent."""
    token = _auth(agent_a)
    claims = _decode_no_verify(token)
    assert _verify(token) is None, "baseline token must be valid"

    forged = _remint(claims, sub=agent_b.agent_id)
    assert _verify(forged) is not None, "sub pivot must be rejected"


def test_B_altered_key_id_rejected(agent_a):
    """TEST B: valid active JTI, only JWT.key_id changed to another ACTIVE key."""
    second = Ed25519Signer.generate()
    other_key_id = agent_a.add_key(second)

    token = _auth(agent_a)
    claims = _decode_no_verify(token)
    assert claims["key_id"] != other_key_id

    forged = _remint(claims, key_id=other_key_id)
    assert _verify(forged) is not None, "key_id pivot must be rejected"


def test_C_altered_aud_rejected(agent_a):
    """TEST C: valid active JTI, only JWT.aud changed to another ALLOWED audience.

    This is the audience-pivot attack: the JTI was registered for
    aera-agent-api, the attacker re-mints it for aera-agent-relay.
    """
    token = _auth(agent_a)
    claims = _decode_no_verify(token)
    assert claims["aud"] == AUD_AGENT_API

    forged = _remint(claims, aud=AUD_AGENT_RELAY)
    # verified against the audience the attacker is actually targeting
    assert _verify(forged, aud=AUD_AGENT_RELAY) is not None, \
        "audience pivot on an active JTI must be rejected"


def test_D_altered_owner_wallet_rejected(agent_a):
    """TEST D: valid active JTI, only JWT.owner_wallet changed."""
    token = _auth(agent_a)
    claims = _decode_no_verify(token)

    forged = _remint(claims,
                     owner_wallet="0x000000000000000000000000000000000000dead")
    assert _verify(forged) is not None, "owner_wallet pivot must be rejected"


def test_E_fully_matching_claims_accepted(agent_a):
    """TEST E: every claim matches the DB registration -> success."""
    token = _auth(agent_a)
    assert _verify(token) is None

    claims = _decode_no_verify(token)
    row = _repo.get_connection().execute(
        "SELECT agent_id, key_id, aud, status FROM agent_jti WHERE jti=?",
        (claims["jti"],)).fetchone()
    assert row["status"] == "active"
    assert row["agent_id"] == claims["sub"]
    assert row["key_id"] == claims["key_id"]
    assert row["aud"] == claims["aud"]


def test_F_unknown_jti_rejected(agent_a):
    """TEST F: well-formed, correctly signed token with a random unknown JTI."""
    token = _auth(agent_a)
    claims = _decode_no_verify(token)

    forged = _remint(claims, jti=uuid.uuid4().hex)
    assert _verify(forged) == "jti_unknown"


def test_G_revoked_jti_fails_immediately(agent_a):
    """TEST G: revoking the JTI invalidates the already-issued token at once."""
    token = _auth(agent_a)
    assert _verify(token) is None

    claims = _decode_no_verify(token)
    assert _tokens.revoke_jti(claims["jti"]) is True
    assert _verify(token) == "jti_revoked"


def test_H_revoked_key_invalidates_bound_jwts(agent_a):
    """TEST H: revoking the signing key kills every JWT bound to that key."""
    old_key_id = agent_a.key_id
    token = _auth(agent_a)
    assert _verify(token) is None, "token must be valid before key revocation"

    second = Ed25519Signer.generate()
    new_key_id = agent_a.rotate_key(second, revoke=old_key_id)
    assert new_key_id != old_key_id

    # the previously issued token is bound to the now-revoked key
    assert _verify(token) is not None, \
        "JWT bound to a revoked key must fail verification"


def test_I_revoked_agent_invalidates_all_jwts(agent_a):
    """TEST I: revoking the agent kills all of its JWTs."""
    token = _auth(agent_a)
    assert _verify(token) is None

    r = agent_a.revoke_agent()
    assert r.status_code == 200, r.text
    assert _verify(token) is not None


def test_J_valid_jwt_is_reusable_until_exp(agent_a):
    """TEST J: the JTI is a lifecycle register, NOT a one-time-use nonce.

    A valid Agent JWT MUST remain verifiable on repeated use before exp.
    This test exists to prevent a future regression into one-time-use tokens.
    """
    token = _auth(agent_a)
    for i in range(5):
        assert _verify(token) is None, f"verification #{i + 1} must still succeed"


# ==========================================================================
# PHASE 4 - SECRET COMPROMISE MODEL
# ==========================================================================

def test_secret_compromise_model(agent_a, agent_b):
    """Attacker holds AGENT_JWT_SECRET. Prove that is not enough.

    All six scenarios from the release prompt, evaluated in one place so the
    result is unambiguous.
    """
    base_token = _auth(agent_a)
    claims = _decode_no_verify(base_token)

    second = Ed25519Signer.generate()
    other_key_id = agent_a.add_key(second)

    results: dict[str, object] = {}

    # 1. unknown JTI
    results["1_unknown_jti"] = _verify(_remint(claims, jti=uuid.uuid4().hex))

    # 2. active JTI, altered sub
    results["2_altered_sub"] = _verify(_remint(claims, sub=agent_b.agent_id))

    # 3. active JTI, altered key_id
    results["3_altered_key_id"] = _verify(_remint(claims, key_id=other_key_id))

    # 4. active JTI, altered aud
    results["4_altered_aud"] = _verify(
        _remint(claims, aud=AUD_AGENT_RELAY), aud=AUD_AGENT_RELAY)

    # 5. active JTI, altered owner_wallet
    results["5_altered_owner"] = _verify(
        _remint(claims, owner_wallet="0x00000000000000000000000000000000deadbeef"))

    # 6. correctly bound token
    results["6_correctly_bound"] = _verify(base_token)

    # scenarios 1-5 MUST all be rejections (non-None error code)
    for name in ("1_unknown_jti", "2_altered_sub", "3_altered_key_id",
                 "4_altered_aud", "5_altered_owner"):
        assert results[name] is not None, f"{name} was ACCEPTED - forgery possible"

    # scenario 6 MUST succeed
    assert results["6_correctly_bound"] is None


def test_forged_token_with_foreign_issuer_rejected(agent_a):
    """Secret alone must not allow issuer spoofing."""
    claims = _decode_no_verify(_auth(agent_a))
    assert _verify(_remint(claims, iss="evil.example")) == "invalid_issuer"


def test_forged_token_with_wrong_typ_rejected(agent_a):
    """An OAuth-shaped token signed with the agent secret must not pass."""
    claims = _decode_no_verify(_auth(agent_a))
    assert _verify(_remint(claims, typ="access")) == "wrong_typ"


def test_forged_token_with_escalated_capabilities_rejected(agent_a):
    """Capabilities are server-authoritative even with the secret in hand."""
    claims = _decode_no_verify(_auth(agent_a))
    forged = _remint(claims, capabilities=["agent.admin", "agent.everything"])
    assert _verify(forged) == "capability_denied"


def test_forged_expired_token_rejected(agent_a):
    """exp is still enforced under a leaked secret."""
    claims = _decode_no_verify(_auth(agent_a))
    past = datetime.now(timezone.utc) - timedelta(hours=2)
    forged = _remint(claims,
                     iat=int((past - timedelta(minutes=5)).timestamp()),
                     exp=int(past.timestamp()))
    assert _verify(forged) == "expired_token"
