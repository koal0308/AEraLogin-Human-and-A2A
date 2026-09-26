"""Phase 12 – Agent Layer Test Specification (design only, no code).

This file intentionally contains PENDING tests. They serve as
executable placeholders for the security tests that MUST be
implemented once the Agent Identity Layer is built.

Every test is marked as `xfail(strict=False, reason='design only')` so
pytest reports them as expected-fail; they do not obscure real results.
"""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.xfail(strict=False,
                               reason="Design-only spec – Agent Layer not implemented yet")


def test_agent_impersonation_rejected():
    """Given a valid agent JWT for agent_A, a request that claims to
    originate from agent_A but is signed with agent_B's key MUST be
    rejected with 401."""
    raise NotImplementedError


def test_agent_public_key_replacement_requires_owner_signature():
    """Rotating agents[agent_id].public_key MUST require a fresh
    wallet-owner signature. Direct DB-writes must never suffice."""
    raise NotImplementedError


def test_agent_challenge_is_single_use():
    """A challenge from /api/agents/{id}/challenge MUST be consumable
    exactly once. The second /authenticate with the same nonce MUST 401."""
    raise NotImplementedError


def test_agent_expired_challenge_rejected():
    """A challenge older than agent_nonces.expires_at MUST be rejected."""
    raise NotImplementedError


def test_wrong_agent_signature_rejected():
    """Ed25519 signature that fails verification against
    agents.public_key MUST 401."""
    raise NotImplementedError


def test_signature_from_another_agent_rejected():
    """A signature made by agent_B over a challenge issued to agent_A
    MUST 401 even if agent_B is also registered."""
    raise NotImplementedError


def test_revoked_agent_rejected():
    """agents.revoked_at IS NOT NULL ⇒ all authentication attempts MUST
    fail, and existing JWTs (via jti store) MUST be invalidated."""
    raise NotImplementedError


def test_cross_agent_jwt_rejected():
    """A JWT with sub=agent_A cannot be used at endpoints that require
    agent_B. aud MUST be validated."""
    raise NotImplementedError


def test_agent_jwt_wrong_audience_rejected():
    """verify_aud MUST be enabled (opposite of current S-01)."""
    raise NotImplementedError


def test_agent_jwt_wrong_issuer_rejected():
    """iss MUST equal the AEra issuer (opposite of current S-08)."""
    raise NotImplementedError


def test_duplicated_jti_rejected():
    """Second use of the same jti MUST 401 (fixes S-02)."""
    raise NotImplementedError


def test_agent_interaction_records_agent_id_in_metadata():
    """When Agent-A → Agent-B, on-chain metadata must include both
    agent identifiers, while the wallet columns still carry the owner
    wallets."""
    raise NotImplementedError
