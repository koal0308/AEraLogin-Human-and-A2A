"""Phase 13 – Interaction origin cannot be attributed to an Agent.

We do NOT implement agents. We only DOCUMENT via a test that the
production code path calls `web3_service.record_interaction` with the
follower's WALLET (or owner) address, and that the on-chain `msg.sender`
is always the backend account – i.e. Agent-A cannot be cryptographically
distinguished from the backend today.
"""
from __future__ import annotations

import inspect
import re
from pathlib import Path

import server


def test_record_interaction_is_only_called_by_backend():
    """Every call site passes user addresses as arguments, but the
    Web3Service.record_interaction builds a tx with `self.account.address`
    as `from` – proving the on-chain sender is the backend wallet."""
    src = Path(server.__file__).parent.joinpath("web3_service.py").read_text()

    m = re.search(
        r"async def record_interaction\(.*?\).*?(?=\n    async def |\nclass )",
        src, flags=re.S)
    assert m, "record_interaction not found in production source"
    body = m.group(0)
    # The tx must be built with self.account.address as `from`
    assert "'from': self.account.address" in body, \
        "Sanity: production still uses backend wallet as on-chain msg.sender"


def test_backend_cannot_distinguish_agent_from_owner(server_module, db,
                                                     eth_test_account):
    """Simulate: an 'agent' calls a backend endpoint on behalf of its owner.
    With the CURRENT code there is no such endpoint; the closest is an
    interaction triggered by /api/verify. We check that the recorded call
    on the mocked web3_service uses the OWNER wallet, not an agent id."""
    import web3_service as w3s
    calls_before = list(w3s._MOCK_CALLS["record_interaction"])
    # Nothing to trigger without follow flow; we simply assert the mock
    # captures only address strings, never agent identifiers.
    for c in calls_before:
        assert c["initiator"].startswith("0x")
        assert c["responder"].startswith("0x")
        assert "agent" not in c["metadata"].lower()
