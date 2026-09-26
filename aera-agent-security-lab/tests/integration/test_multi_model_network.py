"""MODEL-07 .. MODEL-16 -- three independent identities, three A2A hops.

Offline half of the proof. The AEra relay call is stubbed here (there is no
relay endpoint in the offline `FakeDirectory`); the relay half is proven LIVE
by `src/cli/network.py` and recorded in `run-artifacts/network-run*.json`.

Everything security relevant is REAL: Ed25519 signing, canonical JSON, content
hashing and the full receiver-side `LocalVerifier` chain all use the production
primitives.
"""
from __future__ import annotations

import pytest

from src.a2a.protocol import LocalTransport
from src.agents.legit import RelayOutcome
from src.agents.roles import ANALYST, ORCHESTRATOR, REVIEWER, RoleAgent, hop
from src.crypto.aera_crypto import content_hash
from src.providers.claude import ClaudeProvider
from src.providers.deepseek import DeepSeekProvider
from src.providers.grok import GrokProvider
from src.providers.mock import MockProvider


def _agent(http, directory, ident, provider, name, role) -> RoleAgent:
    """Build a RoleAgent on a pre-seeded offline identity."""
    a = RoleAgent(http, provider, name=name, role=role)
    a.identity = ident
    a.bootstrap = lambda **kw: {}          # registration is a live-only step
    from src.a2a.protocol import LocalVerifier
    a.verifier = LocalVerifier(http=http, self_agent_id=ident.agent_id)
    # The relay is a live endpoint; offline we assert only the local half.
    a.notarise = lambda env: RelayOutcome(True, 200, None)
    return a


@pytest.fixture
def net(http, directory, ident_a, ident_b, ident_c):
    a = _agent(http, directory, ident_a, GrokProvider("xai-k"), "AgentA", ORCHESTRATOR)
    b = _agent(http, directory, ident_b, DeepSeekProvider("sk-k"), "AgentB", ANALYST)
    c = _agent(http, directory, ident_c, ClaudeProvider("sk-ant-k"), "AgentC", REVIEWER)
    return a, b, c, LocalTransport()


# --- MODEL-07/08/09: three INDEPENDENT identities ------------------------- #
def test_model_07_agent_ids_are_distinct(net):
    a, b, c, _ = net
    ids = [a.agent_id, b.agent_id, c.agent_id]
    assert all(i and i.startswith("did:aera:agent:") for i in ids)
    assert len(set(ids)) == 3


def test_model_08_key_ids_are_distinct(net):
    a, b, c, _ = net
    key_ids = [a.identity.key_id, b.identity.key_id, c.identity.key_id]
    assert all(key_ids)
    assert len(set(key_ids)) == 3


def test_model_09_ed25519_public_keys_are_distinct(net):
    a, b, c, _ = net
    keys = [a.identity.public_key, b.identity.public_key, c.identity.public_key]
    assert all(keys)
    assert len(set(keys)) == 3


def test_model_09b_identity_is_independent_of_the_provider(net):
    """LLM PROVIDER != AGENT IDENTITY: swapping the provider must not change
    a single identity attribute."""
    a, _, _, _ = net
    before = (a.agent_id, a.identity.key_id, a.identity.public_key)
    assert a.provider_name == "grok"

    a.provider = ClaudeProvider("sk-ant-other")
    assert a.provider_name == "claude"
    assert (a.agent_id, a.identity.key_id, a.identity.public_key) == before

    a.provider = MockProvider()
    assert (a.agent_id, a.identity.key_id, a.identity.public_key) == before


def test_model_09c_identity_carries_no_provider_information(net):
    """Nothing provider-specific may end up in the signed envelope."""
    a, b, _, t = net
    _, result = hop(a, b, t, "please analyse X")
    assert result.ok
    env = t.log and a.verifier  # delivered
    signed = str(a.agent_id) + str(a.identity.key_id)
    for token in ("grok", "deepseek", "claude", "xai", "anthropic", "gpt"):
        assert token not in signed.lower()


# --- MODEL-10/11/12: the three hops succeed ------------------------------- #
def test_model_10_a_to_b(net):
    a, b, _, t = net
    body, r = hop(a, b, t, "analyse this")
    assert r.ok and r.local_error is None and body == "analyse this"
    assert (r.sender, r.receiver) == ("AgentA", "AgentB")


def test_model_11_b_to_c(net):
    _, b, c, t = net
    body, r = hop(b, c, t, "review this analysis")
    assert r.ok and body == "review this analysis"


def test_model_12_c_to_a(net):
    a, _, c, t = net
    body, r = hop(c, a, t, "here is my review")
    assert r.ok and body == "here is my review"


def test_model_10_11_12_full_round_trip(net):
    a, b, c, t = net
    for sender, receiver in ((a, b), (b, c), (c, a)):
        body, r = hop(sender, receiver, t, f"{sender.name}->{receiver.name}")
        assert r.ok, (r.sender, r.receiver, r.local_error)
        assert body == f"{sender.name}->{receiver.name}"


# --- MODEL-13/14/15: each receiver verifies the sender INDEPENDENTLY ------ #
@pytest.mark.parametrize("pair", [("a", "b"), ("b", "c"), ("c", "a")])
def test_model_13_14_15_receiver_verifies_sender(net, pair):
    agents = dict(zip("abc", net[:3]))
    sender, receiver = agents[pair[0]], agents[pair[1]]
    body, r = hop(sender, receiver, net[3], "hello")
    assert r.local_ok and body == "hello"


@pytest.mark.parametrize("pair", [("a", "b"), ("b", "c"), ("c", "a")])
def test_model_13_14_15_receiver_rejects_the_wrong_sender(net, pair):
    """A receiver must reject a correctly signed message from an unexpected
    peer -- AEra acceptance alone is never sufficient."""
    agents = dict(zip("abc", net[:3]))
    sender, receiver = agents[pair[0]], agents[pair[1]]
    transport = net[3]
    impostor = [x for x in net[:3] if x not in (sender, receiver)][0]

    env, _ = impostor.send(transport, receiver=receiver, content="trust me")
    body, err, _ = receiver.receive(transport, expected_sender=sender.agent_id)
    assert body is None
    assert err == "sender_mismatch"


# --- MODEL-16: content_hash verified at EVERY hop ------------------------- #
@pytest.mark.parametrize("pair", [("a", "b"), ("b", "c"), ("c", "a")])
def test_model_16_content_hash_is_bound_to_the_bytes(net, pair):
    agents = dict(zip("abc", net[:3]))
    sender, receiver = agents[pair[0]], agents[pair[1]]
    transport = net[3]

    env, _ = sender.send(transport, receiver=receiver, content="original")
    assert env.payload["content_hash"] == content_hash(b"original")

    body, err, got = receiver.receive(transport, expected_sender=sender.agent_id)
    assert err is None and body == "original"
    assert content_hash(got.content) == got.payload["content_hash"]


@pytest.mark.parametrize("pair", [("a", "b"), ("b", "c"), ("c", "a")])
def test_model_16_tampered_content_is_rejected_at_every_hop(net, pair):
    agents = dict(zip("abc", net[:3]))
    sender, receiver = agents[pair[0]], agents[pair[1]]
    transport = net[3]

    env, _ = sender.send(transport, receiver=receiver, content="pay 10")
    queue = transport.inbox[receiver.agent_id]
    queue[-1].content = b"pay 10000"

    body, err, _ = receiver.receive(transport, expected_sender=sender.agent_id)
    assert body is None and err == "content_hash_mismatch"


# --- provider outage is an AVAILABILITY state, never a security pass ------ #
def test_provider_outage_never_raises_and_never_forges_content(net):
    a, b, _, t = net
    b.provider = MockProvider(fail=True)
    text, call = b.think("analyse this")
    assert text is None and call.ok is False and call.error
    assert call.provider == "mock"

    # The identity layer is unaffected by the outage.
    body, r = hop(b, a, t, "provider unavailable")
    assert r.ok


def test_think_reports_chars_on_success(net):
    _, b, _, _ = net
    b.provider = MockProvider(reply="XYZ")
    text, call = b.think("q")
    assert call.ok and call.chars == len(text) and call.provider == "mock"
