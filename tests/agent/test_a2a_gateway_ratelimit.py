"""Public A2A gateway — rate limiting and abuse control tests.

The threat model here is an UNAUTHENTICATED caller. There is no credential to
revoke and no account to suspend, so the only levers are cost and time. These
tests therefore check three separate things:

  1. the limiter actually limits (and can be configured),
  2. it cannot be bypassed — not by varying message ids, rpc ids, or by
     spoofing a forwarding header,
  3. it does not weaken anything that was already protecting the gateway:
     replay protection, agent status checks, and non-enumerability all still
     hold while rate limiting is active.

Timing is injected (`now=`) wherever possible rather than slept on, so these
tests are deterministic and do not get slower as the limits get stricter.
"""
from __future__ import annotations

import json
import uuid

import pytest

from a2a_gateway.constants import (
    ERR_RATE_LIMITED,
    GATEWAY_PATH,
    MAX_REQUEST_BYTES,
    SKILL_READ_PROFILE,
    TARGET_AGENT_FIELD,
    WELL_KNOWN_PATH,
)
from a2a_gateway.ratelimit import (
    SCOPE_AGENT,
    SCOPE_GLOBAL,
    SCOPE_PEER,
    Limit,
    RateLimiter,
    client_source,
    get_limiter,
    load_limits,
    reset_limiter,
    trusted_proxies,
)

# Reuse the existing suite's fixtures and builders rather than duplicating the
# AEra-side setup; `agent`, `rpc` and `post` come with the autouse fixture that
# mounts the router and resets limiter state per test.
from tests.agent.test_a2a_gateway import (  # noqa: F401
    CAP_PROFILE,
    _gateway_router,
    agent,
    post,
    rpc,
)


def flood(client, agent_id, n):
    """Send n well-formed, individually-valid requests. Returns the responses."""
    return [post(client, rpc(target=agent_id)) for _ in range(n)]


def first_429(responses):
    for i, r in enumerate(responses):
        if r.status_code == 429:
            return i, r
    return None, None


# --------------------------------------------------------------------------- #
# the limiter itself (deterministic, no HTTP, no sleeping)
# --------------------------------------------------------------------------- #
def test_burst_is_allowed_then_the_sustained_rate_applies():
    limiter = RateLimiter({SCOPE_PEER: Limit(rate=1.0, burst=5.0)})
    allowed = [limiter.check(SCOPE_PEER, "peer", now=100.0).allowed for _ in range(6)]
    assert allowed == [True] * 5 + [False], (
        "the bucket must permit exactly its burst capacity at one instant")


def test_tokens_refill_at_the_configured_rate():
    limiter = RateLimiter({SCOPE_PEER: Limit(rate=2.0, burst=2.0)})
    for _ in range(2):
        assert limiter.check(SCOPE_PEER, "peer", now=0.0).allowed
    assert not limiter.check(SCOPE_PEER, "peer", now=0.0).allowed
    # One second later, a rate of 2/s must have restored exactly two tokens.
    assert limiter.check(SCOPE_PEER, "peer", now=1.0).allowed
    assert limiter.check(SCOPE_PEER, "peer", now=1.0).allowed
    assert not limiter.check(SCOPE_PEER, "peer", now=1.0).allowed


def test_the_bucket_never_refills_beyond_its_burst():
    """Otherwise a long-idle attacker would accumulate an unbounded burst."""
    limiter = RateLimiter({SCOPE_PEER: Limit(rate=1.0, burst=3.0)})
    limiter.check(SCOPE_PEER, "peer", now=0.0)
    allowed = [limiter.check(SCOPE_PEER, "peer", now=100_000.0).allowed
               for _ in range(4)]
    assert allowed == [True, True, True, False]


def test_retry_after_reflects_the_actual_wait():
    limiter = RateLimiter({SCOPE_PEER: Limit(rate=0.5, burst=1.0)})
    assert limiter.check(SCOPE_PEER, "peer", now=0.0).allowed
    decision = limiter.check(SCOPE_PEER, "peer", now=0.0)
    assert not decision.allowed
    # At 0.5 tokens/s, one token takes 2s. Rounded up, never below 1.
    assert decision.retry_after == 2


def test_retry_after_is_always_at_least_one_second():
    """A Retry-After of 0 invites an immediate retry, which is the opposite
    of what a limiter is for."""
    limiter = RateLimiter({SCOPE_PEER: Limit(rate=1000.0, burst=1.0)})
    limiter.check(SCOPE_PEER, "peer", now=0.0)
    assert limiter.check(SCOPE_PEER, "peer", now=0.0).retry_after >= 1


def test_the_three_scopes_are_independent():
    """One noisy peer must not drain a bucket that everyone else shares."""
    limiter = RateLimiter({
        SCOPE_GLOBAL: Limit(rate=1.0, burst=100.0),
        SCOPE_PEER: Limit(rate=1.0, burst=1.0),
        SCOPE_AGENT: Limit(rate=1.0, burst=1.0),
    })
    limiter.check(SCOPE_PEER, "noisy", now=0.0)
    assert not limiter.check(SCOPE_PEER, "noisy", now=0.0).allowed
    # A different peer, and the other scopes, are untouched.
    assert limiter.check(SCOPE_PEER, "quiet", now=0.0).allowed
    assert limiter.check(SCOPE_GLOBAL, "all", now=0.0).allowed
    assert limiter.check(SCOPE_AGENT, "agent-1", now=0.0).allowed


def test_distinct_keys_do_not_share_a_bucket():
    limiter = RateLimiter({SCOPE_AGENT: Limit(rate=1.0, burst=1.0)})
    assert limiter.check(SCOPE_AGENT, "agent-a", now=0.0).allowed
    assert limiter.check(SCOPE_AGENT, "agent-b", now=0.0).allowed


def test_bucket_table_is_bounded_so_it_cannot_exhaust_memory():
    """An attacker with a large address pool must not be able to grow our
    state without limit."""
    limiter = RateLimiter({SCOPE_PEER: Limit(rate=1.0, burst=1.0)}, max_keys=50)
    for i in range(500):
        limiter.check(SCOPE_PEER, f"10.0.0.{i}", now=float(i))
    assert limiter.tracked_keys() <= 50


def test_eviction_does_not_release_a_currently_throttled_peer():
    """Evicting an actively-limited bucket would hand an attacker a free reset,
    so a peer that is over its limit stays over it even under memory pressure."""
    limiter = RateLimiter({SCOPE_PEER: Limit(rate=0.001, burst=1.0)}, max_keys=10)
    limiter.check(SCOPE_PEER, "attacker", now=0.0)
    assert not limiter.check(SCOPE_PEER, "attacker", now=0.0).allowed
    for i in range(9):
        limiter.check(SCOPE_PEER, f"filler-{i}", now=0.0)
    assert not limiter.check(SCOPE_PEER, "attacker", now=0.0).allowed


def test_limits_are_configurable_from_the_environment(monkeypatch):
    monkeypatch.setenv("AERA_A2A_PEER_RATE", "7")
    monkeypatch.setenv("AERA_A2A_PEER_BURST", "9")
    limits = load_limits()
    assert limits[SCOPE_PEER].rate == 7.0
    assert limits[SCOPE_PEER].burst == 9.0


def test_invalid_or_hostile_configuration_falls_back_to_defaults(monkeypatch):
    """A typo in the environment must not silently disable rate limiting."""
    default = load_limits()[SCOPE_PEER]
    for bad in ("", "abc", "0", "-5"):
        monkeypatch.setenv("AERA_A2A_PEER_RATE", bad)
        assert load_limits()[SCOPE_PEER].rate == default.rate, (
            f"{bad!r} must not disable the limit")


# --------------------------------------------------------------------------- #
# peer identification — X-Forwarded-For is attacker-controlled
# --------------------------------------------------------------------------- #
class _FakeRequest:
    def __init__(self, host, headers=None):
        self.client = type("C", (), {"host": host})()
        self.headers = headers or {}


def test_forwarded_header_is_ignored_when_no_proxy_is_trusted(monkeypatch):
    monkeypatch.delenv("AERA_A2A_TRUSTED_PROXIES", raising=False)
    request = _FakeRequest("203.0.113.9", {"x-forwarded-for": "1.2.3.4"})
    assert client_source(request) == "203.0.113.9", (
        "an unauthenticated caller must not be able to choose its own bucket")


def test_spoofed_forwarded_header_cannot_rotate_the_rate_limit_key(monkeypatch):
    """The core bypass: if X-Forwarded-For were trusted, an attacker would get
    a fresh bucket per request simply by changing a header."""
    monkeypatch.delenv("AERA_A2A_TRUSTED_PROXIES", raising=False)
    keys = {client_source(_FakeRequest("198.51.100.5",
                                       {"x-forwarded-for": f"9.9.9.{i}"}))
            for i in range(20)}
    assert keys == {"198.51.100.5"}


def test_forwarded_header_is_used_only_from_a_configured_proxy(monkeypatch):
    monkeypatch.setenv("AERA_A2A_TRUSTED_PROXIES", "10.0.0.1")
    trusted = _FakeRequest("10.0.0.1", {"x-forwarded-for": "1.2.3.4"})
    assert client_source(trusted) == "1.2.3.4"
    untrusted = _FakeRequest("10.0.0.2", {"x-forwarded-for": "1.2.3.4"})
    assert client_source(untrusted) == "10.0.0.2"


def test_proxy_chain_uses_the_last_untrusted_hop(monkeypatch):
    monkeypatch.setenv("AERA_A2A_TRUSTED_PROXIES", "10.0.0.1,10.0.0.2")
    request = _FakeRequest("10.0.0.1",
                           {"x-forwarded-for": "1.2.3.4, 5.6.7.8, 10.0.0.2"})
    assert client_source(request) == "5.6.7.8", (
        "entries beyond the trusted chain are attacker-supplied and must not win")


def test_trusted_proxies_are_empty_by_default(monkeypatch):
    monkeypatch.delenv("AERA_A2A_TRUSTED_PROXIES", raising=False)
    assert trusted_proxies() == frozenset()


def test_a_missing_client_address_still_yields_a_usable_key():
    assert client_source(_FakeRequest(None)) == "unknown"


# --------------------------------------------------------------------------- #
# HTTP behaviour
# --------------------------------------------------------------------------- #
def test_flooding_the_endpoint_eventually_returns_429(client, agent, monkeypatch):
    monkeypatch.setenv("AERA_A2A_PEER_BURST", "4")
    monkeypatch.setenv("AERA_A2A_PEER_RATE", "1")
    reset_limiter()
    index, response = first_429(flood(client, agent.agent_id, 12))
    assert response is not None, "an unauthenticated flood was never throttled"
    assert index == 4, f"expected the 5th request to trip the burst of 4, got {index}"


def test_the_429_carries_a_retry_after_header(client, agent, monkeypatch):
    monkeypatch.setenv("AERA_A2A_PEER_BURST", "2")
    monkeypatch.setenv("AERA_A2A_PEER_RATE", "1")
    reset_limiter()
    _, response = first_429(flood(client, agent.agent_id, 6))
    assert "retry-after" in {k.lower() for k in response.headers}
    assert int(response.headers["retry-after"]) >= 1


def test_the_429_body_is_a_structured_jsonrpc_error(client, agent, monkeypatch):
    monkeypatch.setenv("AERA_A2A_PEER_BURST", "2")
    reset_limiter()
    _, response = first_429(flood(client, agent.agent_id, 6))
    body = response.json()
    assert body["jsonrpc"] == "2.0"
    assert body["error"]["code"] == ERR_RATE_LIMITED
    assert body["error"]["data"]["retryAfter"] == int(response.headers["retry-after"])


def test_the_429_body_leaks_no_configuration_or_internals(client, agent, monkeypatch):
    """Telling the caller which bucket tripped, or how big it is, is a recipe
    for tuning a flood that stays just under the limit."""
    monkeypatch.setenv("AERA_A2A_PEER_BURST", "2")
    reset_limiter()
    _, response = first_429(flood(client, agent.agent_id, 6))
    blob = json.dumps(response.json()).lower()
    for forbidden in ("peer", "global", "bucket", "token", "aera_a2a_",
                      "burst", "traceback", "sqlite", "/home/"):
        assert forbidden not in blob, f"429 body leaked {forbidden!r}"


def test_varying_the_message_id_does_not_bypass_the_limit(client, agent, monkeypatch):
    """`rpc()` already mints a fresh messageId per call, so this asserts that
    rate limiting is keyed on the caller and not on request identity."""
    monkeypatch.setenv("AERA_A2A_PEER_BURST", "3")
    reset_limiter()
    responses = [post(client, rpc(target=agent.agent_id, message_id=uuid.uuid4().hex))
                 for _ in range(9)]
    assert any(r.status_code == 429 for r in responses)


def test_varying_the_rpc_id_does_not_bypass_the_limit(client, agent, monkeypatch):
    monkeypatch.setenv("AERA_A2A_PEER_BURST", "3")
    reset_limiter()
    responses = [post(client, rpc(target=agent.agent_id, rpc_id=str(i)))
                 for i in range(9)]
    assert any(r.status_code == 429 for r in responses)


def test_malformed_requests_still_consume_the_limit(client, monkeypatch):
    """If garbage were free, an attacker would simply send garbage."""
    monkeypatch.setenv("AERA_A2A_PEER_BURST", "3")
    reset_limiter()
    statuses = [client.post(GATEWAY_PATH, content=b"{not json",
                            headers={"content-type": "application/json"}).status_code
                for _ in range(9)]
    assert 429 in statuses


def test_oversized_requests_still_consume_the_limit(client, monkeypatch):
    monkeypatch.setenv("AERA_A2A_PEER_BURST", "3")
    reset_limiter()
    huge = b'{"x":"' + b"a" * (MAX_REQUEST_BYTES + 100) + b'"}'
    statuses = [client.post(GATEWAY_PATH, content=huge,
                            headers={"content-type": "application/json"}).status_code
                for _ in range(9)]
    assert 429 in statuses


def test_requests_for_an_unknown_agent_still_consume_the_limit(client, monkeypatch):
    monkeypatch.setenv("AERA_A2A_PEER_BURST", "3")
    reset_limiter()
    responses = [post(client, rpc(target="agent_does_not_exist")) for _ in range(9)]
    assert any(r.status_code == 429 for r in responses)


def test_the_agent_card_is_not_blocked_by_a_post_flood(client, agent, monkeypatch):
    """Discovery is cheap, static and cached; throttling it would break
    legitimate A2A clients for no security benefit."""
    monkeypatch.setenv("AERA_A2A_PEER_BURST", "2")
    reset_limiter()
    flood(client, agent.agent_id, 10)
    for _ in range(5):
        assert client.get(WELL_KNOWN_PATH).status_code == 200


def test_the_internal_agent_relay_is_unaffected(client, agent, monkeypatch):
    """/api/agents/messages is a different endpoint with its own auth; the
    gateway's limiter must not reach into it."""
    monkeypatch.setenv("AERA_A2A_PEER_BURST", "1")
    reset_limiter()
    flood(client, agent.agent_id, 5)
    response = client.post("/api/agents/messages", json=rpc(target=agent.agent_id))
    assert response.status_code != 429


# --------------------------------------------------------------------------- #
# rate limiting must not weaken the existing protections
# --------------------------------------------------------------------------- #
def test_rate_limiting_is_enforced_before_any_database_access(client, agent,
                                                              monkeypatch):
    """The whole point: a throttled request must cost us no I/O. If the limiter
    ran after routing, this test would surface the DB error instead of a 429."""
    from a2a_gateway import routes as gw_routes

    monkeypatch.setenv("AERA_A2A_PEER_BURST", "2")
    reset_limiter()
    post(client, rpc(target=agent.agent_id))
    post(client, rpc(target=agent.agent_id))

    def explode():
        raise AssertionError("database was touched for a rate-limited request")

    monkeypatch.setattr(gw_routes, "_conn_factory", explode)
    response = post(client, rpc(target=agent.agent_id))
    assert response.status_code == 429


def test_the_per_agent_limit_applies_before_the_database_lookup(agent, monkeypatch):
    """The per-agent bucket is checked in the handler, after parsing but still
    before SQLite is opened."""
    from a2a_gateway.handler import handle_request

    monkeypatch.setenv("AERA_A2A_AGENT_BURST", "2")
    reset_limiter()
    limiter = get_limiter()
    for _ in range(2):
        limiter.check(SCOPE_AGENT, agent.agent_id)

    def explode():
        raise AssertionError("database was touched for a rate-limited request")

    payload, status = handle_request(rpc(target=agent.agent_id), {},
                                     conn_factory=explode, protocol_version="0.3")
    assert status == 429
    assert payload["error"]["code"] == ERR_RATE_LIMITED


def test_a_distributed_flood_at_one_agent_is_still_capped(monkeypatch):
    """Many source addresses each stay under the per-peer limit, so only the
    per-agent bucket can stop them."""
    limiter = RateLimiter({
        SCOPE_PEER: Limit(rate=1.0, burst=5.0),
        SCOPE_AGENT: Limit(rate=1.0, burst=3.0),
    })
    outcomes = []
    for i in range(20):
        peer_ok = limiter.check(SCOPE_PEER, f"10.0.0.{i}", now=0.0).allowed
        agent_ok = limiter.check(SCOPE_AGENT, "victim", now=0.0).allowed
        outcomes.append(peer_ok and agent_ok)
    assert all(outcomes[:3]) and not any(outcomes[3:])


def test_replay_protection_still_rejects_a_duplicate(client, agent, monkeypatch):
    """Rate limiting and replay protection are separate concerns; neither may
    be allowed to quietly stand in for the other."""
    monkeypatch.setenv("AERA_A2A_PEER_BURST", "20")
    monkeypatch.setenv("AERA_A2A_AGENT_BURST", "20")
    reset_limiter()
    payload = rpc(target=agent.agent_id)
    assert post(client, payload).status_code == 200
    second = post(client, payload)
    assert second.status_code != 429, "a replay must be reported as a replay"
    assert "error" in second.json()


def test_a_revoked_agent_is_still_refused_under_the_limit(client, agent, monkeypatch):
    monkeypatch.setenv("AERA_A2A_PEER_BURST", "20")
    reset_limiter()
    agent.revoke_agent()
    response = post(client, rpc(target=agent.agent_id))
    assert response.status_code != 429
    assert "error" in response.json()


def test_unknown_and_revoked_agents_remain_indistinguishable(client, agent,
                                                             monkeypatch):
    """Rate limiting must not have introduced a new enumeration oracle."""
    monkeypatch.setenv("AERA_A2A_PEER_BURST", "20")
    reset_limiter()
    agent.revoke_agent()
    revoked = post(client, rpc(target=agent.agent_id)).json()
    unknown = post(client, rpc(target="agent_nope")).json()
    assert revoked["error"]["message"] == unknown["error"]["message"]
    assert revoked["error"]["code"] == unknown["error"]["code"]


def test_a_legitimate_client_recovers_after_waiting(client, agent, monkeypatch):
    """Throttling must be temporary — otherwise it is a self-inflicted outage."""
    monkeypatch.setenv("AERA_A2A_PEER_BURST", "2")
    monkeypatch.setenv("AERA_A2A_PEER_RATE", "1")
    reset_limiter()
    _, throttled = first_429(flood(client, agent.agent_id, 6))
    assert throttled is not None

    # Instead of sleeping, hand the bucket the time it asked us to wait for.
    limiter = get_limiter()
    import time as _time
    future = _time.monotonic() + int(throttled.headers["retry-after"]) + 1
    assert limiter.check(SCOPE_PEER, "testclient", now=future).allowed


def test_limiter_state_is_per_process_and_this_is_documented():
    """Guards the honesty of the deployment claim: this limiter is in-process,
    so it only equals a global limit while the service runs one worker."""
    import a2a_gateway.ratelimit as rl

    assert "PER PROCESS" in rl.__doc__
    assert RateLimiter() is not RateLimiter(), "state must not be class-level"
