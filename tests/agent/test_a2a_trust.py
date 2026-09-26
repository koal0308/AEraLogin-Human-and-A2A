"""AEra External Peer Trust Assessment -- tests organised by the property defended.

Each test names the property it protects. The ordering follows the boundaries
that matter, not the call graph:

  A. Determinism and policy versioning
  B. Evidence: what is observed, what is refused
  C. Trust level vs confidence (the core distinction)
  D. Decay over time
  E. Credential rotation and peer identity
  F. Owner standing as ONE bounded input
  G. Trust never overrides authentication or authorization
  H. Trust never promotes LEVEL 3 to LEVEL 2
  I. Anonymous callers
  J. Bounded storage
  K. No enumeration oracle
  L. The Agent Identity Layer is untouched
"""
from __future__ import annotations

import ast
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from a2a_gateway import credentials as gw_cred
from a2a_gateway import peer as gw_peer
from a2a_gateway import trust as gw_trust

GATEWAY_DIR = Path(__file__).resolve().parents[2] / "a2a_gateway"
NOW = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


# --------------------------------------------------------------------------- #
# fixtures
# --------------------------------------------------------------------------- #
@pytest.fixture
def store():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    gw_trust.init_schema(conn)
    gw_cred.init_schema(conn)
    conn.execute("CREATE TABLE agents (agent_id TEXT, owner_wallet TEXT)")
    conn.execute("INSERT INTO agents VALUES ('agent-a', '0xowner')")
    conn.execute("INSERT INTO agents VALUES ('agent-b', '0xowner')")
    conn.commit()
    yield conn
    conn.close()


def _issue(conn, *, owner="0xowner", peer_id=None, days_ago=0.0):
    issued = gw_cred.issue_credential(
        conn, owner_address=owner, peer_id=peer_id,
        now=NOW - timedelta(days=days_ago))
    conn.commit()
    return issued


def _successes(conn, peer_id, count, *, agent="agent-a", spread_days=20.0,
               end_days_ago=0.0):
    """Record `count` successes spread backwards over `spread_days`."""
    for i in range(count):
        offset = end_days_ago + spread_days * (1 - (i + 1) / count)
        gw_trust.record_event(conn, peer_id=peer_id,
                              event_type=gw_trust.EV_REQUEST_SUCCESS,
                              target_agent_id=agent,
                              now=NOW - timedelta(days=offset))
    conn.commit()


def _assess(conn, peer_id):
    return gw_trust.assess_peer(conn, peer_id, now=NOW)


# --------------------------------------------------------------------------- #
# A. determinism and policy versioning
# --------------------------------------------------------------------------- #
def test_the_same_evidence_always_yields_the_same_assessment(store):
    issued = _issue(store, days_ago=30)
    peer = issued.record.peer_id
    _successes(store, peer, 10)

    first = _assess(store, peer)
    second = _assess(store, peer)

    assert first.trust_level == second.trust_level
    assert first.trust_score == second.trust_score
    assert first.confidence == second.confidence


def test_every_assessment_carries_the_policy_version_that_produced_it(store):
    issued = _issue(store)
    assessment = _assess(store, issued.record.peer_id)
    assert assessment.policy_version == gw_trust.POLICY_VERSION
    assert assessment.policy_version  # never blank


def test_the_calculation_is_pure_and_needs_no_database(store):
    """`assess` must stay I/O-free so a trust decision cannot make a call out."""
    summary = gw_trust.EvidenceSummary(
        peer_id="peer_x", counts={gw_trust.EV_REQUEST_SUCCESS: 5},
        first_seen=NOW - timedelta(days=10), last_seen=NOW)
    assessment = gw_trust.assess(summary, gw_trust.CredentialFacts(),
                                 gw_trust.OwnerStanding(), now=NOW)
    assert assessment.peer_id == "peer_x"


def test_assess_source_contains_no_network_or_sql(store):
    """Checked against the parsed code, not the prose -- docstrings may discuss
    anything; the executable statements may not."""
    tree = ast.parse((GATEWAY_DIR / "trust.py").read_text(encoding="utf-8"))
    func = next(n for n in ast.walk(tree)
                if isinstance(n, ast.FunctionDef) and n.name == "assess")
    called = {n.func.attr for n in ast.walk(func)
              if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
    for forbidden in ("execute", "executemany", "get", "post", "urlopen",
                      "connect", "request"):
        assert forbidden not in called, f"assess() calls .{forbidden}()"


def test_the_assessment_explains_itself(store):
    issued = _issue(store, days_ago=30)
    _successes(store, issued.record.peer_id, 10)
    assessment = _assess(store, issued.record.peer_id)

    names = {f.name for f in assessment.factors}
    assert {"successful_interactions", "relationship_age_days",
            "owner_standing", "negative_events"} <= names
    for factor in assessment.factors:
        assert factor.note, f"factor {factor.name} has no explanation"


# --------------------------------------------------------------------------- #
# B. evidence capture
# --------------------------------------------------------------------------- #
def test_an_unknown_event_type_is_refused_not_stored(store):
    assert gw_trust.record_event(store, peer_id="peer_1",
                                 event_type="looks_fine_to_me") is False
    rows = store.execute(f"SELECT COUNT(*) FROM {gw_trust.TABLE}").fetchone()
    assert rows[0] == 0


def test_evidence_stores_no_content_and_no_credential(store):
    """The table's columns are the guarantee: there is nowhere to put a secret."""
    cols = {row[1] for row in
            store.execute(f"PRAGMA table_info({gw_trust.TABLE})").fetchall()}
    for forbidden in ("text", "content", "message", "secret", "token",
                      "authorization", "payload", "owner_address", "wallet"):
        assert forbidden not in cols


def test_a_successful_request_is_positive_evidence(store):
    issued = _issue(store, days_ago=30)
    peer = issued.record.peer_id
    before = _assess(store, peer)
    _successes(store, peer, 20)
    after = _assess(store, peer)
    assert after.trust_score > before.trust_score


def test_negative_behaviour_lowers_the_assessment(store):
    issued = _issue(store, days_ago=30)
    peer = issued.record.peer_id
    _successes(store, peer, 20)
    good = _assess(store, peer)

    for _ in range(4):
        gw_trust.record_event(store, peer_id=peer,
                              event_type=gw_trust.EV_AUTHORIZATION_DENIED,
                              now=NOW)
    store.commit()
    bad = _assess(store, peer)

    assert bad.trust_score < good.trust_score
    assert bad.rank <= good.rank


def test_a_replay_attempt_weighs_more_than_a_rate_limit(store):
    """A reused messageId is deliberate. A 429 is usually just enthusiasm."""
    assert (gw_trust.NEGATIVE_WEIGHTS[gw_trust.EV_REPLAY_REJECTED]
            > gw_trust.NEGATIVE_WEIGHTS[gw_trust.EV_RATE_LIMITED])


def test_sustained_misbehaviour_makes_a_peer_untrusted_despite_good_history(store):
    """Good behaviour does not buy the right to misbehave."""
    issued = _issue(store, days_ago=60)
    peer = issued.record.peer_id
    _successes(store, peer, 25)
    for _ in range(5):
        gw_trust.record_event(store, peer_id=peer,
                              event_type=gw_trust.EV_REPLAY_REJECTED, now=NOW)
    store.commit()
    assert _assess(store, peer).trust_level == gw_trust.LEVEL_UNTRUSTED


def test_mixed_history_lands_between_the_extremes(store):
    issued = _issue(store, days_ago=30)
    clean = issued.record.peer_id
    _successes(store, clean, 20)

    mixed_issued = _issue(store, days_ago=30)
    mixed = mixed_issued.record.peer_id
    _successes(store, mixed, 20)
    gw_trust.record_event(store, peer_id=mixed,
                          event_type=gw_trust.EV_INVALID_REQUEST, now=NOW)
    store.commit()

    assert _assess(store, mixed).trust_score < _assess(store, clean).trust_score
    assert _assess(store, mixed).trust_score > 0.0


def test_an_aera_internal_error_is_not_charged_to_the_peer(store):
    """A 500 is our bug. Charging the peer would let a defect destroy standing."""
    from a2a_gateway.constants import ERR_INTERNAL
    from a2a_gateway.handler import _evidence_event

    assert _evidence_event("internal_error", ERR_INTERNAL, False) is None


def test_outcome_mapping_distinguishes_a_replay_from_a_malformed_request(store):
    from a2a_gateway.constants import ERR_INVALID_REQUEST
    from a2a_gateway.handler import _evidence_event

    assert _evidence_event("rejected", ERR_INVALID_REQUEST, True) == \
        gw_trust.EV_REPLAY_REJECTED
    assert _evidence_event("rejected", ERR_INVALID_REQUEST, False) == \
        gw_trust.EV_INVALID_REQUEST


# --------------------------------------------------------------------------- #
# C. trust level vs confidence
# --------------------------------------------------------------------------- #
def test_a_brand_new_peer_is_unknown_not_trusted(store):
    """Absence of negative evidence is not positive evidence."""
    issued = _issue(store)
    assessment = _assess(store, issued.record.peer_id)
    assert assessment.trust_level == gw_trust.LEVEL_UNKNOWN
    assert assessment.confidence < gw_trust.MIN_CONFIDENCE_FOR_OPINION


def test_a_new_peer_never_reaches_established_however_good_its_context(store):
    """The confidence gate, stated as a property rather than a threshold."""
    summary = gw_trust.EvidenceSummary(peer_id="peer_new", counts={})
    creds = gw_trust.CredentialFacts(
        total=1, active=1, earliest_issued_at=NOW - timedelta(days=400))
    owner = gw_trust.OwnerStanding(known=True, identity_active=True, score=200.0)
    assessment = gw_trust.assess(summary, creds, owner, now=NOW)
    assert assessment.trust_level != gw_trust.LEVEL_ESTABLISHED


def test_context_alone_never_clears_the_confidence_floor(store):
    """The gate must BITE, not merely exist.

    This peer has everything except behaviour: an old relationship, a perfect
    owner, a credential that has actually been used, multiple credentials. Its
    *score* is respectable. It has never been observed doing anything, so AEra
    has no opinion and must say so.
    """
    summary = gw_trust.EvidenceSummary(peer_id="peer_silent", counts={})
    creds = gw_trust.CredentialFacts(
        total=3, active=1, earliest_issued_at=NOW - timedelta(days=900),
        last_used_at=NOW)
    owner = gw_trust.OwnerStanding(known=True, identity_active=True, score=200.0)
    assessment = gw_trust.assess(summary, creds, owner, now=NOW)

    assert assessment.trust_score >= gw_trust.SCORE_MINIMAL, (
        "precondition: context alone must produce a score that WOULD earn a "
        "level, otherwise this test proves nothing about the gate")
    assert assessment.confidence < gw_trust.MIN_CONFIDENCE_FOR_OPINION
    assert assessment.trust_level == gw_trust.LEVEL_UNKNOWN


def test_a_burst_of_successes_does_not_reach_established_on_its_own(store):
    """Volume is not the same as a track record.

    Twenty-five successes in a single instant produce a high score and decent
    confidence -- but no observation *span*, so the evidence is a snapshot
    rather than a history. `established` requires the stronger confidence, so
    this peer stops at `limited`.
    """
    summary = gw_trust.EvidenceSummary(
        peer_id="peer_burst",
        counts={gw_trust.EV_REQUEST_SUCCESS: 25},
        distinct_agents=3, first_seen=NOW, last_seen=NOW)
    creds = gw_trust.CredentialFacts(
        total=2, active=1, earliest_issued_at=NOW - timedelta(days=90))
    owner = gw_trust.OwnerStanding(known=True, identity_active=True, score=200.0)
    assessment = gw_trust.assess(summary, creds, owner, now=NOW)

    assert assessment.trust_score >= gw_trust.SCORE_ESTABLISHED, (
        "precondition: the score must clear the established threshold, so that "
        "only the confidence gate can be what holds this peer back")
    assert assessment.confidence < gw_trust.MIN_CONFIDENCE_FOR_ESTABLISHED
    assert assessment.trust_level == gw_trust.LEVEL_LIMITED


def test_a_sustained_track_record_does_reach_established(store):
    """The counterpart: the gates must not make the top level unreachable."""
    summary = gw_trust.EvidenceSummary(
        peer_id="peer_good",
        counts={gw_trust.EV_REQUEST_SUCCESS: 25},
        distinct_agents=3,
        first_seen=NOW - timedelta(days=25), last_seen=NOW)
    creds = gw_trust.CredentialFacts(
        total=2, active=1, earliest_issued_at=NOW - timedelta(days=90),
        last_used_at=NOW)
    owner = gw_trust.OwnerStanding(known=True, identity_active=True, score=120.0)
    assessment = gw_trust.assess(summary, creds, owner, now=NOW)
    assert assessment.trust_level == gw_trust.LEVEL_ESTABLISHED


def test_more_evidence_raises_confidence(store):
    thin = _issue(store, days_ago=30)
    _successes(store, thin.record.peer_id, 2, spread_days=1.0)
    thick = _issue(store, days_ago=30)
    _successes(store, thick.record.peer_id, 25, spread_days=25.0)

    assert (_assess(store, thick.record.peer_id).confidence
            > _assess(store, thin.record.peer_id).confidence)


def test_confidence_and_level_are_independent_numbers(store):
    issued = _issue(store, days_ago=60)
    peer = issued.record.peer_id
    _successes(store, peer, 25, spread_days=25.0)
    for _ in range(3):
        gw_trust.record_event(store, peer_id=peer,
                              event_type=gw_trust.EV_AUTHORIZATION_DENIED,
                              now=NOW)
    store.commit()
    assessment = _assess(store, peer)
    # Plenty of evidence, and what it says is not flattering.
    assert assessment.confidence >= gw_trust.MIN_CONFIDENCE_FOR_OPINION
    assert assessment.rank < gw_trust.level_rank(gw_trust.LEVEL_ESTABLISHED)


def test_the_owner_view_never_exposes_the_raw_score_or_weights(store):
    issued = _issue(store, days_ago=30)
    _successes(store, issued.record.peer_id, 20)
    view = _assess(store, issued.record.peer_id).to_owner_dict()
    assert "trust_score" not in view
    assert "factors" not in view
    assert view["owner_settable"] is False
    assert view["assessed_by"] == "aera"


# --------------------------------------------------------------------------- #
# D. decay
# --------------------------------------------------------------------------- #
def test_trust_decays_when_a_peer_goes_quiet(store):
    active = _issue(store, days_ago=90)
    _successes(store, active.record.peer_id, 25, spread_days=25.0, end_days_ago=0)

    dormant = _issue(store, days_ago=90)
    _successes(store, dormant.record.peer_id, 25, spread_days=25.0,
               end_days_ago=80)

    assert (_assess(store, dormant.record.peer_id).trust_score
            < _assess(store, active.record.peer_id).trust_score)


def test_decay_has_a_floor_and_never_goes_negative(store):
    assert 0.0 < gw_trust.DECAY_FLOOR < 1.0
    ancient = gw_trust._decay_multiplier(NOW - timedelta(days=4000), NOW)
    assert ancient == pytest.approx(gw_trust.DECAY_FLOOR)


def test_recent_activity_is_not_decayed(store):
    assert gw_trust._decay_multiplier(NOW - timedelta(days=1), NOW) == 1.0


def test_a_peer_that_was_never_seen_gets_the_decayed_multiplier(store):
    """"Never observed" must not be treated as "observed just now".

    Distinct from the dormant case above: there `last_seen` is old, here it is
    absent entirely. A peer AEra has never actually served should not collect
    the full positive weight of its relationship age and its owner's standing
    as if it had a spotless recent record -- it has no record.
    """
    assert gw_trust._decay_multiplier(None, NOW) == pytest.approx(
        gw_trust.DECAY_FLOOR)


def test_an_unobserved_peer_scores_below_an_identical_active_one(store):
    """The same property, stated end-to-end rather than on the helper."""
    creds = gw_trust.CredentialFacts(
        total=2, active=1, earliest_issued_at=NOW - timedelta(days=90))
    owner = gw_trust.OwnerStanding(known=True, identity_active=True, score=200.0)

    never_seen = gw_trust.assess(
        gw_trust.EvidenceSummary(peer_id="peer_quiet", counts={}),
        creds, owner, now=NOW)
    active = gw_trust.assess(
        gw_trust.EvidenceSummary(
            peer_id="peer_busy", counts={gw_trust.EV_REQUEST_SUCCESS: 5},
            first_seen=NOW - timedelta(days=5), last_seen=NOW),
        creds, owner, now=NOW)

    assert never_seen.trust_score < active.trust_score
    assert never_seen.decay_multiplier < 1.0


# --------------------------------------------------------------------------- #
# E. credential rotation and peer identity
# --------------------------------------------------------------------------- #
def test_credential_rotation_preserves_the_peers_history(store):
    first = _issue(store, days_ago=40)
    peer = first.record.peer_id
    _successes(store, peer, 20)
    before = _assess(store, peer)

    # Rotation: issue a second credential for the SAME peer, revoke the first.
    second = _issue(store, peer_id=peer)
    gw_cred.revoke_credential(store, cred_id=first.record.cred_id,
                              owner_address="0xowner", reason="rotation")
    store.commit()

    after = _assess(store, peer)
    assert second.record.peer_id == peer
    assert after.evidence_counts == before.evidence_counts
    assert after.evidence_counts[gw_trust.EV_REQUEST_SUCCESS] == 20


def test_a_new_credential_does_not_create_a_new_trust_identity(store):
    first = _issue(store, days_ago=40)
    peer = first.record.peer_id
    _successes(store, peer, 20)
    _issue(store, peer_id=peer)

    peers = {row[0] for row in
             store.execute("SELECT DISTINCT peer_id FROM a2a_peer_credentials")}
    assert peers == {peer}


def test_two_credentials_for_one_peer_share_one_assessment(store):
    first = _issue(store, days_ago=40)
    peer = first.record.peer_id
    second = _issue(store, peer_id=peer)

    gw_trust.record_event(store, peer_id=peer,
                          credential_id=first.record.cred_id,
                          event_type=gw_trust.EV_REQUEST_SUCCESS, now=NOW)
    gw_trust.record_event(store, peer_id=peer,
                          credential_id=second.record.cred_id,
                          event_type=gw_trust.EV_REQUEST_SUCCESS, now=NOW)
    store.commit()
    assert _assess(store, peer).evidence_counts[gw_trust.EV_REQUEST_SUCCESS] == 2


def test_separate_peers_do_not_share_history(store):
    a = _issue(store, days_ago=40)
    b = _issue(store, days_ago=40)
    _successes(store, a.record.peer_id, 20)
    assert _assess(store, b.record.peer_id).evidence_counts == {}


def test_revoked_credentials_count_against_the_peer(store):
    clean = _issue(store, days_ago=40)
    _successes(store, clean.record.peer_id, 20)

    troubled = _issue(store, days_ago=40)
    _successes(store, troubled.record.peer_id, 20)
    for _ in range(2):
        extra = _issue(store, peer_id=troubled.record.peer_id)
        gw_cred.revoke_credential(store, cred_id=extra.record.cred_id,
                                  owner_address="0xowner", reason="compromised")
    store.commit()

    assert (_assess(store, troubled.record.peer_id).trust_score
            < _assess(store, clean.record.peer_id).trust_score)


# --------------------------------------------------------------------------- #
# F. owner standing is ONE input, never the decision
# --------------------------------------------------------------------------- #
def test_owner_standing_alone_cannot_establish_trust(store):
    """The whole point of an AEra-derived assessment of the PEER."""
    summary = gw_trust.EvidenceSummary(peer_id="peer_z", counts={})
    creds = gw_trust.CredentialFacts(total=3, active=1,
                                     earliest_issued_at=NOW - timedelta(days=900),
                                     last_used_at=NOW)
    perfect_owner = gw_trust.OwnerStanding(known=True, identity_active=True,
                                           score=200.0)
    assessment = gw_trust.assess(summary, creds, perfect_owner, now=NOW)
    assert assessment.trust_level != gw_trust.LEVEL_ESTABLISHED
    assert assessment.trust_score < gw_trust.SCORE_ESTABLISHED


def test_owner_standing_is_capped_below_the_majority_of_the_weight(store):
    positives = (gw_trust.W_SUCCESS + gw_trust.W_RELATIONSHIP_AGE
                 + gw_trust.W_OWNER_STANDING + gw_trust.W_AGENT_BREADTH
                 + gw_trust.W_CONTINUITY)
    assert positives == pytest.approx(1.0)
    assert gw_trust.W_OWNER_STANDING < 0.5 * positives


def test_owner_standing_does_contribute_something(store):
    summary = gw_trust.EvidenceSummary(
        peer_id="p", counts={gw_trust.EV_REQUEST_SUCCESS: 10},
        first_seen=NOW - timedelta(days=10), last_seen=NOW)
    creds = gw_trust.CredentialFacts(total=1, active=1,
                                     earliest_issued_at=NOW - timedelta(days=10))
    low = gw_trust.assess(summary, creds, gw_trust.OwnerStanding(), now=NOW)
    high = gw_trust.assess(summary, creds,
                           gw_trust.OwnerStanding(known=True,
                                                  identity_active=True,
                                                  score=200.0), now=NOW)
    assert high.trust_score > low.trust_score


def test_an_unknown_owner_contributes_zero_not_a_default(store):
    assert gw_trust.OwnerStanding().normalised() == 0.0


def test_owner_standing_is_read_from_aera_not_from_the_request(store):
    """There is no parameter by which a caller could supply owner standing."""
    import inspect
    params = set(inspect.signature(gw_trust.owner_standing).parameters)
    assert params == {"conn", "owner_address"}


# --------------------------------------------------------------------------- #
# G. trust never overrides authentication or authorization
# --------------------------------------------------------------------------- #
def test_verify_credential_never_consults_trust(store):
    source = (GATEWAY_DIR / "credentials.py").read_text(encoding="utf-8")
    assert "import trust" not in source
    assert "from .trust" not in source


def test_a_revoked_credential_is_refused_however_trusted_the_peer(store):
    """Revocation outranks trust.

    `now=NOW` is not decoration. Without it, verification runs against the real
    wall clock, the fixture's back-dated credential is already past its expiry,
    and the test passes because of expiry while claiming to prove revocation --
    which is how a broken revocation check would have slipped through.
    """
    issued = _issue(store, days_ago=10)
    peer = issued.record.peer_id
    _successes(store, peer, 25, spread_days=9.0)
    gw_cred.touch(store, issued.record.cred_id, now=NOW)
    store.commit()

    # Precondition: while active, this credential verifies at NOW.
    assert gw_cred.verify_credential(store, issued.plaintext, now=NOW)

    gw_cred.revoke_credential(store, cred_id=issued.record.cred_id,
                              owner_address="0xowner", now=NOW)
    store.commit()

    with pytest.raises(gw_cred.CredentialError) as exc:
        gw_cred.verify_credential(store, issued.plaintext, now=NOW)
    assert exc.value.reason == "revoked"


def test_an_expired_credential_is_refused_however_trusted_the_peer(store):
    issued = _issue(store, days_ago=90)
    peer = issued.record.peer_id
    _successes(store, peer, 25, spread_days=25.0)
    store.execute("UPDATE a2a_peer_credentials SET expires_at = ? "
                  "WHERE cred_id = ?",
                  ("2020-01-01T00:00:00Z", issued.record.cred_id))
    store.commit()
    with pytest.raises(gw_cred.CredentialError) as exc:
        gw_cred.verify_credential(store, issued.plaintext, now=NOW)
    assert exc.value.reason == "expired"


def test_authorize_request_ignores_trust_entirely(store):
    """Scope is the owner's decision; trust may not widen it."""
    import inspect
    source = inspect.getsource(gw_cred.authorize_request)
    assert "trust" not in source.lower().replace("untrusted", "")


def test_trust_does_not_enforce_authorization_in_this_phase(store):
    assert gw_trust.trust_enforces_authorization() is False


def test_the_handler_never_lets_trust_change_a_response(store):
    """`_observe_peer` runs in `finally` and its return value only reaches audit."""
    source = (GATEWAY_DIR / "handler.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    func = next(n for n in ast.walk(tree)
                if isinstance(n, ast.FunctionDef) and n.name == "_observe_peer")
    returns = [n for n in ast.walk(func) if isinstance(n, ast.Return)]
    assert returns, "_observe_peer must return the audit view"
    # It must not raise: every path is wrapped, so a broken trust layer cannot
    # turn a good request into a 500.
    assert not [n for n in ast.walk(func) if isinstance(n, ast.Raise)]


def test_trust_is_not_consulted_before_authentication(store):
    """Ordering property: no trust call may precede authenticate_request."""
    source = (GATEWAY_DIR / "handler.py").read_text(encoding="utf-8")
    body = source.split("def handle_request", 1)[1].split("def _evidence_event", 1)[0]
    auth_at = body.index("authenticate_request(headers")
    for marker in ("assess_peer", "record_event", "_observe_peer"):
        if marker in body:
            assert body.index(marker) > auth_at, f"{marker} precedes authentication"


# --------------------------------------------------------------------------- #
# H. trust never promotes LEVEL 3 to LEVEL 2
# --------------------------------------------------------------------------- #
def test_the_highest_trust_level_is_still_not_an_aera_agent(store):
    issued = _issue(store, days_ago=365)
    peer_id = issued.record.peer_id
    _successes(store, peer_id, 25, spread_days=25.0, agent="agent-a")
    _successes(store, peer_id, 25, spread_days=25.0, agent="agent-b")
    gw_cred.touch(store, issued.record.cred_id, now=NOW)
    _issue(store, peer_id=peer_id)
    store.commit()

    assessment = _assess(store, peer_id)
    identity = gw_peer.authenticated_peer(issued.record)

    assert assessment.rank >= gw_trust.level_rank(gw_trust.LEVEL_LIMITED)
    assert identity.is_trusted_aera_agent is False


def _code_strings_and_names(path: Path) -> set[str]:
    """Every identifier and string literal that is actually executed.

    Docstrings and comments are excluded on purpose: this file is allowed to
    *explain* the boundaries it must not cross, and a test that forbade the
    explanation would punish the documentation rather than the code.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                             ast.AsyncFunctionDef)):
            doc = ast.get_docstring(node, clean=False)
            if doc:
                docstrings.add(doc)
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            out.add(node.id)
        elif isinstance(node, ast.Attribute):
            out.add(node.attr)
        elif isinstance(node, ast.alias):
            out.add(node.name)
            if node.asname:
                out.add(node.asname)
        elif isinstance(node, ast.ImportFrom) and node.module:
            out.add(node.module)
        elif isinstance(node, ast.arg):
            out.add(node.arg)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            if node.value not in docstrings:
                out.add(node.value)
    return out


def test_trust_module_never_touches_the_agent_identity_layer(store):
    code = _code_strings_and_names(GATEWAY_DIR / "trust.py")
    for forbidden in ("AGENT_JWT_SECRET", "agent_jti", "agent_keys",
                      "agent_challenges", "AUDIENCE_ALLOWLIST",
                      "is_trusted_aera_agent", "tokens"):
        assert forbidden not in code, f"trust.py uses {forbidden}"


def test_the_assessment_carries_no_agent_identity_material(store):
    issued = _issue(store, days_ago=30)
    _successes(store, issued.record.peer_id, 20)
    payload = str(_assess(store, issued.record.peer_id).to_internal_dict())
    for forbidden in ("eyJ", "aera_a2a_", "BEGIN", "secret"):
        assert forbidden not in payload


# --------------------------------------------------------------------------- #
# I. anonymous callers
# --------------------------------------------------------------------------- #
def test_an_anonymous_caller_has_no_assessment(store):
    assert gw_trust.assess_peer(store, None) is None
    assert gw_trust.assess_peer(store, "") is None


def test_an_anonymous_caller_cannot_write_evidence(store):
    assert gw_trust.record_event(store, peer_id=None,
                                 event_type=gw_trust.EV_REQUEST_SUCCESS) is False
    assert gw_trust.record_event(store, peer_id="",
                                 event_type=gw_trust.EV_REQUEST_SUCCESS) is False
    assert store.execute(f"SELECT COUNT(*) FROM {gw_trust.TABLE}").fetchone()[0] == 0


def test_an_anonymous_peer_identity_has_no_peer_id(store):
    anon = gw_peer.anonymous_peer("i-am-important")
    assert anon.peer_id is None
    assert anon.is_authenticated is False


def _keepalive(conn):
    """Hand `_observe_peer` a connection it may close without killing the fixture.

    `_observe_peer` owns and closes whatever the factory gives it -- correctly,
    since in production it opens its own. The test therefore lends it a proxy
    whose `close()` is a no-op, so the assertions afterwards can still read the
    same in-memory database.
    """
    class _Lent:
        def __getattr__(self, name):
            return getattr(conn, name)

        def close(self):
            pass

    return _Lent()


def test_the_handler_writes_no_evidence_for_an_anonymous_caller(store):
    """The guard in `_observe_peer`, exercised rather than assumed.

    Tested through the handler's own helper with a real store, because the
    property that matters is not "the source contains an if" but "nothing is
    written". An anonymous flood must not be able to grow this table.
    """
    from a2a_gateway.handler import _observe_peer

    class _Inbound:
        target_agent_id = "agent-a"
        skill_id = "agent.read.profile"

    view = _observe_peer(gw_peer.anonymous_peer("pretty-please"),
                         conn_factory=lambda: _keepalive(store),
                         inbound=_Inbound(), result_label="success",
                         error_code=None, replay_rejected=False)

    assert view is None
    assert store.execute(
        f"SELECT COUNT(*) FROM {gw_trust.TABLE}").fetchone()[0] == 0


def test_an_anonymous_caller_never_reaches_the_evidence_store_at_all(store):
    """A tripwire, not an outcome check.

    `record_event` refuses a missing peer_id too, so "no row was written" is
    satisfied by either guard and cannot tell us the handler's own guard is
    intact. Two layers is the right design, but it means the outcome test alone
    would still pass with the outer guard deleted.

    This asserts the stronger, structural property: for an anonymous caller the
    handler never opens a connection in the first place. That is what keeps
    unauthenticated traffic from costing AEra any database I/O.
    """
    from a2a_gateway.handler import _observe_peer

    opened = []

    def tripwire():
        opened.append(True)
        return _keepalive(store)

    class _Inbound:
        target_agent_id = "agent-a"
        skill_id = "agent.read.profile"

    _observe_peer(gw_peer.anonymous_peer(), conn_factory=tripwire,
                  inbound=_Inbound(), result_label="success",
                  error_code=None, replay_rejected=False)

    assert opened == [], "anonymous traffic opened a database connection"


def test_the_handler_does_write_evidence_for_an_authenticated_peer(store):
    """The counterpart, so the guard above cannot be satisfied by a no-op."""
    from a2a_gateway.handler import _observe_peer

    issued = _issue(store)
    identity = gw_peer.authenticated_peer(issued.record)

    class _Inbound:
        target_agent_id = "agent-a"
        skill_id = "agent.read.profile"

    _observe_peer(identity, conn_factory=lambda: _keepalive(store),
                  inbound=_Inbound(), result_label="success",
                  error_code=None, replay_rejected=False)

    rows = store.execute(
        f"SELECT peer_id, event_type FROM {gw_trust.TABLE}").fetchall()
    assert len(rows) == 1
    assert rows[0][0] == issued.record.peer_id
    assert rows[0][1] == gw_trust.EV_REQUEST_SUCCESS


# --------------------------------------------------------------------------- #
# J. bounded storage
# --------------------------------------------------------------------------- #
#
# Two genuinely different properties, deliberately tested apart:
#
#   1. the configured cap is itself small enough to bound anything  (policy)
#   2. pruning actually enforces whatever cap is configured         (mechanism)
#
# They used to be one test that looped `MAX_EVIDENCE_PER_PEER + 50` times. That
# test derived its own cost from the very constant under test, so raising the
# cap raised the runtime with it -- at 10_000_000 the suite ran for 28 minutes
# without finishing. Worse, it never checked (1) at all: an absurd cap passed,
# slowly. Splitting them tests strictly more and costs constant time.

def test_the_configured_evidence_cap_is_small_enough_to_bound_storage():
    """Property 1: the number itself. A cap of ten million bounds nothing.

    This is what makes unbounded-growth impossible in production, and it is
    checked directly rather than inferred from a loop.
    """
    assert 0 < gw_trust.MAX_EVIDENCE_PER_PEER <= 10_000


def test_evidence_per_peer_is_capped(store, monkeypatch):
    """Property 2: the mechanism enforces whatever cap is configured.

    The cap is patched to a small value so the cost of this test is constant
    and independent of the production setting.
    """
    monkeypatch.setattr(gw_trust, "MAX_EVIDENCE_PER_PEER", 20)
    issued = _issue(store)
    peer = issued.record.peer_id
    for _ in range(gw_trust.MAX_EVIDENCE_PER_PEER + 50):
        gw_trust.record_event(store, peer_id=peer,
                              event_type=gw_trust.EV_REQUEST_SUCCESS, now=NOW)
    store.commit()
    count = store.execute(f"SELECT COUNT(*) FROM {gw_trust.TABLE} "
                          "WHERE peer_id = ?", (peer,)).fetchone()[0]
    assert count <= gw_trust.MAX_EVIDENCE_PER_PEER


def test_the_cap_keeps_the_newest_evidence_not_the_oldest(store, monkeypatch):
    """Pruning must discard history, not the present.

    Dropping the newest rows would make a peer's recent behaviour invisible --
    which is precisely the behaviour an attacker would want flushed.
    """
    monkeypatch.setattr(gw_trust, "MAX_EVIDENCE_PER_PEER", 5)
    issued = _issue(store)
    peer = issued.record.peer_id
    for day in range(20):
        gw_trust.record_event(store, peer_id=peer,
                              event_type=gw_trust.EV_REQUEST_SUCCESS,
                              target_agent_id=f"agent-{day}",
                              now=NOW - timedelta(days=20 - day))
    store.commit()
    rows = store.execute(
        f"SELECT target_agent_id FROM {gw_trust.TABLE} WHERE peer_id = ? "
        "ORDER BY id", (peer,)).fetchall()
    kept = [r[0] for r in rows]
    assert len(kept) <= 5
    assert "agent-19" in kept, "the most recent evidence was discarded"
    assert "agent-0" not in kept, "the oldest evidence was retained"


def test_the_configured_ttl_is_short_enough_to_bound_retention():
    """Policy: the retention window itself.

    Same failure mode as the cap above. A test that asks "is evidence older
    than EVIDENCE_TTL_DAYS pruned?" moves its own goalposts when the constant
    changes: set the TTL to 100_000 days and the test dutifully backdates a row
    by 100_005 days and still passes, while production now retains evidence for
    274 years. The number has to be checked as a number.
    """
    assert 0 < gw_trust.EVIDENCE_TTL_DAYS <= 365


def test_evidence_older_than_the_ttl_is_pruned(store, monkeypatch):
    """Mechanism: pruning enforces whatever TTL is configured."""
    monkeypatch.setattr(gw_trust, "EVIDENCE_TTL_DAYS", 30)
    issued = _issue(store)
    peer = issued.record.peer_id
    gw_trust.record_event(store, peer_id=peer,
                          event_type=gw_trust.EV_REQUEST_SUCCESS,
                          now=NOW - timedelta(days=gw_trust.EVIDENCE_TTL_DAYS + 5))
    gw_trust.record_event(store, peer_id=peer,
                          event_type=gw_trust.EV_REQUEST_SUCCESS, now=NOW)
    store.commit()
    count = store.execute(f"SELECT COUNT(*) FROM {gw_trust.TABLE} "
                          "WHERE peer_id = ?", (peer,)).fetchone()[0]
    assert count == 1


def test_both_bounds_exist_because_either_alone_is_insufficient(store):
    assert gw_trust.EVIDENCE_TTL_DAYS > 0
    assert gw_trust.MAX_EVIDENCE_PER_PEER > 0


def test_a_broken_evidence_table_never_breaks_a_request(store):
    store.execute(f"DROP TABLE {gw_trust.TABLE}")
    store.commit()
    assert gw_trust.record_event(store, peer_id="peer_1",
                                 event_type=gw_trust.EV_REQUEST_SUCCESS) is False
    assert gw_trust.summarize_evidence(store, "peer_1").total_events == 0


# --------------------------------------------------------------------------- #
# K. no enumeration oracle
# --------------------------------------------------------------------------- #
def test_trust_observation_is_off_by_default(monkeypatch):
    monkeypatch.delenv("AERA_A2A_TRUST_MODE", raising=False)
    assert gw_trust.enforcement_mode() == gw_trust.ENFORCEMENT_OFF
    assert gw_trust.trust_is_observed() is False


def test_an_unrecognised_mode_falls_back_to_off(monkeypatch):
    monkeypatch.setenv("AERA_A2A_TRUST_MODE", "block-everything")
    assert gw_trust.enforcement_mode() == gw_trust.ENFORCEMENT_OFF


def test_there_is_no_blocking_mode_to_enable(store):
    source = (GATEWAY_DIR / "trust.py").read_text(encoding="utf-8")
    assert "ENFORCEMENT_BLOCK" not in source
    assert "ENFORCEMENT_ENFORCE" not in source


def test_no_external_error_message_mentions_trust(store):
    for name in ("handler.py", "routes.py", "credentials.py", "auth.py"):
        source = (GATEWAY_DIR / name).read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                lowered = node.value.lower()
                if "trust" in lowered and "untrusted" not in lowered:
                    # Comments and docstrings are fine; a message is not.
                    assert not lowered.startswith(("peer has", "insufficient trust")), \
                        f"{name} may leak trust in a message: {node.value!r}"


def test_the_agent_card_advertises_no_trust_information(store):
    from a2a_gateway.card import build_agent_card, card_is_safe_to_publish
    card = build_agent_card("https://example.test", runtime_available=False)
    safe, leaked = card_is_safe_to_publish(card)
    assert safe, leaked
    payload = str(card).lower()
    assert "trust_level" not in payload
    assert "trust_score" not in payload
    assert "peer_evidence" not in payload


def test_the_audit_view_is_minimal(store):
    issued = _issue(store, days_ago=30)
    _successes(store, issued.record.peer_id, 20)
    view = _assess(store, issued.record.peer_id).to_audit_dict()
    assert set(view) == {"level", "confidence", "policy"}


# --------------------------------------------------------------------------- #
# L. caller-supplied fields are ignored
# --------------------------------------------------------------------------- #
def test_no_caller_supplied_field_can_reach_the_trust_layer(store):
    """`record_event` and `assess` have no parameter a caller could populate."""
    import inspect
    record_params = set(inspect.signature(gw_trust.record_event).parameters)
    for forbidden in ("trust", "trusted", "reputation", "owner_trust",
                      "identity_status", "capabilities", "claimed_id",
                      "external_agent_id", "metadata", "params", "body"):
        assert forbidden not in record_params


def test_the_trust_layer_never_reads_the_message_or_its_metadata(store):
    code = _code_strings_and_names(GATEWAY_DIR / "trust.py")
    for forbidden in ("inbound", "params", "payload", "request", "headers",
                      "body", "text", "content", "message"):
        assert forbidden not in code, f"trust.py references {forbidden}"


def test_claimed_identity_is_not_part_of_the_evidence_key(store):
    """Evidence is keyed on the AEra-minted peer_id, never on what was claimed."""
    cols = {row[1] for row in
            store.execute(f"PRAGMA table_info({gw_trust.TABLE})").fetchall()}
    assert "peer_id" in cols
    assert "external_agent_id" not in cols
    assert "claimed_id" not in cols


# --------------------------------------------------------------------------- #
# M. the Agent Identity Layer is untouched
# --------------------------------------------------------------------------- #
def test_no_gateway_module_imports_agent_token_machinery(store):
    """No gateway module may READ the agent signing secret.

    `audit.py` legitimately contains the literal `AGENT_JWT_SECRET` -- as a
    scrubbing marker, so that the string is redacted if it ever appears in a
    log line. Naming a thing in order to destroy it is the opposite of using
    it, so the test looks for an actual read instead of a text match.
    """
    for path in sorted(GATEWAY_DIR.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                target = getattr(node.func, "attr", getattr(node.func, "id", ""))
                if target in ("getenv", "environ"):
                    for arg in node.args:
                        if isinstance(arg, ast.Constant):
                            assert arg.value != "AGENT_JWT_SECRET", path.name
            if isinstance(node, ast.ImportFrom):
                assert node.module != "agent.tokens", path.name


def test_the_trust_table_is_separate_from_every_agent_table(store):
    assert gw_trust.TABLE == "a2a_peer_evidence"
    assert not gw_trust.TABLE.startswith("agent")
