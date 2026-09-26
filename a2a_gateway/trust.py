"""AEra's own assessment of an external A2A peer (LEVEL 3).

WHAT THIS IS
------------
An answer, derived by AEra from evidence AEra itself observed, to the question:

    "How much trust should AEra currently place in this external peer?"

WHAT THIS IS NOT
----------------
It is not a flag an owner may set. It is not an authentication result. It is
not a permission. It is not a Resonance Score, and it does not turn a peer into
an AEra agent -- `ExternalPeerIdentity.is_trusted_aera_agent` stays False at
every trust level, forever.

The distinction that makes this layer honest:

    authentication  -> "who is calling"        (credentials.verify_credential)
    authorization   -> "what may they do"      (credentials.authorize_request)
    trust           -> "how much do we believe them"   (here)

Each is computed separately and none may be substituted for another. In
particular, a high assessment can never revive a revoked or expired credential:
this module is never consulted during verification at all.

WHY EVIDENCE AND NOT AN OWNER FLAG
----------------------------------
An owner flag records an intention. It cannot notice that the peer it vouched
for started replaying messages last Tuesday. Only observation can. Owner
standing is therefore *one bounded input* (see `W_OWNER_STANDING`, capped so it
can never decide the outcome alone) and never the decision.

WHAT IS OBSERVED
----------------
Only security metadata about requests that were already authenticated -- so an
anonymous or unauthenticated caller can write nothing here, and cannot create
a trust identity by sending traffic. Never message content, never a credential,
never a key, never a header.

TRUST LEVEL VS CONFIDENCE
-------------------------
Deliberately two numbers, because they answer different questions:

    trust level -- what does the evidence say?
    confidence  -- is there enough evidence to say anything?

A brand-new peer has no negative evidence, and that is emphatically not the
same as having positive evidence. A high level is therefore *gated* by
confidence (`MIN_CONFIDENCE_FOR_ESTABLISHED`), so silence can never be promoted
into a good reputation.
"""
from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

TABLE = "a2a_peer_evidence"

# --------------------------------------------------------------------------- #
# policy -- every constant that shapes an assessment lives in this block
# --------------------------------------------------------------------------- #
#: Bump this whenever any constant below, or the arithmetic that uses them,
#: changes. It is stored on every assessment so a past decision can be
#: explained by the policy that actually produced it, not by today's.
POLICY_VERSION = "aera-peer-trust-1"

#: Ordered trust levels. The order is the API -- callers compare, they do not
#: parse strings. `UNKNOWN` is deliberately *above* `UNTRUSTED` and *below*
#: everything else: it means "we have nothing to go on", which is a different
#: statement from "we have seen this peer misbehave".
LEVEL_UNTRUSTED = "untrusted"
LEVEL_UNKNOWN = "unknown"
LEVEL_MINIMAL = "minimal"
LEVEL_LIMITED = "limited"
LEVEL_ESTABLISHED = "established"

LEVEL_ORDER = (
    LEVEL_UNTRUSTED,
    LEVEL_UNKNOWN,
    LEVEL_MINIMAL,
    LEVEL_LIMITED,
    LEVEL_ESTABLISHED,
)


def level_rank(level: str) -> int:
    """Numeric rank for comparison. Unrecognised levels rank lowest."""
    try:
        return LEVEL_ORDER.index(level)
    except ValueError:
        return 0


# --- event vocabulary -------------------------------------------------------
# A closed set. An unknown event type is refused rather than stored, so a
# future careless caller cannot quietly invent a signal with no defined weight.
EV_REQUEST_SUCCESS = "request_success"
EV_AUTHORIZATION_DENIED = "authorization_denied"
EV_REPLAY_REJECTED = "replay_rejected"
EV_RATE_LIMITED = "rate_limited"
EV_INVALID_REQUEST = "invalid_request"

POSITIVE_EVENTS = frozenset({EV_REQUEST_SUCCESS})

#: How much each kind of bad behaviour counts against a peer, relative to one
#: another. These are ratios, not scores; the absolute effect is set by
#: `W_NEGATIVE` and `NEGATIVE_SATURATION` below.
#:
#: A replay attempt weighs most: a correctly implemented client does not reuse
#: a messageId by accident, so it is the clearest signal of deliberate probing.
#: Rate limiting weighs least: it is frequently just an enthusiastic client,
#: and the limiter has already dealt with it.
NEGATIVE_WEIGHTS = {
    EV_REPLAY_REJECTED: 2.0,
    EV_AUTHORIZATION_DENIED: 1.5,
    EV_INVALID_REQUEST: 1.0,
    EV_RATE_LIMITED: 0.5,
}

KNOWN_EVENTS = frozenset(POSITIVE_EVENTS | set(NEGATIVE_WEIGHTS))

# --- positive factor weights (these four sum to 1.0) ------------------------
#: Sustained successful use is the strongest thing a peer can do, and the only
#: factor it controls entirely by behaving well.
W_SUCCESS = 0.45
#: A relationship that has existed for a while is harder to fake than a burst.
W_RELATIONSHIP_AGE = 0.20
#: Owner standing is context, not peer behaviour, so it is capped at a fifth of
#: the positive weight. A peer cannot become `established` on its voucher's
#: reputation alone -- see `test_owner_standing_alone_cannot_establish_trust`.
W_OWNER_STANDING = 0.20
#: Serving several distinct agents is weak corroboration of genuine use.
W_AGENT_BREADTH = 0.08
#: The peer survived at least one credential rotation, i.e. an owner chose to
#: keep the relationship alive rather than let it lapse.
W_CONTINUITY = 0.07

#: Saturation points -- the value at which a factor is considered "full".
#: Beyond these, more of the same buys nothing, so a peer cannot farm trust by
#: sending a million trivial requests.
SUCCESS_SATURATION = 25
RELATIONSHIP_AGE_SATURATION_DAYS = 30.0
AGENT_BREADTH_SATURATION = 3
NEGATIVE_SATURATION = 10.0
REVOKED_SATURATION = 2

# --- negative factor weights ------------------------------------------------
W_NEGATIVE = 0.60
#: Credentials this peer held that an owner had to revoke. Revocation is a
#: human act with a reason attached, so it is meaningful evidence -- but it is
#: also sometimes routine rotation hygiene, hence the modest weight.
W_REVOKED_CREDENTIALS = 0.20

#: A negative burden at or above this point means AEra has direct evidence of
#: harmful behaviour, and the peer is `untrusted` regardless of how much good
#: history sits beside it. Good behaviour does not buy the right to misbehave.
UNTRUSTED_PENALTY_THRESHOLD = 0.35

# --- decay ------------------------------------------------------------------
#: Trust is not sticky. After this many days without observed activity the
#: positive side of the assessment starts to shrink, reaching `DECAY_FLOOR`
#: after `DECAY_FULL_DAYS`. A peer that was excellent two years ago and has not
#: been seen since is not currently established; it is currently unknown.
DECAY_GRACE_DAYS = 14.0
DECAY_FULL_DAYS = 90.0
DECAY_FLOOR = 0.40

# --- confidence -------------------------------------------------------------
C_VOLUME = 0.50
C_SPAN = 0.30
C_USED = 0.20
CONFIDENCE_VOLUME_SATURATION = 20
CONFIDENCE_SPAN_SATURATION_DAYS = 21.0

#: Below this, AEra declines to express an opinion at all: the level is
#: `unknown`, whatever the arithmetic says.
#:
#: The value is chosen so the gate actually bites. `C_USED` alone contributes
#: 0.20, so a peer whose credential has merely been used once -- with no
#: recorded behaviour whatsoever -- would clear a 0.20 threshold and collect a
#: level from context alone (age + owner standing). That is exactly the
#: "silence becomes a good reputation" failure this layer exists to prevent,
#: so the floor sits above what context can buy on its own. Confirmed
#: unreachable-without-behaviour by `test_context_alone_never_clears_the_
#: confidence_floor` and by the negative proof.
MIN_CONFIDENCE_FOR_OPINION = 0.35
#: The top level additionally requires that the evidence actually be strong.
MIN_CONFIDENCE_FOR_ESTABLISHED = 0.60

#: Score thresholds, applied only after the confidence gates above.
SCORE_ESTABLISHED = 0.70
SCORE_LIMITED = 0.45
SCORE_MINIMAL = 0.20

# --- storage bounds ---------------------------------------------------------
#: Evidence storage is bounded in two independent ways, because either one
#: alone fails: a TTL alone lets a flood inside the window grow without limit,
#: and a per-peer cap alone keeps rows for peers that vanished years ago.
EVIDENCE_TTL_DAYS = 90
MAX_EVIDENCE_PER_PEER = 500

# --- enforcement ------------------------------------------------------------
#: Part I found no evidence in the repository for what trust level any skill
#: should require, and inventing one would be exactly the guess this phase was
#: told not to make. Enforcement is therefore NOT implemented: the assessment
#: is produced and observable, and it changes no response.
#:
#:   off      (default) -- nothing is computed on the request path at all
#:   monitor            -- the assessment is computed and audited, and still
#:                         changes no response
#:
#: There is deliberately no third value. Adding a blocking mode is a product
#: decision with its own threat model, not a configuration flag.
ENFORCEMENT_OFF = "off"
ENFORCEMENT_MONITOR = "monitor"


def enforcement_mode() -> str:
    """Read the observation mode. Anything unrecognised means `off`."""
    value = (os.getenv("AERA_A2A_TRUST_MODE", "") or "").strip().lower()
    return ENFORCEMENT_MONITOR if value == ENFORCEMENT_MONITOR else ENFORCEMENT_OFF


def trust_is_observed() -> bool:
    return enforcement_mode() == ENFORCEMENT_MONITOR


def trust_enforces_authorization() -> bool:
    """Always False in this phase, and asserted by test and negative proof.

    Kept as an explicit function rather than an absent feature so that enabling
    enforcement later is a visible, reviewable edit rather than a side effect
    of someone adding an `if` to the handler.
    """
    return False


# --------------------------------------------------------------------------- #
# schema
# --------------------------------------------------------------------------- #
_SCHEMA = f"""
CREATE TABLE IF NOT EXISTS {TABLE} (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    peer_id         TEXT NOT NULL,
    credential_id   TEXT,
    target_agent_id TEXT,
    skill_id        TEXT,
    event_type      TEXT NOT NULL,
    outcome         TEXT NOT NULL,
    occurred_at     TEXT NOT NULL
)
"""

_INDEXES = (
    f"CREATE INDEX IF NOT EXISTS idx_a2a_evidence_peer ON {TABLE}(peer_id, occurred_at)",
    f"CREATE INDEX IF NOT EXISTS idx_a2a_evidence_time ON {TABLE}(occurred_at)",
)


def init_schema(conn: sqlite3.Connection) -> None:
    conn.execute(_SCHEMA)
    for statement in _INDEXES:
        conn.execute(statement)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    normalised = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalised)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


# --------------------------------------------------------------------------- #
# evidence capture
# --------------------------------------------------------------------------- #
def record_event(conn: sqlite3.Connection, *, peer_id: Optional[str],
                 event_type: str, outcome: str = "",
                 credential_id: Optional[str] = None,
                 target_agent_id: Optional[str] = None,
                 skill_id: Optional[str] = None,
                 now: Optional[datetime] = None) -> bool:
    """Persist one piece of security metadata about an authenticated peer.

    Returns False -- without writing anything -- when there is no authenticated
    peer to attribute the event to. That is the anonymous case, and it is the
    reason an anonymous flood cannot manufacture a trust identity or grow this
    table: no peer_id, no row.

    Only the closed vocabulary in `KNOWN_EVENTS` is accepted. Content, headers
    and credentials are not parameters of this function, so they cannot be
    stored by mistake.
    """
    if not peer_id or not isinstance(peer_id, str):
        return False
    if event_type not in KNOWN_EVENTS:
        return False

    moment = now or _now()
    try:
        conn.execute(
            f"INSERT INTO {TABLE} (peer_id, credential_id, target_agent_id, "
            "skill_id, event_type, outcome, occurred_at) VALUES (?,?,?,?,?,?,?)",
            (peer_id[:128],
             str(credential_id)[:128] if credential_id else None,
             str(target_agent_id)[:128] if target_agent_id else None,
             str(skill_id)[:128] if skill_id else None,
             event_type, str(outcome)[:64], _iso(moment)),
        )
    except sqlite3.Error:
        # Evidence collection must never fail a request that was otherwise
        # fine. A missing observation degrades the assessment's confidence,
        # which is the correct consequence, rather than a 500.
        return False

    prune_peer(conn, peer_id, now=moment)
    return True


def prune_peer(conn: sqlite3.Connection, peer_id: str, *,
               now: Optional[datetime] = None) -> int:
    """Enforce both storage bounds for one peer. Returns rows removed."""
    moment = now or _now()
    removed = 0
    try:
        cutoff = _iso(moment - timedelta(days=EVIDENCE_TTL_DAYS))
        cur = conn.execute(
            f"DELETE FROM {TABLE} WHERE peer_id = ? AND occurred_at < ?",
            (peer_id, cutoff))
        removed += cur.rowcount or 0

        # Keep the newest MAX_EVIDENCE_PER_PEER rows. Ordering by id rather
        # than occurred_at keeps this deterministic when many events share a
        # second, which is exactly what happens under a burst.
        cur = conn.execute(
            f"DELETE FROM {TABLE} WHERE peer_id = ? AND id NOT IN "
            f"(SELECT id FROM {TABLE} WHERE peer_id = ? ORDER BY id DESC LIMIT ?)",
            (peer_id, peer_id, MAX_EVIDENCE_PER_PEER))
        removed += cur.rowcount or 0
    except sqlite3.Error:
        return removed
    return removed


# --------------------------------------------------------------------------- #
# evidence summary
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class EvidenceSummary:
    """Everything observed about one peer, reduced to counts and timestamps."""

    peer_id: str
    counts: dict[str, int] = field(default_factory=dict)
    distinct_agents: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None

    @property
    def successes(self) -> int:
        return self.counts.get(EV_REQUEST_SUCCESS, 0)

    @property
    def total_events(self) -> int:
        return sum(self.counts.values())

    @property
    def negative_burden(self) -> float:
        """Negative events, weighted by kind. Not yet normalised."""
        return sum(NEGATIVE_WEIGHTS.get(name, 0.0) * count
                   for name, count in self.counts.items())


def summarize_evidence(conn: sqlite3.Connection, peer_id: str
                       ) -> EvidenceSummary:
    counts: dict[str, int] = {}
    distinct_agents = 0
    first_seen = last_seen = None
    try:
        rows = conn.execute(
            f"SELECT event_type, COUNT(*), MIN(occurred_at), MAX(occurred_at) "
            f"FROM {TABLE} WHERE peer_id = ? GROUP BY event_type",
            (peer_id,)).fetchall()
        for row in rows:
            counts[row[0]] = int(row[1])
            low, high = _parse_iso(row[2]), _parse_iso(row[3])
            if low and (first_seen is None or low < first_seen):
                first_seen = low
            if high and (last_seen is None or high > last_seen):
                last_seen = high
        row = conn.execute(
            f"SELECT COUNT(DISTINCT target_agent_id) FROM {TABLE} "
            "WHERE peer_id = ? AND target_agent_id IS NOT NULL "
            "AND event_type = ?", (peer_id, EV_REQUEST_SUCCESS)).fetchone()
        distinct_agents = int(row[0]) if row else 0
    except sqlite3.Error:
        pass
    return EvidenceSummary(peer_id=peer_id, counts=counts,
                           distinct_agents=distinct_agents,
                           first_seen=first_seen, last_seen=last_seen)


@dataclass(frozen=True)
class CredentialFacts:
    """Lifecycle facts about the credentials belonging to one peer.

    Read from `a2a_peer_credentials`, which already keys on `peer_id`. This is
    why rotation does not reset a peer: the credentials change, the peer_id
    does not, and both evidence and these facts are keyed on the peer.
    """

    total: int = 0
    active: int = 0
    revoked: int = 0
    owner_address: Optional[str] = None
    earliest_issued_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None


def credential_facts(conn: sqlite3.Connection, peer_id: str) -> CredentialFacts:
    from .credentials import STATUS_ACTIVE, STATUS_REVOKED
    from .credentials import TABLE as CRED_TABLE

    try:
        rows = conn.execute(
            f"SELECT status, issued_at, last_used_at, owner_address "
            f"FROM {CRED_TABLE} WHERE peer_id = ?", (peer_id,)).fetchall()
    except sqlite3.Error:
        return CredentialFacts()

    total = active = revoked = 0
    owner = None
    earliest = latest_use = None
    for row in rows:
        total += 1
        status = row[0]
        if status == STATUS_ACTIVE:
            active += 1
        elif status == STATUS_REVOKED:
            revoked += 1
        issued = _parse_iso(row[1])
        if issued and (earliest is None or issued < earliest):
            earliest = issued
        used = _parse_iso(row[2])
        if used and (latest_use is None or used > latest_use):
            latest_use = used
        if owner is None and row[3]:
            owner = row[3]
    return CredentialFacts(total=total, active=active, revoked=revoked,
                           owner_address=owner, earliest_issued_at=earliest,
                           last_used_at=latest_use)


@dataclass(frozen=True)
class OwnerStanding:
    """The issuing owner's own, independently verified standing.

    AEra already established this through wallet ownership, Identity NFT
    minting and on-chain score synchronisation. Nothing here is asserted by
    the peer, and nothing here is asserted by the owner either -- it is read
    from AEra's own `users` row.
    """

    known: bool = False
    identity_active: bool = False
    score: Optional[float] = None

    def normalised(self) -> float:
        """0.0 .. 1.0. An unknown owner contributes nothing, not a default."""
        if not self.known:
            return 0.0
        identity_part = 0.5 if self.identity_active else 0.0
        if self.score is None:
            return identity_part
        # 50 is the documented starting score, so only what is earned above it
        # counts. 200 is the top of the range `owner_gate_configs` validates.
        earned = _saturate(max(0.0, self.score - 50.0), 150.0)
        return identity_part + 0.5 * earned


def owner_standing(conn: sqlite3.Connection,
                   owner_address: Optional[str]) -> OwnerStanding:
    if not owner_address:
        return OwnerStanding()
    try:
        row = conn.execute(
            "SELECT score, blockchain_score, identity_status FROM users "
            "WHERE lower(address) = ?", (owner_address.lower(),)).fetchone()
    except sqlite3.Error:
        # The users table is part of the main application, not of this
        # gateway. If it is absent (unit tests, an isolated store) the owner is
        # simply unknown and contributes nothing.
        return OwnerStanding()
    if row is None:
        return OwnerStanding()

    def _num(value):
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    onchain = _num(row[1])
    offchain = _num(row[0])
    # Prefer the on-chain value: it is the one AEra verified against the chain
    # rather than the one it accumulated locally.
    score = onchain if (onchain is not None and onchain > 0) else offchain
    return OwnerStanding(known=True,
                         identity_active=(row[2] == "active"),
                         score=score)


# --------------------------------------------------------------------------- #
# assessment
# --------------------------------------------------------------------------- #
def _saturate(value: float, full: float) -> float:
    if full <= 0:
        return 0.0
    return max(0.0, min(1.0, float(value) / full))


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, value))


@dataclass(frozen=True)
class TrustFactor:
    """One named contribution, retained so the result can be explained."""

    name: str
    observed: Any
    normalised: float
    weight: float
    contribution: float
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "observed": self.observed,
            "normalised": round(self.normalised, 4),
            "weight": self.weight,
            "contribution": round(self.contribution, 4),
            "note": self.note,
        }


@dataclass(frozen=True)
class TrustAssessment:
    """AEra's current opinion of one external peer, with its reasoning."""

    peer_id: str
    trust_level: str
    trust_score: float
    confidence: float
    calculated_at: str
    policy_version: str
    factors: tuple[TrustFactor, ...] = ()
    evidence_counts: dict[str, int] = field(default_factory=dict)
    decay_multiplier: float = 1.0

    @property
    def rank(self) -> int:
        return level_rank(self.trust_level)

    def to_internal_dict(self) -> dict[str, Any]:
        """Full reasoning. For AEra's own logs and nothing else."""
        return {
            "peer_id": self.peer_id,
            "trust_level": self.trust_level,
            "trust_score": round(self.trust_score, 4),
            "confidence": round(self.confidence, 4),
            "decay_multiplier": round(self.decay_multiplier, 4),
            "calculated_at": self.calculated_at,
            "policy_version": self.policy_version,
            "evidence_counts": dict(self.evidence_counts),
            "factors": [f.to_dict() for f in self.factors],
        }

    def to_owner_dict(self) -> dict[str, Any]:
        """What the issuing owner may see. Read-only, and not settable.

        Deliberately omits the raw score and the individual weights: those are
        the tuning of a security control, and publishing them -- even to an
        owner -- turns the dashboard into a calculator for how much
        misbehaviour a peer can afford.
        """
        return {
            "peer_id": self.peer_id,
            "trust_level": self.trust_level,
            "confidence_band": _confidence_band(self.confidence),
            "calculated_at": self.calculated_at,
            "policy_version": self.policy_version,
            "assessed_by": "aera",
            "owner_settable": False,
            "observed_events": sum(self.evidence_counts.values()),
        }

    def to_audit_dict(self) -> dict[str, Any]:
        """The minimum that belongs in an inbound audit line."""
        return {
            "level": self.trust_level,
            "confidence": round(self.confidence, 2),
            "policy": self.policy_version,
        }


def _confidence_band(confidence: float) -> str:
    if confidence >= MIN_CONFIDENCE_FOR_ESTABLISHED:
        return "high"
    if confidence >= MIN_CONFIDENCE_FOR_OPINION:
        return "moderate"
    return "insufficient"


def _decay_multiplier(last_seen: Optional[datetime], now: datetime) -> float:
    """Shrink the positive side of an assessment that has gone quiet."""
    if last_seen is None:
        return DECAY_FLOOR
    idle_days = max(0.0, (now - last_seen).total_seconds() / 86400.0)
    if idle_days <= DECAY_GRACE_DAYS:
        return 1.0
    span = DECAY_FULL_DAYS - DECAY_GRACE_DAYS
    if span <= 0:
        return DECAY_FLOOR
    progress = min(1.0, (idle_days - DECAY_GRACE_DAYS) / span)
    return 1.0 - progress * (1.0 - DECAY_FLOOR)


def assess(summary: EvidenceSummary, creds: CredentialFacts,
           owner: OwnerStanding, *, now: Optional[datetime] = None
           ) -> TrustAssessment:
    """Pure, deterministic. Same inputs -> same assessment, always.

    Kept free of I/O so it can be tested exhaustively without a database, and
    so that no future edit can smuggle a network call into a trust decision.
    """
    moment = now or _now()
    factors: list[TrustFactor] = []

    # --- positive evidence -------------------------------------------------
    success_n = _saturate(summary.successes, SUCCESS_SATURATION)
    factors.append(TrustFactor(
        "successful_interactions", summary.successes, success_n, W_SUCCESS,
        success_n * W_SUCCESS,
        "authenticated requests AEra served without incident"))

    start = creds.earliest_issued_at or summary.first_seen
    age_days = max(0.0, (moment - start).total_seconds() / 86400.0) if start else 0.0
    age_n = _saturate(age_days, RELATIONSHIP_AGE_SATURATION_DAYS)
    factors.append(TrustFactor(
        "relationship_age_days", round(age_days, 2), age_n, W_RELATIONSHIP_AGE,
        age_n * W_RELATIONSHIP_AGE,
        "days since AEra first issued this peer a credential"))

    owner_n = owner.normalised()
    factors.append(TrustFactor(
        "owner_standing", {"known": owner.known,
                           "identity_active": owner.identity_active,
                           "score": owner.score},
        owner_n, W_OWNER_STANDING, owner_n * W_OWNER_STANDING,
        "standing of the AEra owner who vouched for this peer; context only, "
        "capped so it cannot decide the assessment alone"))

    breadth_n = _saturate(summary.distinct_agents, AGENT_BREADTH_SATURATION)
    factors.append(TrustFactor(
        "agent_breadth", summary.distinct_agents, breadth_n, W_AGENT_BREADTH,
        breadth_n * W_AGENT_BREADTH,
        "distinct AEra agents this peer has successfully reached"))

    continuity_n = 1.0 if (creds.total > 1 and creds.active > 0) else 0.0
    factors.append(TrustFactor(
        "credential_continuity", creds.total, continuity_n, W_CONTINUITY,
        continuity_n * W_CONTINUITY,
        "the relationship survived at least one credential rotation"))

    positive = sum(f.contribution for f in factors)

    # --- decay -------------------------------------------------------------
    decay = _decay_multiplier(summary.last_seen or creds.last_used_at, moment)
    positive *= decay

    # --- negative evidence -------------------------------------------------
    burden = summary.negative_burden
    burden_n = _saturate(burden, NEGATIVE_SATURATION)
    negative_penalty = burden_n * W_NEGATIVE
    factors.append(TrustFactor(
        "negative_events", round(burden, 2), burden_n, -W_NEGATIVE,
        -negative_penalty,
        "weighted authorization refusals, replay attempts, malformed requests "
        "and rate-limit violations"))

    revoked_n = _saturate(creds.revoked, REVOKED_SATURATION)
    revoked_penalty = revoked_n * W_REVOKED_CREDENTIALS
    factors.append(TrustFactor(
        "revoked_credentials", creds.revoked, revoked_n, -W_REVOKED_CREDENTIALS,
        -revoked_penalty,
        "credentials issued to this peer that an owner later revoked"))

    score = _clamp(positive - negative_penalty - revoked_penalty)

    # --- confidence --------------------------------------------------------
    volume_n = _saturate(summary.total_events, CONFIDENCE_VOLUME_SATURATION)
    span_days = 0.0
    if summary.first_seen and summary.last_seen:
        span_days = max(0.0, (summary.last_seen - summary.first_seen)
                        .total_seconds() / 86400.0)
    span_n = _saturate(span_days, CONFIDENCE_SPAN_SATURATION_DAYS)
    used_n = 1.0 if creds.last_used_at is not None else 0.0
    confidence = _clamp(volume_n * C_VOLUME + span_n * C_SPAN + used_n * C_USED)

    # --- level -------------------------------------------------------------
    level = _level_for(score, confidence,
                       negative_penalty + revoked_penalty)

    return TrustAssessment(
        peer_id=summary.peer_id,
        trust_level=level,
        trust_score=score,
        confidence=confidence,
        calculated_at=_iso(moment),
        policy_version=POLICY_VERSION,
        factors=tuple(factors),
        evidence_counts=dict(summary.counts),
        decay_multiplier=decay,
    )


def _level_for(score: float, confidence: float, penalty: float) -> str:
    """Map (score, confidence, penalty) onto a level. The gates are the point.

    Order matters. Direct evidence of harm outranks everything: a peer that has
    been caught replaying does not get to average that away against a large
    pile of successful requests. Only after that does insufficient evidence
    collapse to `unknown`, and only then is the score consulted.
    """
    if penalty >= UNTRUSTED_PENALTY_THRESHOLD:
        return LEVEL_UNTRUSTED
    if confidence < MIN_CONFIDENCE_FOR_OPINION:
        # Not "minimal". AEra has no opinion, and saying `minimal` would be an
        # opinion. Absence of negative evidence is not positive evidence.
        return LEVEL_UNKNOWN
    if score >= SCORE_ESTABLISHED and confidence >= MIN_CONFIDENCE_FOR_ESTABLISHED:
        return LEVEL_ESTABLISHED
    if score >= SCORE_LIMITED:
        return LEVEL_LIMITED
    if score >= SCORE_MINIMAL:
        return LEVEL_MINIMAL
    return LEVEL_UNKNOWN


def assess_peer(conn: sqlite3.Connection, peer_id: Optional[str], *,
                now: Optional[datetime] = None) -> Optional[TrustAssessment]:
    """Assess one peer from the store. Returns None for an anonymous caller.

    There is no assessment for anonymous traffic, and no placeholder one
    either: an anonymous caller has no stable identity to accumulate evidence
    against, so inventing a peer_id for it would be fiction.
    """
    if not peer_id:
        return None
    summary = summarize_evidence(conn, peer_id)
    creds = credential_facts(conn, peer_id)
    owner = owner_standing(conn, creds.owner_address)
    return assess(summary, creds, owner, now=now)


def assess_peers_for_owner(conn: sqlite3.Connection, owner_address: str, *,
                           now: Optional[datetime] = None
                           ) -> list[TrustAssessment]:
    """Every distinct peer this owner has issued a credential to."""
    from .credentials import TABLE as CRED_TABLE

    try:
        rows = conn.execute(
            f"SELECT DISTINCT peer_id FROM {CRED_TABLE} WHERE owner_address = ?",
            ((owner_address or "").lower(),)).fetchall()
    except sqlite3.Error:
        return []
    out = []
    for row in rows:
        assessment = assess_peer(conn, row[0], now=now)
        if assessment is not None:
            out.append(assessment)
    return out
