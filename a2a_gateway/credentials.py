"""External A2A peer credentials (LEVEL 3).

WHAT THIS IS
------------
An opaque bearer credential issued by AEra, authorised by an agent owner, and
held by an external A2A peer. It authenticates *who is calling*; it says
nothing about what they may do -- that is authorisation, and it lives in
`authorize_request()` below, deliberately as a separate step.

WHY OPAQUE AND NOT A JWT
------------------------
The requirement is that compromising one peer's credential must not endanger
any other peer. An opaque random token satisfies that maximally: there is no
signing secret at all, so there is nothing shared to leak.

The usual argument for a JWT is stateless verification. That argument does not
survive contact with revocation: if revocation has to be immediate and
authoritative, every request must consult the store anyway. A JWT would
therefore add a server-wide signing secret and buy nothing.

WHAT IS STORED
--------------
Only SHA-256 of the secret. The plaintext exists exactly once, in the issuance
response, and is never written to the database, a log, or an audit record.

FORMAT
------
    aera_a2a_<cred_id>_<secret>

`cred_id` is a public, indexed lookup handle -- it makes verification an O(1)
indexed read rather than a scan over every row, which would otherwise be both
slow and a timing oracle. The secret is compared with `hmac.compare_digest`.

THIS IS NOT AN AERA AGENT TOKEN. The audience is `aera-a2a-gateway`, which is
deliberately absent from `agent.constants.AUDIENCE_ALLOWLIST`. An AEra Agent
JWT presented here is refused, and always was.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from .constants import (
    CREDENTIAL_AUDIENCE,
    CREDENTIAL_ISSUER,
    CREDENTIAL_PREFIX,
    DEFAULT_CREDENTIAL_TTL_DAYS,
)

TABLE = "a2a_peer_credentials"

STATUS_ACTIVE = "active"
STATUS_REVOKED = "revoked"

#: Length in bytes of the random parts. 16 bytes of id is collision-free for any
#: plausible number of credentials; 32 bytes of secret is 256 bits as specified.
CRED_ID_BYTES = 16
SECRET_BYTES = 32

#: Peer ids are minted by AEra, never supplied by a caller.
PEER_ID_BYTES = 12

_CRED_ID_RE = re.compile(r"^[0-9a-f]{32}$")

_SCHEMA = f"""
CREATE TABLE IF NOT EXISTS {TABLE} (
    cred_id        TEXT PRIMARY KEY,
    peer_id        TEXT NOT NULL,
    peer_label     TEXT,
    secret_hash    TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT '{STATUS_ACTIVE}',
    issued_at      TEXT NOT NULL,
    expires_at     TEXT NOT NULL,
    scoped_agents  TEXT NOT NULL DEFAULT '[]',
    scoped_skills  TEXT NOT NULL DEFAULT '[]',
    audience       TEXT NOT NULL,
    issuer         TEXT NOT NULL,
    owner_address  TEXT NOT NULL,
    revoked_at     TEXT,
    revoked_reason TEXT,
    last_used_at   TEXT
)
"""

_INDEXES = (
    f"CREATE INDEX IF NOT EXISTS idx_a2a_cred_owner ON {TABLE}(owner_address)",
    f"CREATE INDEX IF NOT EXISTS idx_a2a_cred_peer ON {TABLE}(peer_id)",
    f"CREATE INDEX IF NOT EXISTS idx_a2a_cred_status ON {TABLE}(status)",
)


class CredentialError(Exception):
    """A credential was presented and is not acceptable.

    Carries a machine-readable `reason` for audit, but the message sent to the
    caller is uniform -- see `OPAQUE_AUTH_FAILURE`. Distinguishing "no such
    credential" from "wrong secret" would turn this endpoint into an
    enumeration oracle.
    """

    def __init__(self, reason: str, message: str = "") -> None:
        super().__init__(reason)
        self.reason = reason
        self.message = message or OPAQUE_AUTH_FAILURE


#: The single external-facing wording for every authentication failure.
OPAQUE_AUTH_FAILURE = "invalid or expired credential"


# --------------------------------------------------------------------------- #
# schema
# --------------------------------------------------------------------------- #
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
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc)
    except ValueError:
        return None


def credential_ttl_days() -> int:
    raw = os.getenv("AERA_A2A_CREDENTIAL_TTL_DAYS", "")
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_CREDENTIAL_TTL_DAYS
    # A zero or negative TTL would mean "already expired" or "never expires";
    # neither is a sane reading of a typo, so fall back to the default.
    return value if value > 0 else DEFAULT_CREDENTIAL_TTL_DAYS


# --------------------------------------------------------------------------- #
# the credential itself
# --------------------------------------------------------------------------- #
def hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def mint_peer_id() -> str:
    """AEra mints peer identities. They are never derived from an address,
    a wallet, an agent id or anything the caller can influence."""
    return f"peer_{secrets.token_hex(PEER_ID_BYTES)}"


def build_credential(cred_id: str, secret: str) -> str:
    return f"{CREDENTIAL_PREFIX}{cred_id}_{secret}"


def parse_credential(raw: Any) -> tuple[str, str]:
    """Split a presented credential into (cred_id, secret).

    Raises CredentialError for anything that is not exactly our format. A
    malformed credential is an authentication *failure*, never a silent
    downgrade to anonymous.
    """
    if not isinstance(raw, str):
        raise CredentialError("not_a_string")
    value = raw.strip()
    if not value.startswith(CREDENTIAL_PREFIX):
        raise CredentialError("wrong_prefix")

    remainder = value[len(CREDENTIAL_PREFIX):]
    cred_id, separator, secret = remainder.partition("_")
    if not separator or not secret:
        raise CredentialError("malformed")
    if not _CRED_ID_RE.match(cred_id):
        raise CredentialError("malformed_cred_id")
    # A secret of the wrong length cannot be one of ours; reject before any
    # database work so a flood of junk costs nothing.
    if len(secret) != SECRET_BYTES * 2 or not re.fullmatch(r"[0-9a-f]+", secret):
        raise CredentialError("malformed_secret")
    return cred_id, secret


def looks_like_our_credential(raw: Any) -> bool:
    return isinstance(raw, str) and raw.strip().startswith(CREDENTIAL_PREFIX)


# --------------------------------------------------------------------------- #
# records
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class CredentialRecord:
    """A verified credential. Never contains the secret or its hash."""

    cred_id: str
    peer_id: str
    owner_address: str
    scoped_agents: tuple[str, ...] = ()
    scoped_skills: tuple[str, ...] = ()
    status: str = STATUS_ACTIVE
    issued_at: Optional[str] = None
    expires_at: Optional[str] = None
    peer_label: Optional[str] = None
    audience: str = CREDENTIAL_AUDIENCE
    issuer: str = CREDENTIAL_ISSUER
    revoked_at: Optional[str] = None
    revoked_reason: Optional[str] = None
    last_used_at: Optional[str] = None

    def to_owner_dict(self) -> dict[str, Any]:
        """What the *owner* may see in the dashboard. Still no secret."""
        return {
            "cred_id": self.cred_id,
            "peer_id": self.peer_id,
            "peer_label": self.peer_label,
            "status": self.status,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "scoped_agents": list(self.scoped_agents),
            "scoped_skills": list(self.scoped_skills),
            "audience": self.audience,
            "issuer": self.issuer,
            "revoked_at": self.revoked_at,
            "revoked_reason": self.revoked_reason,
            "last_used_at": self.last_used_at,
        }

    def __repr__(self) -> str:  # keep credentials out of tracebacks
        return (f"<CredentialRecord {self.cred_id} peer={self.peer_id} "
                f"status={self.status}>")


def _row_to_record(row) -> CredentialRecord:
    def get(key, default=None):
        try:
            value = row[key]
        except (IndexError, KeyError, TypeError):
            return default
        return default if value is None else value

    return CredentialRecord(
        cred_id=get("cred_id", ""),
        peer_id=get("peer_id", ""),
        owner_address=get("owner_address", ""),
        scoped_agents=tuple(_loads_list(get("scoped_agents", "[]"))),
        scoped_skills=tuple(_loads_list(get("scoped_skills", "[]"))),
        status=get("status", STATUS_ACTIVE),
        issued_at=get("issued_at"),
        expires_at=get("expires_at"),
        peer_label=get("peer_label"),
        audience=get("audience", CREDENTIAL_AUDIENCE),
        issuer=get("issuer", CREDENTIAL_ISSUER),
        revoked_at=get("revoked_at"),
        revoked_reason=get("revoked_reason"),
        last_used_at=get("last_used_at"),
    )


def _loads_list(value: Any) -> list[str]:
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    try:
        parsed = json.loads(value or "[]")
    except (ValueError, TypeError):
        return []
    return [str(v) for v in parsed] if isinstance(parsed, list) else []


# --------------------------------------------------------------------------- #
# issuance
# --------------------------------------------------------------------------- #
@dataclass
class IssuedCredential:
    """The one and only moment the plaintext exists."""

    record: CredentialRecord
    plaintext: str = field(repr=False)

    def to_issue_response(self) -> dict[str, Any]:
        payload = self.record.to_owner_dict()
        payload["credential"] = self.plaintext
        payload["warning"] = (
            "This is the only time the credential is shown. AEra stores only a "
            "hash of it and cannot display it again."
        )
        return payload


def issue_credential(conn: sqlite3.Connection, *, owner_address: str,
                     scoped_agents: Optional[list[str]] = None,
                     scoped_skills: Optional[list[str]] = None,
                     peer_id: Optional[str] = None,
                     peer_label: Optional[str] = None,
                     ttl_days: Optional[int] = None,
                     now: Optional[datetime] = None) -> IssuedCredential:
    """Create a credential for an external peer.

    `owner_address` MUST come from the authenticated dashboard session, never
    from a request body or query string. Scope ownership is verified by the
    caller (`verify_owns_agents`) before this is invoked.

    Passing an existing `peer_id` issues an additional credential for the same
    peer -- that is how rotation works: issue the new one, hand it over, then
    revoke the old one. Nothing is revoked implicitly here.
    """
    moment = now or _now()
    cred_id = secrets.token_hex(CRED_ID_BYTES)
    secret = secrets.token_hex(SECRET_BYTES)
    ttl = ttl_days if (ttl_days and ttl_days > 0) else credential_ttl_days()

    record = CredentialRecord(
        cred_id=cred_id,
        peer_id=peer_id or mint_peer_id(),
        owner_address=owner_address.lower(),
        scoped_agents=tuple(scoped_agents or ()),
        scoped_skills=tuple(scoped_skills or ()),
        status=STATUS_ACTIVE,
        issued_at=_iso(moment),
        expires_at=_iso(moment + timedelta(days=ttl)),
        peer_label=peer_label,
    )

    conn.execute(
        f"INSERT INTO {TABLE} (cred_id, peer_id, peer_label, secret_hash, status, "
        "issued_at, expires_at, scoped_agents, scoped_skills, audience, issuer, "
        "owner_address) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (record.cred_id, record.peer_id, record.peer_label, hash_secret(secret),
         record.status, record.issued_at, record.expires_at,
         json.dumps(list(record.scoped_agents)),
         json.dumps(list(record.scoped_skills)),
         record.audience, record.issuer, record.owner_address),
    )
    return IssuedCredential(record=record, plaintext=build_credential(cred_id, secret))


# --------------------------------------------------------------------------- #
# verification
# --------------------------------------------------------------------------- #
def verify_credential(conn: sqlite3.Connection, raw: Any, *,
                      now: Optional[datetime] = None) -> CredentialRecord:
    """Authenticate a presented credential, or raise CredentialError.

    Order matters: everything cheap and local happens before the database is
    touched, so junk costs nothing. Every failure raises with the *same*
    external message.
    """
    cred_id, secret = parse_credential(raw)
    moment = now or _now()

    row = conn.execute(
        f"SELECT cred_id, peer_id, peer_label, secret_hash, status, issued_at, "
        f"expires_at, scoped_agents, scoped_skills, audience, issuer, "
        f"owner_address, revoked_at, revoked_reason, last_used_at "
        f"FROM {TABLE} WHERE cred_id = ?",
        (cred_id,),
    ).fetchone()

    if row is None:
        raise CredentialError("unknown_credential")

    stored_hash = row["secret_hash"] if _has_keys(row) else row[3]
    # Constant time: a byte-by-byte early exit would leak the secret through
    # response timing, one byte at a time.
    if not hmac.compare_digest(stored_hash or "", hash_secret(secret)):
        raise CredentialError("bad_secret")

    record = _row_to_record(row)

    if record.status != STATUS_ACTIVE:
        # Revocation is authoritative and immediate. There is no validity
        # window left to wait out.
        raise CredentialError("revoked")

    if record.audience != CREDENTIAL_AUDIENCE:
        raise CredentialError("wrong_audience")

    if record.issuer != CREDENTIAL_ISSUER:
        raise CredentialError("wrong_issuer")

    expires = _parse_iso(record.expires_at)
    if expires is None or expires <= moment:
        raise CredentialError("expired")

    return record


def _has_keys(row) -> bool:
    return hasattr(row, "keys")


def touch(conn: sqlite3.Connection, cred_id: str, *,
          now: Optional[datetime] = None) -> None:
    """Record last use. Best effort: never fail a valid request over telemetry."""
    try:
        conn.execute(f"UPDATE {TABLE} SET last_used_at = ? WHERE cred_id = ?",
                     (_iso(now or _now()), cred_id))
    except Exception:  # noqa: BLE001 - auditing must not break authentication
        pass


# --------------------------------------------------------------------------- #
# authorisation -- deliberately separate from authentication
# --------------------------------------------------------------------------- #
def authorize_request(record: CredentialRecord, *, target_agent_id: str,
                      skill_id: Optional[str]) -> bool:
    """May this peer address this agent with this skill?

    A valid credential proves "this is peer X". It does not prove "peer X may
    talk to agent Y". Those are two questions and this is the second one.

    An empty scope list means "no restriction at this dimension", which is why
    an empty list must never be produced accidentally from a parse failure --
    `_loads_list` returns [] only for genuinely empty or invalid JSON, and the
    issuance path always writes a real list.
    """
    if record.scoped_agents and target_agent_id not in record.scoped_agents:
        return False
    if record.scoped_skills and skill_id is not None:
        if skill_id not in record.scoped_skills:
            return False
    return True


# --------------------------------------------------------------------------- #
# owner-side management
# --------------------------------------------------------------------------- #
def verify_owns_agents(conn: sqlite3.Connection, owner_address: str,
                       agent_ids: list[str]) -> list[str]:
    """Return the requested agent ids the owner does NOT own.

    Scoping a credential to somebody else's agent would let one owner hand out
    access to another owner's agent, so this is checked server-side against
    `agents.owner_wallet` and never against anything in the request.
    """
    if not agent_ids:
        return []
    owner = (owner_address or "").lower()
    placeholders = ",".join("?" for _ in agent_ids)
    rows = conn.execute(
        f"SELECT agent_id FROM agents WHERE agent_id IN ({placeholders}) "
        "AND lower(owner_wallet) = ?",
        (*agent_ids, owner),
    ).fetchall()
    owned = {row[0] for row in rows}
    return [agent_id for agent_id in agent_ids if agent_id not in owned]


def list_for_owner(conn: sqlite3.Connection, owner_address: str
                   ) -> list[CredentialRecord]:
    rows = conn.execute(
        f"SELECT cred_id, peer_id, peer_label, secret_hash, status, issued_at, "
        f"expires_at, scoped_agents, scoped_skills, audience, issuer, "
        f"owner_address, revoked_at, revoked_reason, last_used_at "
        f"FROM {TABLE} WHERE owner_address = ? ORDER BY issued_at DESC",
        ((owner_address or "").lower(),),
    ).fetchall()
    return [_row_to_record(row) for row in rows]


def revoke_credential(conn: sqlite3.Connection, *, cred_id: str,
                      owner_address: str, reason: str = "",
                      now: Optional[datetime] = None) -> bool:
    """Revoke one credential. Returns False if it is not this owner's.

    The row is never deleted: the historical identity stays auditable, and an
    audit log referring to a cred_id must remain resolvable.
    """
    cursor = conn.execute(
        f"UPDATE {TABLE} SET status = ?, revoked_at = ?, revoked_reason = ? "
        "WHERE cred_id = ? AND owner_address = ? AND status = ?",
        (STATUS_REVOKED, _iso(now or _now()), (reason or "")[:200],
         cred_id, (owner_address or "").lower(), STATUS_ACTIVE),
    )
    return cursor.rowcount > 0
