"""Replay and duplicate protection for the inbound gateway.

This is a SEPARATE protocol boundary from the internal AEra relay, so it gets
its own state rather than reusing `agent_message_ids`:

  * the internal relay keys replay state on (receiver_agent_id, message_id) of a
    signed AEra envelope, where the sender is a verified AEra agent;
  * here the sender is an unauthenticated external peer, so the scope must not
    be attributed to an AEra sender identity at all.

Mixing the two would let an external caller write rows into the internal relay's
replay namespace. The tables are therefore kept apart deliberately.

Only identifiers and timestamps are stored. No message content is retained.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional

from .constants import REPLAY_TTL_SECONDS

TABLE = "a2a_inbound_requests"

_SCHEMA = f"""
CREATE TABLE IF NOT EXISTS {TABLE} (
    message_id   TEXT NOT NULL,
    target_agent TEXT NOT NULL,
    rpc_id       TEXT,
    received_at  TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    PRIMARY KEY (message_id, target_agent)
)
"""

_INDEX = f"CREATE INDEX IF NOT EXISTS idx_a2a_inbound_expires ON {TABLE}(expires_at)"


def init_schema(conn: sqlite3.Connection) -> None:
    conn.execute(_SCHEMA)
    conn.execute(_INDEX)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def purge_expired(conn: sqlite3.Connection, *, now: Optional[datetime] = None) -> int:
    cur = conn.execute(f"DELETE FROM {TABLE} WHERE expires_at <= ?",
                       ((now or _now()).isoformat(),))
    return cur.rowcount or 0


def remember(conn: sqlite3.Connection, *, message_id: str, target_agent: str,
             rpc_id: Optional[str] = None, now: Optional[datetime] = None,
             ttl_seconds: int = REPLAY_TTL_SECONDS) -> bool:
    """Record this request id. Returns False if it was already seen.

    The insert itself is the duplicate check -- doing it in one atomic statement
    means two concurrent replays cannot both pass a separate "have I seen this?"
    lookup before either writes.
    """
    current = now or _now()
    purge_expired(conn, now=current)
    expires = current + timedelta(seconds=ttl_seconds)
    try:
        conn.execute(
            f"INSERT INTO {TABLE} (message_id, target_agent, rpc_id, received_at, "
            "expires_at) VALUES (?, ?, ?, ?, ?)",
            (message_id, target_agent, str(rpc_id) if rpc_id is not None else None,
             current.isoformat(), expires.isoformat()),
        )
    except sqlite3.IntegrityError:
        return False
    return True


def was_seen(conn: sqlite3.Connection, *, message_id: str, target_agent: str,
             now: Optional[datetime] = None) -> bool:
    row = conn.execute(
        f"SELECT 1 FROM {TABLE} WHERE message_id = ? AND target_agent = ? "
        "AND expires_at > ?",
        (message_id, target_agent, (now or _now()).isoformat()),
    ).fetchone()
    return row is not None
