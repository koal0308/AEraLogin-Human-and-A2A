"""SQLite repository for the Agent Identity Layer.

Uses the same `sqlite3` pattern as `server.py`. Foreign keys are enforced
per-connection to avoid mutating global DB configuration used by legacy code.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
from contextlib import contextmanager
from typing import Iterator, Optional


def _db_path() -> str:
    # Same resolution rule as server.py: DATABASE_PATH may be relative to project root.
    raw = os.getenv("DATABASE_PATH", "./aera.db")
    if raw.startswith("./"):
        raw = raw[2:]
    if os.path.isabs(raw):
        return raw
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(root, raw)


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(_db_path(), check_same_thread=False, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=10000")
    return conn


@contextmanager
def transaction() -> Iterator[sqlite3.Connection]:
    """`BEGIN IMMEDIATE` + commit/rollback."""
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        yield conn
        conn.commit()
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        raise
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# Schema
# --------------------------------------------------------------------------- #
_SCHEMA = [
    """CREATE TABLE IF NOT EXISTS agents (
        agent_id           TEXT PRIMARY KEY,
        owner_wallet       TEXT NOT NULL,
        status             TEXT NOT NULL DEFAULT 'active',
        capabilities       TEXT NOT NULL,
        label              TEXT,
        created_at         TEXT NOT NULL,
        updated_at         TEXT NOT NULL,
        revoked_at         TEXT,
        revocation_reason  TEXT,
        last_seen_at       TEXT
    )""",
    """CREATE INDEX IF NOT EXISTS idx_agents_owner
        ON agents(owner_wallet, status)""",

    """CREATE TABLE IF NOT EXISTS agent_keys (
        key_id       TEXT PRIMARY KEY,
        agent_id     TEXT NOT NULL,
        algorithm    TEXT NOT NULL,
        public_key   TEXT NOT NULL,
        status       TEXT NOT NULL DEFAULT 'active',
        created_at   TEXT NOT NULL,
        activated_at TEXT,
        revoked_at   TEXT,
        UNIQUE(agent_id, public_key),
        FOREIGN KEY(agent_id) REFERENCES agents(agent_id)
    )""",
    """CREATE INDEX IF NOT EXISTS idx_agent_keys_agent
        ON agent_keys(agent_id, status)""",

    """CREATE TABLE IF NOT EXISTS agent_challenges (
        challenge_id TEXT PRIMARY KEY,
        agent_id     TEXT NOT NULL,
        key_id       TEXT NOT NULL,
        challenge    TEXT NOT NULL,
        issued_at    TEXT NOT NULL,
        expires_at   TEXT NOT NULL,
        consumed_at  TEXT,
        aud          TEXT NOT NULL,
        FOREIGN KEY(agent_id) REFERENCES agents(agent_id),
        FOREIGN KEY(key_id)   REFERENCES agent_keys(key_id)
    )""",
    """CREATE INDEX IF NOT EXISTS idx_ac_agent_open
        ON agent_challenges(agent_id, key_id, consumed_at, expires_at)""",

    """CREATE TABLE IF NOT EXISTS owner_challenges (
        challenge_id TEXT PRIMARY KEY,
        owner_wallet TEXT NOT NULL,
        agent_id     TEXT,
        operation    TEXT NOT NULL,
        challenge    TEXT NOT NULL,
        issued_at    TEXT NOT NULL,
        expires_at   TEXT NOT NULL,
        consumed_at  TEXT
    )""",
    """CREATE INDEX IF NOT EXISTS idx_oc_open
        ON owner_challenges(owner_wallet, operation, expires_at)""",

    """CREATE TABLE IF NOT EXISTS agent_jti (
        jti            TEXT PRIMARY KEY,
        agent_id       TEXT NOT NULL,
        key_id         TEXT NOT NULL,
        status         TEXT NOT NULL DEFAULT 'active',
        issued_at      TEXT NOT NULL,
        expires_at     TEXT NOT NULL,
        revoked_at     TEXT,
        revoked_reason TEXT,
        aud            TEXT NOT NULL,
        FOREIGN KEY(agent_id) REFERENCES agents(agent_id)
    )""",
    """CREATE INDEX IF NOT EXISTS idx_jti_agent
        ON agent_jti(agent_id, status)""",
    """CREATE INDEX IF NOT EXISTS idx_jti_expires
        ON agent_jti(expires_at)""",

    """CREATE TABLE IF NOT EXISTS agent_message_ids (
        receiver_agent_id TEXT NOT NULL,
        message_id        TEXT NOT NULL,
        expires_at        TEXT NOT NULL,
        PRIMARY KEY(receiver_agent_id, message_id)
    )""",

    """CREATE TABLE IF NOT EXISTS agent_interactions (
        id                     INTEGER PRIMARY KEY AUTOINCREMENT,
        message_id             TEXT UNIQUE,
        initiator_agent_id     TEXT NOT NULL,
        responder_agent_id     TEXT,
        initiator_owner_wallet TEXT NOT NULL,
        responder_owner_wallet TEXT,
        interaction_type       INTEGER NOT NULL,
        metadata_hash          TEXT NOT NULL,
        signature              TEXT NOT NULL,
        onchain_tx_hash        TEXT,
        created_at             TEXT NOT NULL
    )""",

    """CREATE TABLE IF NOT EXISTS agent_audit_log (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        event      TEXT NOT NULL,
        agent_id   TEXT,
        key_id     TEXT,
        jti        TEXT,
        actor      TEXT,
        meta       TEXT,
        created_at TEXT NOT NULL
    )""",
    """CREATE INDEX IF NOT EXISTS idx_audit_agent
        ON agent_audit_log(agent_id, created_at)""",

    # Pending runtime pairings. Additive table; no existing table is altered.
    # Only a SHA-256 of the enrollment secret is stored, never the secret.
    """CREATE TABLE IF NOT EXISTS agent_enrollments (
        enrollment_id TEXT PRIMARY KEY,
        owner_wallet  TEXT NOT NULL,
        secret_hash   TEXT NOT NULL,
        label         TEXT,
        capabilities  TEXT NOT NULL,
        status        TEXT NOT NULL DEFAULT 'pending',
        public_key    TEXT,
        agent_id      TEXT,
        key_id        TEXT,
        created_at    TEXT NOT NULL,
        expires_at    TEXT NOT NULL,
        claimed_at    TEXT,
        completed_at  TEXT
    )""",
    """CREATE INDEX IF NOT EXISTS idx_enroll_owner
        ON agent_enrollments(owner_wallet, status, expires_at)""",

    """CREATE TABLE IF NOT EXISTS agent_rate_limits (
        bucket     TEXT NOT NULL,
        key        TEXT NOT NULL,
        window_start REAL NOT NULL,
        count      INTEGER NOT NULL,
        PRIMARY KEY(bucket, key)
    )""",
]


def init_schema(conn: Optional[sqlite3.Connection] = None) -> None:
    """Create all agent tables if not present. Safe to call multiple times."""
    own = conn is None
    c = conn or get_connection()
    try:
        for ddl in _SCHEMA:
            c.execute(ddl)
        c.commit()
    finally:
        if own:
            c.close()


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #
def utcnow_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def utcnow_epoch() -> int:
    return int(time.time())


def dumps_capabilities(caps) -> str:
    # Deterministic, sorted, ASCII-only.
    return json.dumps(sorted(set(caps)), separators=(",", ":"), ensure_ascii=True)


def loads_capabilities(s: Optional[str]) -> list[str]:
    if not s:
        return []
    try:
        v = json.loads(s)
        return list(v) if isinstance(v, list) else []
    except Exception:
        return []
