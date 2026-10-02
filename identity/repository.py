"""Persistence for Human Identities and their provider bindings.

Same plain-sqlite3 pattern as agent/repository.py. Every function takes the
caller's connection, so identity writes can join the caller's transaction
(e.g. agent creation) instead of committing behind its back.
"""
from __future__ import annotations

import secrets
import sqlite3
from typing import Optional

from .models import (
    HUMAN_ID_PREFIX,
    STATUS_ACTIVE,
    HumanIdentity,
    ProviderBinding,
)
from .providers import WALLET, normalize_subject

SCHEMA = [
    """CREATE TABLE IF NOT EXISTS human_identities (
        human_id   TEXT PRIMARY KEY,
        status     TEXT NOT NULL DEFAULT 'active',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )""",
    # One provider account maps to exactly one human (UNIQUE provider+subject).
    # A human may later hold several providers; it may hold at most one binding
    # per provider subject, never the same subject twice.
    """CREATE TABLE IF NOT EXISTS human_identity_providers (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        human_id         TEXT NOT NULL,
        provider         TEXT NOT NULL,
        provider_subject TEXT NOT NULL,
        email            TEXT,
        email_verified   INTEGER NOT NULL DEFAULT 0,
        created_at       TEXT NOT NULL,
        last_login_at    TEXT,
        UNIQUE(provider, provider_subject),
        FOREIGN KEY(human_id) REFERENCES human_identities(human_id)
    )""",
    """CREATE INDEX IF NOT EXISTS idx_hip_human
        ON human_identity_providers(human_id)""",
]


def init_schema(conn: sqlite3.Connection) -> None:
    """Create the identity tables if absent. Additive and idempotent."""
    for ddl in SCHEMA:
        conn.execute(ddl)


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_human_id() -> str:
    """Random, never derived from a wallet, e-mail or provider account."""
    return f"{HUMAN_ID_PREFIX}{secrets.token_hex(16)}"


def _row(conn: sqlite3.Connection, sql: str, params: tuple):
    cur = conn.execute(sql, params)
    row = cur.fetchone()
    if row is None:
        return None
    names = [d[0] for d in cur.description]
    return dict(zip(names, row))


def get_human(conn: sqlite3.Connection, human_id: str) -> Optional[HumanIdentity]:
    r = _row(conn, "SELECT human_id, status, created_at, updated_at "
                   "FROM human_identities WHERE human_id = ?", (human_id,))
    return HumanIdentity(**r) if r else None


def find_binding(conn: sqlite3.Connection, provider: str,
                 subject: str) -> Optional[ProviderBinding]:
    subject = normalize_subject(provider, subject)
    r = _row(conn, "SELECT id, human_id, provider, provider_subject, email, "
                   "email_verified, created_at, last_login_at "
                   "FROM human_identity_providers "
                   "WHERE provider = ? AND provider_subject = ?", (provider, subject))
    if not r:
        return None
    r["email_verified"] = bool(r["email_verified"])
    return ProviderBinding(**r)


def bindings_for(conn: sqlite3.Connection, human_id: str) -> list[ProviderBinding]:
    cur = conn.execute(
        "SELECT id, human_id, provider, provider_subject, email, email_verified, "
        "created_at, last_login_at FROM human_identity_providers "
        "WHERE human_id = ? ORDER BY id", (human_id,))
    names = [d[0] for d in cur.description]
    out = []
    for row in cur.fetchall():
        r = dict(zip(names, row))
        r["email_verified"] = bool(r["email_verified"])
        out.append(ProviderBinding(**r))
    return out


def resolve(conn: sqlite3.Connection, provider: str,
            subject: str) -> Optional[HumanIdentity]:
    """Provider account -> its Human Identity, or None. Never creates."""
    binding = find_binding(conn, provider, subject)
    return get_human(conn, binding.human_id) if binding else None


def resolve_or_create(conn: sqlite3.Connection, provider: str,
                      subject: str) -> HumanIdentity:
    """Provider account -> Human Identity, creating both on first sight.

    Idempotent and race-safe: the UNIQUE(provider, provider_subject) constraint
    decides the winner; a losing attempt rolls back its own human row, so no
    orphan or duplicate identity is ever left behind. Call ONLY with a subject
    that the caller has already authenticated (verified signature / session).
    """
    subject = normalize_subject(provider, subject)
    existing = resolve(conn, provider, subject)
    if existing is not None:
        return existing

    human_id = new_human_id()
    now = _now()
    conn.execute("SAVEPOINT identity_create")
    try:
        conn.execute("INSERT INTO human_identities(human_id, status, created_at, "
                     "updated_at) VALUES (?, ?, ?, ?)",
                     (human_id, STATUS_ACTIVE, now, now))
        conn.execute("INSERT INTO human_identity_providers(human_id, provider, "
                     "provider_subject, created_at) VALUES (?, ?, ?, ?)",
                     (human_id, provider, subject, now))
    except sqlite3.IntegrityError:
        # Someone bound this subject concurrently: discard our human, use theirs.
        conn.execute("ROLLBACK TO SAVEPOINT identity_create")
        conn.execute("RELEASE SAVEPOINT identity_create")
        winner = resolve(conn, provider, subject)
        if winner is None:  # pragma: no cover - constraint fired, row must exist
            raise
        return winner
    conn.execute("RELEASE SAVEPOINT identity_create")
    return HumanIdentity(human_id=human_id, status=STATUS_ACTIVE,
                         created_at=now, updated_at=now)


def resolve_wallet(conn: sqlite3.Connection, address: str) -> Optional[HumanIdentity]:
    return resolve(conn, WALLET, address)


def resolve_or_create_wallet(conn: sqlite3.Connection, address: str) -> HumanIdentity:
    return resolve_or_create(conn, WALLET, address)


def touch_login(conn: sqlite3.Connection, provider: str, subject: str) -> None:
    subject = normalize_subject(provider, subject)
    conn.execute("UPDATE human_identity_providers SET last_login_at = ? "
                 "WHERE provider = ? AND provider_subject = ?",
                 (_now(), provider, subject))
