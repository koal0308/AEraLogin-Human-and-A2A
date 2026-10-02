"""Idempotent, non-destructive migration of existing wallet users.

* adds the nullable column `agents.owner_id` (if the agents table exists),
* creates one Human Identity + wallet binding per distinct, valid wallet found
  in agents.owner_wallet, agent_enrollments.owner_wallet and users.address,
* fills agents.owner_id ONLY where it is NULL, from the wallet binding of the
  agent's own owner_wallet.

Nothing is deleted or rewritten: agent IDs, keys, owner_wallet, challenges,
tokens and A2A data stay exactly as they are. Running it again changes nothing.
Malformed legacy wallets are skipped and counted, never "repaired".
"""
from __future__ import annotations

import sqlite3

from . import repository as repo
from .providers import ProviderError, wallet_subject

_SOURCES = (
    ("agents", "owner_wallet"),
    ("agent_enrollments", "owner_wallet"),
    ("users", "address"),
)


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def ensure_agent_owner_column(conn: sqlite3.Connection) -> bool:
    """Add agents.owner_id if agents exists and lacks it. True if added."""
    cols = _columns(conn, "agents")
    if not cols or "owner_id" in cols:
        return False
    conn.execute("ALTER TABLE agents ADD COLUMN owner_id TEXT")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_agents_owner_id ON agents(owner_id)")
    return True


def init(conn: sqlite3.Connection) -> None:
    repo.init_schema(conn)
    ensure_agent_owner_column(conn)
    if "owner_id" in _columns(conn, "agents"):
        conn.execute("CREATE INDEX IF NOT EXISTS idx_agents_owner_id ON agents(owner_id)")


def migrate_existing_wallets(conn: sqlite3.Connection) -> dict:
    init(conn)
    stats = {"wallets_seen": 0, "humans_created": 0, "invalid_skipped": 0,
             "agents_linked": 0}
    wallets: set[str] = set()
    for table, col in _SOURCES:
        if col not in _columns(conn, table):
            continue
        for (raw,) in conn.execute(
                f"SELECT DISTINCT {col} FROM {table} WHERE {col} IS NOT NULL"):
            try:
                wallets.add(wallet_subject(raw))
            except ProviderError:
                stats["invalid_skipped"] += 1
    stats["wallets_seen"] = len(wallets)
    for w in sorted(wallets):
        if repo.resolve_wallet(conn, w) is None:
            repo.resolve_or_create_wallet(conn, w)
            stats["humans_created"] += 1

    if "owner_id" in _columns(conn, "agents"):
        cur = conn.execute(
            """UPDATE agents SET owner_id = (
                   SELECT p.human_id FROM human_identity_providers p
                   WHERE p.provider = 'wallet'
                     AND p.provider_subject = lower(agents.owner_wallet))
               WHERE owner_id IS NULL
                 AND EXISTS (SELECT 1 FROM human_identity_providers p
                   WHERE p.provider = 'wallet'
                     AND p.provider_subject = lower(agents.owner_wallet))""")
        stats["agents_linked"] = cur.rowcount
    return stats
