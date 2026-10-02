"""Owner authorization on top of Human Identity.

Inputs are ONLY server-verified values (a dashboard session's address claim
or an owner-challenge-verified wallet). Client-supplied owner_id/human_id are
never accepted here.
"""
from __future__ import annotations

import sqlite3
from typing import Optional

from . import repository as repo
from .providers import ProviderError


def human_for_verified_wallet(conn: sqlite3.Connection,
                              wallet: str) -> Optional[str]:
    """Verified wallet -> active human_id (created on first sight) or None."""
    try:
        human = repo.resolve_or_create_wallet(conn, wallet)
    except ProviderError:
        return None
    return human.human_id if human.is_active else None


def owns_agent(conn: sqlite3.Connection, human_id: str, wallet: str,
               agent_id: str) -> bool:
    """True only if the agent belongs to this human AND this wallet.

    Both columns must agree; a legacy row without owner_id falls back to the
    unchanged owner_wallet rule, never to "allow".
    """
    if not human_id or not wallet:
        return False
    row = conn.execute("SELECT owner_wallet, owner_id FROM agents WHERE agent_id = ?",
                       (agent_id,)).fetchone()
    if row is None:
        return False
    owner_wallet, owner_id = row[0], row[1]
    if (owner_wallet or "").lower() != wallet.lower():
        return False
    return owner_id is None or owner_id == human_id
