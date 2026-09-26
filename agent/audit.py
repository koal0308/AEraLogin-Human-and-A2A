"""Append-only audit log helper. No secrets, no private keys, no full tokens."""
from __future__ import annotations

import json
import sqlite3
from typing import Any, Mapping, Optional

from . import repository


def log_event(
    event: str,
    *,
    agent_id: Optional[str] = None,
    key_id: Optional[str] = None,
    jti: Optional[str] = None,
    actor: Optional[str] = None,
    meta: Optional[Mapping[str, Any]] = None,
    conn: Optional[sqlite3.Connection] = None,
) -> None:
    safe_meta = None
    if meta is not None:
        cleaned = {k: v for k, v in meta.items()
                   if k not in {"secret", "private_key", "signature", "token", "challenge"}}
        safe_meta = json.dumps(cleaned, separators=(",", ":"), ensure_ascii=True, sort_keys=True)
    row = (event, agent_id, key_id, jti, actor, safe_meta, repository.utcnow_iso())
    if conn is not None:
        conn.execute(
            "INSERT INTO agent_audit_log(event, agent_id, key_id, jti, actor, meta, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)", row,
        )
        return
    c = repository.get_connection()
    try:
        c.execute(
            "INSERT INTO agent_audit_log(event, agent_id, key_id, jti, actor, meta, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)", row,
        )
        c.commit()
    finally:
        c.close()
