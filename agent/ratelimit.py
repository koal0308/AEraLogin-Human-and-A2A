"""Tiny SQLite-based rate limiter. Fixed windows per (bucket, key)."""
from __future__ import annotations

import time

from . import repository


def check(bucket: str, key: str, *, limit: int, window_seconds: int) -> bool:
    """Return True iff request is allowed."""
    now = time.time()
    conn = repository.get_connection()
    try:
        row = conn.execute(
            "SELECT window_start, count FROM agent_rate_limits WHERE bucket=? AND key=?",
            (bucket, key),
        ).fetchone()
        if row is None or (now - row["window_start"]) >= window_seconds:
            conn.execute(
                "INSERT OR REPLACE INTO agent_rate_limits(bucket, key, window_start, count) "
                "VALUES (?, ?, ?, 1)", (bucket, key, now),
            )
            conn.commit()
            return True
        if row["count"] >= limit:
            return False
        conn.execute(
            "UPDATE agent_rate_limits SET count=count+1 WHERE bucket=? AND key=?",
            (bucket, key),
        )
        conn.commit()
        return True
    finally:
        conn.close()
