"""Agent Challenge subsystem (Spec §6, §6.2a).

Persistent, single-use, bound to (agent_id, key_id, aud).
"""
from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from . import repository
from .constants import (
    AGENT_CHALLENGE_TTL_SECONDS,
    AUDIENCE_ALLOWLIST,
    PROTO_AGENT_AUTH,
    PROTOCOL_VERSION,
)
from .crypto import b64u_encode


class AgentChallengeError(Exception):
    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(message or code)
        self.code = code


def issue(*, agent_id: str, key_id: str, aud: str) -> dict[str, Any]:
    if aud not in AUDIENCE_ALLOWLIST:
        raise AgentChallengeError("invalid_audience")
    # Verify agent + key + binding.
    conn = repository.get_connection()
    try:
        agent = conn.execute(
            "SELECT status FROM agents WHERE agent_id=?", (agent_id,)
        ).fetchone()
        if agent is None or agent["status"] != "active":
            raise AgentChallengeError("revoked_agent" if agent else "invalid_agent")
        key = conn.execute(
            "SELECT agent_id, status FROM agent_keys WHERE key_id=?", (key_id,)
        ).fetchone()
        if key is None:
            raise AgentChallengeError("invalid_key")
        if key["agent_id"] != agent_id:
            raise AgentChallengeError("key_mismatch")
        if key["status"] != "active":
            raise AgentChallengeError("revoked_key")

        challenge_id = secrets.token_hex(16)
        challenge = b64u_encode(secrets.token_bytes(32))
        issued = repository.utcnow_iso()
        exp_dt = datetime.now(timezone.utc) + timedelta(seconds=AGENT_CHALLENGE_TTL_SECONDS)
        expires_at = exp_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        conn.execute(
            "INSERT INTO agent_challenges(challenge_id, agent_id, key_id, challenge, "
            "issued_at, expires_at, aud) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (challenge_id, agent_id, key_id, challenge, issued, expires_at, aud),
        )
        conn.commit()
    finally:
        conn.close()

    return {
        "protocol": PROTO_AGENT_AUTH,
        "version": PROTOCOL_VERSION,
        "agent_id": agent_id,
        "key_id": key_id,
        "challenge_id": challenge_id,
        "challenge": challenge,
        "aud": aud,
        "issued_at": issued,
        "expires_at": expires_at,
    }
