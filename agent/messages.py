"""A2A message relay + off-chain interaction proof.

JWT (transport auth) and Ed25519 payload signature are verified INDEPENDENTLY
per Spec §9a.
"""
from __future__ import annotations

import hashlib
import sqlite3
from datetime import datetime, timezone
from typing import Any

from . import audit, repository
from .constants import (
    AGENT_MESSAGE_KEYS,
    MESSAGE_TTL_SECONDS,
    PROTO_AGENT_MESSAGE,
    PROTOCOL_VERSION,
)
from .crypto import canonical_json, verify_signature


class MessageError(Exception):
    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(message or code)
        self.code = code


def _iso_to_epoch(s: str) -> int:
    try:
        return int(datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())
    except Exception:
        return 0


def _load_active_key(conn: sqlite3.Connection, *, agent_id: str, key_id: str) -> str:
    row = conn.execute(
        "SELECT public_key, status FROM agent_keys WHERE key_id=? AND agent_id=?",
        (key_id, agent_id),
    ).fetchone()
    if row is None or row["status"] != "active":
        raise MessageError("revoked_key")
    return row["public_key"]


def _agent_active(conn: sqlite3.Connection, agent_id: str) -> None:
    r = conn.execute("SELECT status FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
    if r is None or r["status"] != "active":
        raise MessageError("revoked_agent")


def verify_and_store(payload: dict[str, Any], signature_b64u: str, *, jwt_sender: str) -> dict[str, Any]:
    """Validate payload + signature + replay protection and record message_id."""
    required = AGENT_MESSAGE_KEYS
    if set(payload.keys()) - required:
        raise MessageError("message_signature_invalid")
    for k in required:
        if k not in payload:
            raise MessageError("message_signature_invalid")
    if payload.get("protocol") != PROTO_AGENT_MESSAGE:
        raise MessageError("message_signature_invalid")
    if payload.get("version") != PROTOCOL_VERSION:
        raise MessageError("message_signature_invalid")

    sender = payload.get("sender_agent_id")
    receiver = payload.get("receiver_agent_id")
    sender_key = payload.get("sender_key_id")
    message_id = payload.get("message_id")
    if sender != jwt_sender:
        raise MessageError("sender_jwt_mismatch")

    expires_at = payload.get("expires_at", "")
    now_epoch = int(datetime.now(timezone.utc).timestamp())
    exp_epoch = _iso_to_epoch(expires_at)
    if exp_epoch == 0 or exp_epoch < now_epoch:
        raise MessageError("expired_message")

    try:
        canonical = canonical_json(payload, AGENT_MESSAGE_KEYS)
    except ValueError:
        raise MessageError("message_signature_invalid")

    with repository.transaction() as conn:
        _agent_active(conn, sender)
        _agent_active(conn, receiver)
        pk = _load_active_key(conn, agent_id=sender, key_id=sender_key)
        if not verify_signature(pk, signature_b64u, canonical):
            raise MessageError("message_signature_invalid")

        # replay
        try:
            conn.execute(
                "INSERT INTO agent_message_ids(receiver_agent_id, message_id, expires_at) "
                "VALUES (?, ?, ?)",
                (receiver, message_id, expires_at),
            )
        except sqlite3.IntegrityError:
            raise MessageError("message_replay")

        audit.log_event(
            "agent.message_received",
            agent_id=sender,
            key_id=sender_key,
            actor="agent",
            meta={"message_id": message_id, "receiver": receiver},
            conn=conn,
        )
    return payload


def content_hash(content: bytes) -> str:
    from .crypto import b64u_encode
    return "sha256:" + b64u_encode(hashlib.sha256(content).digest())
