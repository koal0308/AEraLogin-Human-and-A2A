"""Off-chain agent interaction proof.

Persists a cryptographic Ed25519 proof and optionally calls the existing
`web3_service.record_interaction` – WITHOUT modifying its signature.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Optional

from . import audit, repository
from .constants import AGENT_MESSAGE_KEYS, PROTO_AGENT_MESSAGE
from .crypto import canonical_json, verify_signature


class InteractionError(Exception):
    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(message or code)
        self.code = code


def record(
    *,
    payload: dict[str, Any],
    signature_b64u: str,
    interaction_type: int,
    metadata: Optional[dict[str, Any]],
    jwt_sender: str,
) -> dict[str, Any]:
    """Record an interaction with off-chain agent authorship proof.
    Reuses the aera-agent-message canonical form for the signature."""
    if payload.get("protocol") != PROTO_AGENT_MESSAGE:
        raise InteractionError("invalid_payload_protocol")
    sender = payload.get("sender_agent_id")
    if sender != jwt_sender:
        raise InteractionError("sender_jwt_mismatch")
    receiver = payload.get("receiver_agent_id")
    sender_key = payload.get("sender_key_id")
    message_id = payload.get("message_id")
    try:
        canonical = canonical_json(payload, AGENT_MESSAGE_KEYS)
    except ValueError:
        raise InteractionError("message_signature_invalid")

    with repository.transaction() as conn:
        s_agent = conn.execute(
            "SELECT owner_wallet, status FROM agents WHERE agent_id=?", (sender,)
        ).fetchone()
        if s_agent is None or s_agent["status"] != "active":
            raise InteractionError("revoked_agent")
        r_agent = None
        if receiver:
            r_agent = conn.execute(
                "SELECT owner_wallet, status FROM agents WHERE agent_id=?", (receiver,)
            ).fetchone()
        key = conn.execute(
            "SELECT public_key, status FROM agent_keys WHERE key_id=? AND agent_id=?",
            (sender_key, sender),
        ).fetchone()
        if key is None or key["status"] != "active":
            raise InteractionError("revoked_key")
        if not verify_signature(key["public_key"], signature_b64u, canonical):
            raise InteractionError("message_signature_invalid")

        meta_str = json.dumps(metadata or {}, separators=(",", ":"), sort_keys=True, ensure_ascii=True)
        meta_hash = hashlib.sha256(meta_str.encode("utf-8")).hexdigest()

        try:
            conn.execute(
                "INSERT INTO agent_interactions(message_id, initiator_agent_id, "
                "responder_agent_id, initiator_owner_wallet, responder_owner_wallet, "
                "interaction_type, metadata_hash, signature, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    message_id, sender, receiver,
                    s_agent["owner_wallet"],
                    r_agent["owner_wallet"] if r_agent else None,
                    int(interaction_type), meta_hash, signature_b64u,
                    repository.utcnow_iso(),
                ),
            )
        except Exception:
            raise InteractionError("duplicate_interaction")

        audit.log_event(
            "agent.interaction_recorded",
            agent_id=sender,
            key_id=sender_key,
            actor="agent",
            meta={"message_id": message_id, "receiver": receiver,
                  "type": int(interaction_type)},
            conn=conn,
        )

    onchain_tx: Optional[str] = None
    try:
        import web3_service  # type: ignore
        rec = getattr(web3_service, "record_interaction", None)
        if callable(rec) and r_agent is not None:
            res = rec(
                s_agent["owner_wallet"],
                r_agent["owner_wallet"],
                int(interaction_type),
                {"agent_id_a": sender, "agent_id_b": receiver,
                 "message_id": message_id, "metadata_hash": meta_hash},
            )
            if isinstance(res, dict):
                onchain_tx = res.get("tx_hash") or res.get("hash")
    except Exception:
        pass  # web3 layer is optional in Phase 1

    return {
        "message_id": message_id,
        "metadata_hash": meta_hash,
        "onchain_tx_hash": onchain_tx,
    }
