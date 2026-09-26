"""Owner Challenge subsystem (Spec §6a).

Persistent, single-use, bound to (owner_wallet, operation[, agent_id]).
Uses EIP-191 (personal_sign) or EIP-1271 (smart contract wallet) for owner
signature verification. This module intentionally does NOT reuse
`server.py`'s /api/verify path, since that path uses the replayable legacy
nonce (S-03).
"""
from __future__ import annotations

import json
import os
import secrets
from typing import Any, Optional

from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import to_checksum_address

from . import repository
from .constants import (
    OWNER_CHALLENGE_TTL_SECONDS,
    OWNER_DOMAIN,
    OWNER_OPS,
    PROTO_OWNER_CHALLENGE,
    PROTOCOL_VERSION,
)
from .crypto import canonical_json
from .constants import OWNER_CHALLENGE_KEYS


class OwnerChallengeError(Exception):
    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(message or code)
        self.code = code


# --------------------------------------------------------------------------- #
# Issue
# --------------------------------------------------------------------------- #
def issue(*, owner_wallet: str, operation: str, agent_id: Optional[str]) -> dict[str, Any]:
    if operation not in OWNER_OPS:
        raise OwnerChallengeError("invalid_operation", f"unknown op: {operation}")
    if not owner_wallet:
        raise OwnerChallengeError("invalid_owner_wallet")
    owner = owner_wallet.lower()
    challenge_id = secrets.token_hex(16)
    challenge = secrets.token_bytes(32)
    from .crypto import b64u_encode
    challenge_b64 = b64u_encode(challenge)
    issued = repository.utcnow_iso()
    from datetime import datetime, timedelta, timezone
    exp_dt = datetime.now(timezone.utc) + timedelta(seconds=OWNER_CHALLENGE_TTL_SECONDS)
    expires_at = exp_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    conn = repository.get_connection()
    try:
        conn.execute(
            "INSERT INTO owner_challenges(challenge_id, owner_wallet, agent_id, operation, "
            "challenge, issued_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (challenge_id, owner, agent_id, operation, challenge_b64, issued, expires_at),
        )
        conn.commit()
    finally:
        conn.close()

    return {
        "protocol": PROTO_OWNER_CHALLENGE,
        "version": PROTOCOL_VERSION,
        "owner_wallet": owner,
        "agent_id": agent_id or "",
        "operation": operation,
        "challenge_id": challenge_id,
        "challenge": challenge_b64,
        "expires_at": expires_at,
        "domain": OWNER_DOMAIN,
    }


def build_signed_payload(rec: dict[str, Any]) -> bytes:
    """Build canonical bytes that the owner MUST sign."""
    payload = {
        "protocol": PROTO_OWNER_CHALLENGE,
        "version": PROTOCOL_VERSION,
        "owner_wallet": rec["owner_wallet"],
        "agent_id": rec.get("agent_id") or "",
        "operation": rec["operation"],
        "challenge_id": rec["challenge_id"],
        "challenge": rec["challenge"],
        "expires_at": rec["expires_at"],
        "domain": OWNER_DOMAIN,
    }
    return canonical_json(payload, OWNER_CHALLENGE_KEYS)


# --------------------------------------------------------------------------- #
# Signature verification (EIP-191 + optional EIP-1271)
# --------------------------------------------------------------------------- #
def _verify_eip191(address: str, message: bytes, signature_hex: str) -> bool:
    try:
        recovered = Account.recover_message(
            encode_defunct(primitive=message), signature=signature_hex
        )
        return recovered.lower() == address.lower()
    except Exception:
        return False


def _verify_eip1271(address: str, message: bytes, signature_hex: str) -> bool:
    """Best-effort EIP-1271 via web3. Skipped in test env where BASE_RPC_URL is a stub."""
    try:
        from web3 import Web3  # type: ignore
        rpc = os.getenv("BASE_RPC_URL", "")
        if not rpc or "mock" in rpc:
            return False
        w3 = Web3(Web3.HTTPProvider(rpc))
        if not w3.is_connected():
            return False
        from eth_account.messages import encode_defunct as _ed
        # compute EIP-191 hash
        eip191_msg = _ed(primitive=message)
        # message hash exposed on SignableMessage.body / .header not directly hash;
        # use hash_message from eth_account:
        from eth_account.messages import _hash_eip191_message
        h = _hash_eip191_message(eip191_msg)
        abi = [{
            "constant": True,
            "inputs": [{"name": "_hash", "type": "bytes32"},
                       {"name": "_sig", "type": "bytes"}],
            "name": "isValidSignature",
            "outputs": [{"name": "", "type": "bytes4"}],
            "type": "function",
        }]
        sig_bytes = bytes.fromhex(signature_hex[2:] if signature_hex.startswith("0x") else signature_hex)
        c = w3.eth.contract(address=to_checksum_address(address), abi=abi)
        res = c.functions.isValidSignature(h, sig_bytes).call()
        return bytes(res)[:4] == bytes.fromhex("1626ba7e")
    except Exception:
        return False


def verify_owner_signature(address: str, message: bytes, signature_hex: str) -> bool:
    if _verify_eip191(address, message, signature_hex):
        return True
    return _verify_eip1271(address, message, signature_hex)


# --------------------------------------------------------------------------- #
# Consume – atomar
# --------------------------------------------------------------------------- #
def consume(
    *,
    challenge_id: str,
    owner_wallet: str,
    operation: str,
    agent_id: Optional[str],
    signature_hex: str,
) -> dict[str, Any]:
    """Verify signature and atomically consume the challenge.
    Returns the row snapshot on success or raises `OwnerChallengeError`.
    """
    if operation not in OWNER_OPS:
        raise OwnerChallengeError("invalid_operation")
    owner = owner_wallet.lower()

    with repository.transaction() as conn:
        row = conn.execute(
            "SELECT * FROM owner_challenges WHERE challenge_id=? AND owner_wallet=? "
            "AND operation=? AND consumed_at IS NULL AND expires_at > ?",
            (challenge_id, owner, operation, repository.utcnow_iso()),
        ).fetchone()
        if row is None:
            raise OwnerChallengeError("invalid_owner_challenge")
        # cross-operation binding: agent_id must match (both NULL or equal)
        stored_agent = row["agent_id"]
        if (stored_agent or None) != (agent_id or None):
            raise OwnerChallengeError("owner_challenge_operation_mismatch")

        rec = {
            "challenge_id": row["challenge_id"],
            "owner_wallet": row["owner_wallet"],
            "agent_id": row["agent_id"] or "",
            "operation": row["operation"],
            "challenge": row["challenge"],
            "expires_at": row["expires_at"],
        }
        message = build_signed_payload(rec)
        if not verify_owner_signature(owner, message, signature_hex):
            raise OwnerChallengeError("invalid_owner_signature")

        cur = conn.execute(
            "UPDATE owner_challenges SET consumed_at=? "
            "WHERE challenge_id=? AND consumed_at IS NULL",
            (repository.utcnow_iso(), challenge_id),
        )
        if cur.rowcount != 1:
            raise OwnerChallengeError("invalid_owner_challenge")

    return rec
