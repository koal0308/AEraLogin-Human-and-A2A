"""Helpers for the isolated test suite (test-only)."""
from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone

from eth_account.messages import encode_defunct


def build_siwe_message(address: str, nonce: str, *, domain="testserver",
                       uri="http://testserver", chain_id=8453) -> str:
    issued_at = datetime.now(timezone.utc).isoformat()
    return (
        f"{domain} wants you to sign in with your Ethereum account:\n"
        f"{address}\n\n"
        f"Sign in to AEraLogIn for third-party authorization\n\n"
        f"URI: {uri}\n"
        f"Version: 1\n"
        f"Chain ID: {chain_id}\n"
        f"Nonce: {nonce}\n"
        f"Issued At: {issued_at}"
    )


def sign_siwe(account, message: str) -> str:
    signed = account.sign_message(encode_defunct(text=message))
    return signed.signature.hex() if isinstance(signed.signature, (bytes, bytearray)) else signed.signature


def register_token_lifecycle(server_module, token, *, status="active"):
    """
    Create the S-02 lifecycle row for a hand-minted test token.

    Production tokens get this row automatically via
    issue_oauth_access_token(). Tests that forge tokens directly must create
    it explicitly, otherwise the verifier correctly rejects them as unknown.
    """
    import jwt as _jwt
    from datetime import datetime, timezone

    payload = _jwt.decode(token, options={"verify_signature": False})
    conn = server_module.get_db_connection()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO oauth_token_jti "
            "(jti, sub, client_id, issued_at, expires_at, status) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (payload.get("jti"),
             (payload.get("sub") or "").lower(),
             payload.get("aud") if isinstance(payload.get("aud"), str) else "",
             datetime.fromtimestamp(payload.get("iat", 0), tz=timezone.utc).isoformat(),
             datetime.fromtimestamp(payload.get("exp", 0), tz=timezone.utc).isoformat(),
             status),
        )
        conn.commit()
    finally:
        conn.close()
    return payload.get("jti")
