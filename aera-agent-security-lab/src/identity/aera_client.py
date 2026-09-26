"""Real AEra Agent identity client.

Implements exactly the documented flow:
  1. POST /api/agents/owner-challenge
  2. EIP-191 sign the canonical owner-challenge payload
  3. POST /api/agents/register
  4. POST /api/agents/{agent_id}/challenge
  5. Ed25519 sign the canonical agent-auth payload
  6. POST /api/agents/{agent_id}/authenticate
  7. receive the real Agent JWT

No fake JWTs. No fake signatures. No security check is bypassed.
Owner EOAs are DISPOSABLE and generated locally; the user's real wallet key is
never requested, read or stored.
"""
from __future__ import annotations

import secrets
import time
from typing import Any, Optional

import httpx
from eth_account import Account
from eth_account.messages import encode_defunct

from ..crypto.aera_crypto import (
    AGENT_AUTH_KEYS,
    AUD_AGENT_API,
    AUD_AGENT_RELAY,
    OWNER_CHALLENGE_KEYS,
    OWNER_DOMAIN,
    PROTO_AGENT_AUTH,
    PROTO_OWNER_CHALLENGE,
    PROTOCOL_VERSION,
    Ed25519Signer,
    b64u_encode,
    canonical_json,
)


class AeraError(RuntimeError):
    def __init__(self, status: int, body: Any) -> None:
        self.status = status
        self.body = body
        super().__init__(f"HTTP {status}: {body}")

    @property
    def agent_error(self) -> Optional[str]:
        return agent_error_of_body(self.body)


def agent_error_of_body(body: Any) -> Optional[str]:
    if isinstance(body, dict):
        detail = body.get("detail", body)
        if isinstance(detail, dict):
            return detail.get("agent_error")
    return None


def agent_error_of(resp: httpx.Response) -> Optional[str]:
    try:
        return agent_error_of_body(resp.json())
    except Exception:
        return None


class AeraIdentityClient:
    """One AEra agent identity: disposable owner EOA + Ed25519 agent key."""

    #: audiences for which a token is cached
    _SKEW = 30

    def __init__(self, http: httpx.Client, *, name: str) -> None:
        self.http = http
        self.name = name
        # Disposable owner EOA -- never a real user wallet.
        self._eth = Account.from_key("0x" + secrets.token_hex(32))
        self.owner_wallet: str = self._eth.address.lower()
        self._signer = Ed25519Signer.generate()
        self.agent_id: Optional[str] = None
        self.key_id: Optional[str] = None
        self.capabilities: list[str] = []
        self._tokens: dict[str, tuple[str, int, str]] = {}  # aud -> (token, exp, jti)

    # -- exposure guards -----------------------------------------------------
    @property
    def public_key(self) -> str:
        return self._signer.public_key_encoded()

    def sign_ed25519(self, data: bytes) -> str:
        """The ONLY way the private key is used. It is never returned."""
        return b64u_encode(self._signer.sign(data))

    def __repr__(self) -> str:  # never leak keys via repr/logs
        return f"<AeraIdentityClient {self.name} agent_id={self.agent_id}>"

    # -- owner authorisation -------------------------------------------------
    def _owner_challenge(self, operation: str, *, agent_id: Optional[str] = None) -> dict:
        r = self.http.post(
            "/api/agents/owner-challenge",
            json={"owner_wallet": self.owner_wallet, "operation": operation,
                  "agent_id": agent_id},
        )
        if r.status_code != 200:
            raise AeraError(r.status_code, _safe_json(r))
        return r.json()

    def _owner_sign(self, rec: dict) -> str:
        canon = canonical_json(
            {
                "protocol": PROTO_OWNER_CHALLENGE,
                "version": PROTOCOL_VERSION,
                "owner_wallet": rec["owner_wallet"],
                "agent_id": rec.get("agent_id") or "",
                "operation": rec["operation"],
                "challenge_id": rec["challenge_id"],
                "challenge": rec["challenge"],
                "expires_at": rec["expires_at"],
                "domain": OWNER_DOMAIN,
            },
            OWNER_CHALLENGE_KEYS,
        )
        sig = self._eth.sign_message(encode_defunct(primitive=canon)).signature
        return sig.hex() if isinstance(sig, (bytes, bytearray)) else sig

    # -- lifecycle -----------------------------------------------------------
    def register(self, *, capabilities: Optional[list[str]] = None,
                 label: Optional[str] = None) -> dict:
        ch = self._owner_challenge("register")
        r = self.http.post(
            "/api/agents/register",
            json={
                "owner_wallet": self.owner_wallet,
                "owner_challenge_id": ch["challenge_id"],
                "owner_signature": self._owner_sign(ch),
                "public_key": self.public_key,
                "label": label,
                "capabilities": capabilities,
            },
        )
        if r.status_code != 200:
            raise AeraError(r.status_code, _safe_json(r))
        data = r.json()
        self.agent_id = data["agent_id"]
        self.key_id = data["key_id"]
        self.capabilities = data["capabilities"]
        return data

    def revoke(self) -> httpx.Response:
        ch = self._owner_challenge("agent_revoke", agent_id=self.agent_id)
        return self.http.request(
            "DELETE", f"/api/agents/{self.agent_id}",
            json={
                "owner_wallet": self.owner_wallet,
                "owner_challenge_id": ch["challenge_id"],
                "owner_signature": self._owner_sign(ch),
                "public_key": self.public_key,
            },
        )

    def get_public_metadata(self) -> httpx.Response:
        return self.http.get(f"/api/agents/{self.agent_id}")

    # -- authentication ------------------------------------------------------
    def authenticate(self, *, aud: str) -> str:
        """Full real challenge/response. Returns the Agent JWT."""
        r = self.http.post(f"/api/agents/{self.agent_id}/challenge",
                           json={"key_id": self.key_id, "aud": aud})
        if r.status_code != 200:
            raise AeraError(r.status_code, _safe_json(r))
        ch = r.json()
        payload = {
            "protocol": PROTO_AGENT_AUTH,
            "version": PROTOCOL_VERSION,
            "agent_id": self.agent_id,
            "key_id": self.key_id,
            "challenge_id": ch["challenge_id"],
            "challenge": ch["challenge"],
            "aud": aud,
            "issued_at": ch["issued_at"],
            "expires_at": ch["expires_at"],
        }
        sig = self.sign_ed25519(canonical_json(payload, AGENT_AUTH_KEYS))
        r = self.http.post(
            f"/api/agents/{self.agent_id}/authenticate",
            json={"challenge_id": ch["challenge_id"], "key_id": self.key_id,
                  "aud": aud, "signature": sig},
        )
        if r.status_code != 200:
            raise AeraError(r.status_code, _safe_json(r))
        data = r.json()
        self._tokens[aud] = (data["token"], int(data["expires_at"]), data["jti"])
        return data["token"]

    def token(self, *, aud: str) -> str:
        """Cached per-audience token. NEVER reuses an api token for the relay."""
        cached = self._tokens.get(aud)
        if cached and cached[1] - self._SKEW > int(time.time()):
            return cached[0]
        return self.authenticate(aud=aud)

    def jti(self, *, aud: str) -> Optional[str]:
        c = self._tokens.get(aud)
        return c[2] if c else None

    def auth_header(self, *, aud: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token(aud=aud)}"}

    def relay_header(self) -> dict[str, str]:
        return self.auth_header(aud=AUD_AGENT_RELAY)

    def api_header(self) -> dict[str, str]:
        return self.auth_header(aud=AUD_AGENT_API)

    def verify_jwt(self) -> httpx.Response:
        return self.http.post("/api/agents/verify-jwt", headers=self.api_header())

    def self_revoke_token(self, *, aud: str) -> httpx.Response:
        return self.http.post("/api/agents/tokens/revoke",
                              json={"jti": self.jti(aud=aud)},
                              headers=self.api_header())


def _safe_json(r: httpx.Response) -> Any:
    try:
        return r.json()
    except Exception:
        return r.text[:300]
