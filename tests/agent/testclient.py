"""Reusable in-process test client for the Agent Identity Layer."""
from __future__ import annotations

import secrets
from typing import Any, Optional

from eth_account import Account
from eth_account.messages import encode_defunct

from agent.constants import (
    AGENT_AUTH_KEYS,
    AGENT_MESSAGE_KEYS,
    AUD_AGENT_API,
    AUD_AGENT_RELAY,
    MESSAGE_TTL_SECONDS,
    OWNER_CHALLENGE_KEYS,
    OWNER_DOMAIN,
    PROTO_AGENT_AUTH,
    PROTO_AGENT_MESSAGE,
    PROTO_OWNER_CHALLENGE,
    PROTOCOL_VERSION,
)
from agent.crypto import Ed25519Signer, b64u_encode, canonical_json


ANVIL_KEY_1 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
ANVIL_KEY_2 = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"


class AgentTestClient:
    def __init__(self, http, *, eth_priv: str = ANVIL_KEY_1) -> None:
        self.http = http
        self.eth = Account.from_key(eth_priv)
        self.owner = self.eth.address.lower()
        self.signer = Ed25519Signer.generate()
        self.agent_id: Optional[str] = None
        self.key_id: Optional[str] = None
        self.token: Optional[str] = None
        self.jwt_aud: Optional[str] = None

    # -- owner sig helper ---------------------------------------------------
    def _owner_sign(self, rec: dict) -> str:
        canon = canonical_json({
            "protocol": PROTO_OWNER_CHALLENGE,
            "version": PROTOCOL_VERSION,
            "owner_wallet": rec["owner_wallet"],
            "agent_id": rec.get("agent_id") or "",
            "operation": rec["operation"],
            "challenge_id": rec["challenge_id"],
            "challenge": rec["challenge"],
            "expires_at": rec["expires_at"],
            "domain": OWNER_DOMAIN,
        }, OWNER_CHALLENGE_KEYS)
        signed = self.eth.sign_message(encode_defunct(primitive=canon))
        sig = signed.signature
        return sig.hex() if isinstance(sig, (bytes, bytearray)) else sig

    def owner_challenge(self, operation: str, *, agent_id: Optional[str] = None) -> dict:
        r = self.http.post("/api/agents/owner-challenge", json={
            "owner_wallet": self.owner, "operation": operation, "agent_id": agent_id,
        })
        assert r.status_code == 200, r.text
        return r.json()

    # -- lifecycle ----------------------------------------------------------
    def register(self, *, capabilities: Optional[list[str]] = None) -> dict:
        ch = self.owner_challenge("register")
        sig = self._owner_sign(ch)
        r = self.http.post("/api/agents/register", json={
            "owner_wallet": self.owner,
            "owner_challenge_id": ch["challenge_id"],
            "owner_signature": sig,
            "public_key": self.signer.public_key_encoded(),
            "capabilities": capabilities,
        })
        assert r.status_code == 200, r.text
        data = r.json()
        self.agent_id = data["agent_id"]
        self.key_id = data["key_id"]
        return data

    def add_key(self, new_signer: Ed25519Signer) -> str:
        ch = self.owner_challenge("key_add", agent_id=self.agent_id)
        sig = self._owner_sign(ch)
        r = self.http.post(f"/api/agents/{self.agent_id}/keys", json={
            "owner_wallet": self.owner,
            "owner_challenge_id": ch["challenge_id"],
            "owner_signature": sig,
            "public_key": new_signer.public_key_encoded(),
        })
        assert r.status_code == 200, r.text
        return r.json()["key_id"]

    def rotate_key(self, new_signer: Ed25519Signer, *, revoke: str) -> str:
        ch = self.owner_challenge("key_rotate", agent_id=self.agent_id)
        sig = self._owner_sign(ch)
        r = self.http.post(f"/api/agents/{self.agent_id}/keys/rotate", json={
            "owner_wallet": self.owner,
            "owner_challenge_id": ch["challenge_id"],
            "owner_signature": sig,
            "new_public_key": new_signer.public_key_encoded(),
            "revoke_key_id": revoke,
        })
        assert r.status_code == 200, r.text
        return r.json()["key_id"]

    def revoke_agent(self):
        ch = self.owner_challenge("agent_revoke", agent_id=self.agent_id)
        sig = self._owner_sign(ch)
        return self.http.request("DELETE", f"/api/agents/{self.agent_id}", json={
            "owner_wallet": self.owner,
            "owner_challenge_id": ch["challenge_id"],
            "owner_signature": sig,
            "public_key": self.signer.public_key_encoded(),
        })

    # -- auth ---------------------------------------------------------------
    def get_challenge(self, *, key_id: Optional[str] = None,
                      aud: str = AUD_AGENT_API):
        return self.http.post(f"/api/agents/{self.agent_id}/challenge", json={
            "key_id": key_id or self.key_id, "aud": aud,
        })

    def authenticate(self, *, aud: str = AUD_AGENT_API,
                     signer: Optional[Ed25519Signer] = None,
                     key_id: Optional[str] = None):
        r = self.get_challenge(key_id=key_id or self.key_id, aud=aud)
        assert r.status_code == 200, r.text
        ch = r.json()
        signer = signer or self.signer
        payload = {
            "protocol": PROTO_AGENT_AUTH,
            "version": PROTOCOL_VERSION,
            "agent_id": self.agent_id,
            "key_id": key_id or self.key_id,
            "challenge_id": ch["challenge_id"],
            "challenge": ch["challenge"],
            "aud": aud,
            "issued_at": ch["issued_at"],
            "expires_at": ch["expires_at"],
        }
        canon = canonical_json(payload, AGENT_AUTH_KEYS)
        sig = b64u_encode(signer.sign(canon))
        resp = self.http.post(f"/api/agents/{self.agent_id}/authenticate", json={
            "challenge_id": ch["challenge_id"],
            "key_id": key_id or self.key_id,
            "aud": aud,
            "signature": sig,
        })
        if resp.status_code == 200:
            data = resp.json()
            self.token = data["token"]
            self.jwt_aud = aud
        return resp

    def auth_headers(self) -> dict:
        assert self.token
        return {"Authorization": f"Bearer {self.token}"}

    # -- messages -----------------------------------------------------------
    def build_message(self, *, receiver: str, content: bytes = b"hi") -> tuple[dict, str]:
        import hashlib
        from datetime import datetime, timedelta, timezone
        now = datetime.now(timezone.utc)
        payload = {
            "protocol": PROTO_AGENT_MESSAGE,
            "version": PROTOCOL_VERSION,
            "message_id": secrets.token_hex(16),
            "sender_agent_id": self.agent_id,
            "sender_key_id": self.key_id,
            "receiver_agent_id": receiver,
            "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_at": (now + timedelta(seconds=MESSAGE_TTL_SECONDS)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "content_hash": "sha256:" + b64u_encode(hashlib.sha256(content).digest()),
        }
        canon = canonical_json(payload, AGENT_MESSAGE_KEYS)
        sig = b64u_encode(self.signer.sign(canon))
        return payload, sig

    def send_message(self, *, receiver: str, content: bytes = b"hi"):
        payload, sig = self.build_message(receiver=receiver, content=content)
        return self.http.post("/api/agents/messages",
                              json={"payload": payload, "signature": sig},
                              headers=self.auth_headers())
