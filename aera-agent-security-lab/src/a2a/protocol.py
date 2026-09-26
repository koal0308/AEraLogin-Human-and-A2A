"""A2A envelope construction, AEra relay notarisation and LOCAL verification.

M-01 (see docs/AEra-agent-api-discovery.md): `POST /api/agents/messages` does
NOT transport or store content. It verifies and notarises the envelope.
Content therefore travels out-of-band over `LocalTransport`, and the receiving
runtime MUST independently re-derive `content_hash` and verify the sender's
Ed25519 signature before acting.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Any, Optional

import httpx

from ..crypto.aera_crypto import (
    AGENT_MESSAGE_KEYS,
    MESSAGE_TTL_SECONDS,
    PROTO_AGENT_MESSAGE,
    PROTOCOL_VERSION,
    canonical_json,
    content_hash,
    utc_iso,
    verify_signature,
)
from ..identity.aera_client import AeraIdentityClient, agent_error_of


@dataclass
class Envelope:
    """A signed A2A envelope plus the out-of-band content it commits to."""
    payload: dict[str, Any]
    signature: str
    content: bytes = b""

    def copy(self) -> "Envelope":
        return Envelope(dict(self.payload), self.signature, self.content)

    @property
    def message_id(self) -> str:
        return self.payload.get("message_id", "")


def build_envelope(
    sender: AeraIdentityClient,
    *,
    receiver_agent_id: str,
    content: bytes,
    ttl_seconds: int = MESSAGE_TTL_SECONDS,
    issued_offset: int = 0,
    sender_agent_id: Optional[str] = None,
    sender_key_id: Optional[str] = None,
    message_id: Optional[str] = None,
) -> Envelope:
    """Build and sign an envelope with the EXACT production key set.

    The override parameters exist solely so the attacker module can claim a
    foreign identity while still signing with its own key -- they never bypass
    a check, they produce the attack input.
    """
    payload = {
        "protocol": PROTO_AGENT_MESSAGE,
        "version": PROTOCOL_VERSION,
        "message_id": message_id or secrets.token_hex(16),
        "sender_agent_id": sender_agent_id or sender.agent_id,
        "sender_key_id": sender_key_id or sender.key_id,
        "receiver_agent_id": receiver_agent_id,
        "issued_at": utc_iso(issued_offset),
        "expires_at": utc_iso(issued_offset + ttl_seconds),
        "content_hash": content_hash(content),
    }
    sig = sender.sign_ed25519(canonical_json(payload, AGENT_MESSAGE_KEYS))
    return Envelope(payload=payload, signature=sig, content=content)


def relay(http: httpx.Client, env: Envelope, *, bearer: str) -> httpx.Response:
    """Submit the envelope to the REAL production relay for notarisation."""
    return http.post(
        "/api/agents/messages",
        json={"payload": env.payload, "signature": env.signature},
        headers={"Authorization": f"Bearer {bearer}"},
    )


# --------------------------------------------------------------------------- #
# Local (receiver-side) verification -- zero trust in the relay's verdict
# --------------------------------------------------------------------------- #
class LocalVerificationError(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass
class LocalVerifier:
    """Receiver-side checks. The receiver does NOT trust a message merely
    because AEra accepted the JWT."""

    http: httpx.Client
    self_agent_id: str
    expected_sender_agent_id: Optional[str] = None
    seen: set[tuple[str, str]] = field(default_factory=set)
    _key_cache: dict[str, dict[str, dict]] = field(default_factory=dict)

    def _keys_of(self, agent_id: str) -> dict[str, dict]:
        if agent_id not in self._key_cache:
            r = self.http.get(f"/api/agents/{agent_id}")
            if r.status_code != 200:
                raise LocalVerificationError("unknown_agent")
            data = r.json()
            if data.get("status") != "active":
                raise LocalVerificationError("revoked_agent")
            self._key_cache[agent_id] = {k["key_id"]: k for k in data.get("keys", [])}
        return self._key_cache[agent_id]

    def verify(self, env: Envelope) -> dict[str, Any]:
        p = env.payload

        # 1. exact protocol vocabulary
        if set(p.keys()) != set(AGENT_MESSAGE_KEYS):
            raise LocalVerificationError("message_signature_invalid")
        if p.get("protocol") != PROTO_AGENT_MESSAGE or p.get("version") != PROTOCOL_VERSION:
            raise LocalVerificationError("message_signature_invalid")

        # 2. receiver binding -- is this actually addressed to me?
        if p.get("receiver_agent_id") != self.self_agent_id:
            raise LocalVerificationError("receiver_mismatch")

        # 3. sender expectation (e.g. A only accepts responses from B)
        if (self.expected_sender_agent_id
                and p.get("sender_agent_id") != self.expected_sender_agent_id):
            raise LocalVerificationError("sender_mismatch")

        # 4. expiry
        if p.get("expires_at", "") <= utc_iso():
            raise LocalVerificationError("expired_message")

        # 5. local replay window
        key = (p["receiver_agent_id"], p["message_id"])
        if key in self.seen:
            raise LocalVerificationError("message_replay")

        # 6. sender key must belong to the claimed sender AND be active
        keys = self._keys_of(p["sender_agent_id"])
        k = keys.get(p["sender_key_id"])
        if k is None:
            raise LocalVerificationError("unknown_key")
        if k.get("status") != "active":
            raise LocalVerificationError("revoked_key")

        # 7. content_hash independently recomputed from the received bytes
        if content_hash(env.content) != p["content_hash"]:
            raise LocalVerificationError("content_hash_mismatch")

        # 8. Ed25519 signature over the canonical payload
        try:
            canon = canonical_json(p, AGENT_MESSAGE_KEYS)
        except ValueError:
            raise LocalVerificationError("message_signature_invalid")
        if not verify_signature(k["public_key"], env.signature, canon):
            raise LocalVerificationError("message_signature_invalid")

        self.seen.add(key)
        return p


class LocalTransport:
    """Out-of-band content channel (M-01 workaround).

    Deliberately dumb and completely untrusted: it performs NO validation at
    all, so that every security property is proven by AEra or by LocalVerifier.
    """

    def __init__(self) -> None:
        self.inbox: dict[str, list[Envelope]] = {}
        self.log: list[tuple[str, str]] = []

    def deliver(self, receiver_agent_id: str, env: Envelope) -> None:
        self.inbox.setdefault(receiver_agent_id, []).append(env)
        self.log.append((receiver_agent_id, env.message_id))

    def pop(self, receiver_agent_id: str) -> Optional[Envelope]:
        q = self.inbox.get(receiver_agent_id) or []
        return q.pop(0) if q else None


def relay_error(resp: httpx.Response) -> Optional[str]:
    return agent_error_of(resp)
