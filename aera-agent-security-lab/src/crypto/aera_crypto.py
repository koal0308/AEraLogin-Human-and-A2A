"""Canonical JSON + Ed25519, re-exported from the PRODUCTION AEra implementation.

The task requires the *exact* canonical JSON implementation used by AEra.
Re-implementing it would risk silent divergence and would make every signature
test meaningless. Therefore this module imports the production primitives
READ-ONLY. Nothing in `agent/` is modified, monkey-patched or shadowed.

If this import ever fails, the lab must fail loudly rather than fall back to a
generic `json.dumps` -- see `tests/unit/test_canonical_is_production.py`.
"""
from __future__ import annotations

import sys
from pathlib import Path

_AERA_ROOT = Path(__file__).resolve().parents[3]
if str(_AERA_ROOT) not in sys.path:
    sys.path.insert(0, str(_AERA_ROOT))

from agent.constants import (  # noqa: E402
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
from agent.crypto import (  # noqa: E402
    Ed25519Signer,
    b64u_decode,
    b64u_encode,
    canonical_json,
    decode_public_key,
    encode_public_key,
    verify_signature,
)

__all__ = [
    "AGENT_AUTH_KEYS", "AGENT_MESSAGE_KEYS", "AUD_AGENT_API", "AUD_AGENT_RELAY",
    "MESSAGE_TTL_SECONDS", "OWNER_CHALLENGE_KEYS", "OWNER_DOMAIN",
    "PROTO_AGENT_AUTH", "PROTO_AGENT_MESSAGE", "PROTO_OWNER_CHALLENGE",
    "PROTOCOL_VERSION", "Ed25519Signer", "b64u_decode", "b64u_encode",
    "canonical_json", "decode_public_key", "encode_public_key",
    "verify_signature", "content_hash", "utc_iso",
]


def content_hash(content: bytes) -> str:
    """`sha256:<base64url-nopad(sha256(content))>` -- identical to
    `agent.messages.content_hash`, verified by a unit test."""
    import hashlib
    return "sha256:" + b64u_encode(hashlib.sha256(content).digest())


def utc_iso(offset_seconds: int = 0) -> str:
    from datetime import datetime, timedelta, timezone
    return (datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
