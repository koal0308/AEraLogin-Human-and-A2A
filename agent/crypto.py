"""Crypto primitives for the Agent Identity Layer.

Ed25519 (via `cryptography`), base64url-nopad, and a strict deterministic
canonical JSON encoder for the restricted payload profile of Spec §7.

Restricted profile (v1.2 §7.1):
  * Fixed ASCII property names only – validated against a per-protocol allowlist.
  * Values may be str, int, bool, or list of these. No None. No floats.
  * Strings are NFC-normalized UTF-8; escaping per RFC 8259 minimum-escape.
  * Object keys sorted by UTF-16 codepoint order (RFC 8785 §3.2.3).

The encoder is hand-rolled to guarantee byte-identical output to a matching
Node.js counterpart (see `tests/agent/interop/canonical_check.js`).
"""
from __future__ import annotations

import base64
import re
import unicodedata
from typing import Any, Iterable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

# --------------------------------------------------------------------------- #
# base64url no-pad
# --------------------------------------------------------------------------- #
def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    s = text.encode("ascii") if isinstance(text, str) else text
    pad = (-len(s)) % 4
    return base64.urlsafe_b64decode(s + b"=" * pad)


# --------------------------------------------------------------------------- #
# Ed25519 wrappers
# --------------------------------------------------------------------------- #
class Ed25519Signer:
    """Wraps a private key. Only exists in test client / agent process."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._sk = private_key

    @classmethod
    def generate(cls) -> "Ed25519Signer":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_raw(cls, raw32: bytes) -> "Ed25519Signer":
        if len(raw32) != 32:
            raise ValueError("Ed25519 private key must be 32 bytes")
        return cls(Ed25519PrivateKey.from_private_bytes(raw32))

    def raw_private(self) -> bytes:
        return self._sk.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def raw_public(self) -> bytes:
        return self._sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def public_key_encoded(self) -> str:
        return encode_public_key(self.raw_public())

    def sign(self, data: bytes) -> bytes:
        return self._sk.sign(data)


def encode_public_key(raw32: bytes) -> str:
    """`ed25519:<base64url-nopad(32B)>`."""
    if len(raw32) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    return "ed25519:" + b64u_encode(raw32)


def decode_public_key(text: str) -> bytes:
    if not isinstance(text, str) or not text.startswith("ed25519:"):
        raise ValueError("Invalid public key encoding (missing ed25519: prefix)")
    raw = b64u_decode(text[len("ed25519:"):])
    if len(raw) != 32:
        raise ValueError("Ed25519 public key must decode to 32 bytes")
    return raw


def public_key_fingerprint(text: str) -> str:
    """Short human-comparable fingerprint of a public key.

    SHA-256 over the raw 32 bytes, first 10 bytes as 5 groups of 4 hex chars
    (80 bits). Shown by the runtime AND the dashboard during pairing so the
    owner can confirm that the key AEra received is the one their runtime
    generated. Public data; not a secret.
    """
    import hashlib

    digest = hashlib.sha256(decode_public_key(text)).hexdigest()[:20].upper()
    return "-".join(digest[i:i + 4] for i in range(0, 20, 4))


def verify_signature(public_key_encoded_str: str, signature_b64u: str, data: bytes) -> bool:
    """Return True iff signature is valid for `data` under given public key."""
    try:
        raw_pk = decode_public_key(public_key_encoded_str)
        sig = b64u_decode(signature_b64u)
        if len(sig) != 64:
            return False
        Ed25519PublicKey.from_public_bytes(raw_pk).verify(sig, data)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


# --------------------------------------------------------------------------- #
# Canonical JSON – restricted profile, hand-rolled deterministic encoder.
# --------------------------------------------------------------------------- #

_INT_MAX = (1 << 53) - 1
_INT_MIN = -_INT_MAX
_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

_ESCAPE_MAP = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: "\\\"",
    0x5C: "\\\\",
}


def _escape_string(s: str) -> str:
    # NFC first
    s = unicodedata.normalize("NFC", s)
    out = ["\""]
    for ch in s:
        cp = ord(ch)
        if 0xD800 <= cp <= 0xDFFF:
            raise ValueError("Surrogate code point not allowed in canonical string")
        esc = _ESCAPE_MAP.get(cp)
        if esc is not None:
            out.append(esc)
        elif cp < 0x20:
            out.append("\\u%04x" % cp)
        else:
            out.append(ch)
    out.append("\"")
    return "".join(out)


def _encode_value(v: Any) -> str:
    if v is True:
        return "true"
    if v is False:
        return "false"
    if v is None:
        raise ValueError("null values not allowed in canonical payload")
    if isinstance(v, bool):  # already handled, defensive
        return "true" if v else "false"
    if isinstance(v, int):
        if not (_INT_MIN <= v <= _INT_MAX):
            raise ValueError(f"integer out of JS-safe range: {v}")
        return str(v)
    if isinstance(v, float):
        raise ValueError("float values not allowed in canonical payload")
    if isinstance(v, str):
        return _escape_string(v)
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(_encode_value(x) for x in v) + "]"
    if isinstance(v, Mapping):
        raise ValueError("nested objects not allowed in canonical payload (Phase 1)")
    raise ValueError(f"unsupported value type: {type(v).__name__}")


def canonical_json(payload: Mapping[str, Any], allowed_keys: Iterable[str]) -> bytes:
    """Return the canonical UTF-8 bytes of `payload`.

    * Every key in payload MUST be in `allowed_keys` (fixed vocabulary per protocol).
    * Keys are sorted by UTF-16 codepoint order (for ASCII == byte order).
    * Values follow the restricted profile of Spec §7.
    """
    allowed = set(allowed_keys)
    seen = set()
    items = []
    for k, v in payload.items():
        if k in seen:
            raise ValueError(f"duplicate key: {k}")
        seen.add(k)
        if not isinstance(k, str) or not _KEY_RE.match(k):
            raise ValueError(f"invalid key syntax: {k!r}")
        if k not in allowed:
            raise ValueError(f"key not in protocol allowlist: {k}")
        if v is None:
            raise ValueError(f"required field {k} is null")
        items.append((k, v))
    # UTF-16 codepoint order; for ASCII keys identical to str order.
    items.sort(key=lambda kv: kv[0])
    body = ",".join(_escape_string(k) + ":" + _encode_value(v) for k, v in items)
    return ("{" + body + "}").encode("utf-8")
