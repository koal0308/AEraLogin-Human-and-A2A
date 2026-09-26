"""Unit tests: crypto primitives, base64url, canonical JSON."""
from __future__ import annotations

import pytest

from agent.crypto import (
    Ed25519Signer,
    b64u_decode,
    b64u_encode,
    canonical_json,
    decode_public_key,
    encode_public_key,
    verify_signature,
)


ALLOWED = {"a", "b", "c", "z_key"}


def test_b64u_roundtrip():
    for n in (0, 1, 15, 32, 64, 100):
        blob = bytes(range(n))
        assert b64u_decode(b64u_encode(blob)) == blob


def test_ed25519_sign_verify_roundtrip():
    s = Ed25519Signer.generate()
    pk = s.public_key_encoded()
    msg = b"hello canonical world"
    sig = b64u_encode(s.sign(msg))
    assert verify_signature(pk, sig, msg)
    assert not verify_signature(pk, sig, msg + b"x")


def test_ed25519_wrong_key_fails():
    s1, s2 = Ed25519Signer.generate(), Ed25519Signer.generate()
    sig = b64u_encode(s1.sign(b"data"))
    assert not verify_signature(s2.public_key_encoded(), sig, b"data")


def test_public_key_encoding_shape():
    raw = bytes(range(32))
    enc = encode_public_key(raw)
    assert enc.startswith("ed25519:")
    assert decode_public_key(enc) == raw
    with pytest.raises(ValueError):
        decode_public_key("noprefix:AA")


def test_canonical_json_sorts_keys():
    out = canonical_json({"b": "1", "a": "2"}, ALLOWED)
    assert out == b'{"a":"2","b":"1"}'


def test_canonical_json_rejects_unknown_key():
    with pytest.raises(ValueError):
        canonical_json({"a": "1", "unknown": "2"}, ALLOWED)


def test_canonical_json_rejects_float():
    with pytest.raises(ValueError):
        canonical_json({"a": 1.5}, ALLOWED)


def test_canonical_json_rejects_null_in_required():
    with pytest.raises(ValueError):
        canonical_json({"a": None}, ALLOWED)


def test_canonical_json_int_range():
    ok = (1 << 53) - 1
    assert canonical_json({"a": ok}, ALLOWED) == b'{"a":%d}' % ok
    with pytest.raises(ValueError):
        canonical_json({"a": 1 << 53}, ALLOWED)


def test_canonical_json_utf8_nfc():
    # é composed vs decomposed – must produce identical bytes after NFC.
    composed = canonical_json({"a": "\u00e9"}, ALLOWED)
    decomposed = canonical_json({"a": "e\u0301"}, ALLOWED)
    assert composed == decomposed


def test_canonical_json_string_escapes():
    out = canonical_json({"a": "line\nbreak\ttab\""}, ALLOWED)
    assert out == b'{"a":"line\\nbreak\\ttab\\""}'


def test_canonical_json_boolean_and_array():
    out = canonical_json({"a": True, "b": [1, 2, "x"]}, ALLOWED)
    assert out == b'{"a":true,"b":[1,2,"x"]}'


def test_canonical_json_no_nested_objects():
    with pytest.raises(ValueError):
        canonical_json({"a": {"nested": "x"}}, ALLOWED)


def test_canonical_json_reject_surrogate():
    with pytest.raises(ValueError):
        canonical_json({"a": "\ud800"}, ALLOWED)
