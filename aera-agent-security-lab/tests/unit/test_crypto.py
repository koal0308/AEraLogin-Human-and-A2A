"""PHASE 1 + 2 -- canonical JSON and Ed25519 must be the PRODUCTION ones."""
from __future__ import annotations

import hashlib

import pytest

from src.crypto import aera_crypto as lab
from src.crypto.aera_crypto import (
    AGENT_MESSAGE_KEYS,
    Ed25519Signer,
    b64u_encode,
    canonical_json,
    content_hash,
    verify_signature,
)


def test_lab_uses_the_production_canonical_json():
    """The lab must not ship its own encoder (silent divergence risk)."""
    import agent.crypto as prod
    assert lab.canonical_json is prod.canonical_json
    assert lab.verify_signature is prod.verify_signature
    assert lab.Ed25519Signer is prod.Ed25519Signer


def test_lab_constants_are_the_production_constants():
    import agent.constants as prod
    assert lab.AGENT_MESSAGE_KEYS is prod.AGENT_MESSAGE_KEYS
    assert lab.PROTO_AGENT_MESSAGE == prod.PROTO_AGENT_MESSAGE
    assert lab.PROTOCOL_VERSION == prod.PROTOCOL_VERSION


def test_content_hash_matches_production_helper():
    from agent.messages import content_hash as prod_ch
    for blob in (b"", b"hello", "über".encode("utf-8"), b"\x00\xff" * 100):
        assert content_hash(blob) == prod_ch(blob)


def test_content_hash_format():
    h = content_hash(b"abc")
    assert h.startswith("sha256:")
    assert h == "sha256:" + b64u_encode(hashlib.sha256(b"abc").digest())
    assert "=" not in h


def test_canonical_json_is_deterministic_and_sorted():
    p = {"b": "2", "a": "1", "c": 3}
    assert canonical_json(p, {"a", "b", "c"}) == b'{"a":"1","b":"2","c":3}'
    assert canonical_json({"c": 3, "a": "1", "b": "2"}, {"a", "b", "c"}) == \
        canonical_json(p, {"a", "b", "c"})


def test_canonical_json_rejects_keys_outside_the_allowlist():
    with pytest.raises(ValueError):
        canonical_json({"a": "1", "evil": "x"}, {"a"})


@pytest.mark.parametrize("bad", [{"a": None}, {"a": 1.5}, {"a": {"n": 1}}])
def test_canonical_json_rejects_forbidden_value_types(bad):
    with pytest.raises(ValueError):
        canonical_json(bad, {"a"})


def test_ed25519_sign_and_verify_roundtrip():
    s = Ed25519Signer.generate()
    data = canonical_json({"a": "1"}, {"a"})
    sig = b64u_encode(s.sign(data))
    assert verify_signature(s.public_key_encoded(), sig, data)


def test_ed25519_rejects_foreign_key():
    s1, s2 = Ed25519Signer.generate(), Ed25519Signer.generate()
    data = b"payload"
    sig = b64u_encode(s1.sign(data))
    assert not verify_signature(s2.public_key_encoded(), sig, data)


def test_ed25519_rejects_mutated_data():
    s = Ed25519Signer.generate()
    sig = b64u_encode(s.sign(b"payload"))
    assert not verify_signature(s.public_key_encoded(), sig, b"payloae")


def test_signature_over_message_payload_is_bound_to_every_field(ident_a):
    from src.a2a.protocol import build_envelope
    env = build_envelope(ident_a, receiver_agent_id="did:aera:agent:" + "2" * 32,
                         content=b"hi")
    canon = canonical_json(env.payload, AGENT_MESSAGE_KEYS)
    assert verify_signature(ident_a.public_key, env.signature, canon)
    for field in AGENT_MESSAGE_KEYS:
        mutated = dict(env.payload)
        mutated[field] = mutated[field] + "X" if isinstance(mutated[field], str) else "X"
        bad = canonical_json(mutated, AGENT_MESSAGE_KEYS)
        assert not verify_signature(ident_a.public_key, env.signature, bad), field
