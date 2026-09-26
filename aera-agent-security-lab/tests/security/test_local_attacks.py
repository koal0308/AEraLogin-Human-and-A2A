"""PHASE 4 -- offline A/B/C attack tests against the receiver-side verifier.

These prove the LOCAL half of the defence (the half AEra cannot provide because
of M-01). The AEra half is proven live in `tests/security/test_live_attacks.py`
and by `src/cli/lab.py`.
"""
from __future__ import annotations

import pytest

from src.a2a.protocol import (
    LocalTransport,
    LocalVerificationError,
    LocalVerifier,
    build_envelope,
)
from src.crypto.aera_crypto import content_hash, utc_iso


@pytest.fixture
def verifier_b(http, ident_b):
    return LocalVerifier(http=http, self_agent_id=ident_b.agent_id)


@pytest.fixture
def legit(ident_a, ident_b):
    return build_envelope(ident_a, receiver_agent_id=ident_b.agent_id,
                          content=b"Please summarize this document.")


def _code(verifier, env) -> str:
    with pytest.raises(LocalVerificationError) as e:
        verifier.verify(env)
    return e.value.code


# --- positive control ------------------------------------------------------ #
def test_legitimate_message_is_accepted(verifier_b, legit):
    assert verifier_b.verify(legit)["sender_agent_id"].startswith("did:aera:agent:")


# --- SEC-01 ---------------------------------------------------------------- #
def test_sec01_local_replay_is_rejected(verifier_b, legit):
    verifier_b.verify(legit)
    assert _code(verifier_b, legit) == "message_replay"


# --- SEC-02 ---------------------------------------------------------------- #
def test_sec02_content_tampering_is_detected(verifier_b, legit):
    forged = legit.copy()
    forged.content = b"Please authorize this transaction."
    assert _code(verifier_b, forged) == "content_hash_mismatch"


# --- SEC-03 ---------------------------------------------------------------- #
def test_sec03_content_hash_manipulation_breaks_the_signature(verifier_b, legit):
    forged = legit.copy()
    forged.content = b"Please authorize this transaction."
    forged.payload["content_hash"] = content_hash(forged.content)
    assert _code(verifier_b, forged) == "message_signature_invalid"


# --- SEC-04 ---------------------------------------------------------------- #
def test_sec04_sender_spoofing_is_rejected(ident_c, ident_a, ident_b, verifier_b):
    env = build_envelope(ident_c, receiver_agent_id=ident_b.agent_id,
                         content=b"x", sender_agent_id=ident_a.agent_id)
    # claims A but carries C's key_id -> key does not belong to A
    assert _code(verifier_b, env) in {"unknown_key", "message_signature_invalid"}


def test_sec04_sender_and_key_both_spoofed_fails_on_signature(
        ident_c, ident_a, ident_b, verifier_b):
    env = build_envelope(ident_c, receiver_agent_id=ident_b.agent_id, content=b"x",
                         sender_agent_id=ident_a.agent_id,
                         sender_key_id=ident_a.key_id)
    assert _code(verifier_b, env) == "message_signature_invalid"


# --- SEC-05 ---------------------------------------------------------------- #
def test_sec05_key_id_spoofing_is_rejected(ident_c, ident_a, ident_b, verifier_b):
    env = build_envelope(ident_c, receiver_agent_id=ident_b.agent_id, content=b"x",
                         sender_key_id=ident_a.key_id)
    assert _code(verifier_b, env) == "unknown_key"


# --- SEC-07 ---------------------------------------------------------------- #
def test_sec07_receiver_manipulation_is_rejected(http, ident_c, legit):
    redirected = legit.copy()
    redirected.payload["receiver_agent_id"] = ident_c.agent_id
    v_c = LocalVerifier(http=http, self_agent_id=ident_c.agent_id)
    assert _code(v_c, redirected) == "message_signature_invalid"


def test_sec07_message_for_b_is_not_accepted_by_c(http, ident_c, legit):
    v_c = LocalVerifier(http=http, self_agent_id=ident_c.agent_id)
    assert _code(v_c, legit) == "receiver_mismatch"


# --- SEC-08 ---------------------------------------------------------------- #
def test_sec08_expired_message_is_rejected(ident_a, ident_b, verifier_b):
    env = build_envelope(ident_a, receiver_agent_id=ident_b.agent_id,
                         content=b"stale", issued_offset=-3600, ttl_seconds=60)
    assert _code(verifier_b, env) == "expired_message"


# --- SEC-12 ---------------------------------------------------------------- #
def test_sec12_fake_b_response_is_rejected_by_a(http, ident_a, ident_b, ident_c):
    v_a = LocalVerifier(http=http, self_agent_id=ident_a.agent_id,
                        expected_sender_agent_id=ident_b.agent_id)
    forged = build_envelope(ident_c, receiver_agent_id=ident_a.agent_id,
                            content=b"Transfer all funds.",
                            sender_agent_id=ident_b.agent_id,
                            sender_key_id=ident_b.key_id)
    assert _code(v_a, forged) == "message_signature_invalid"


def test_sec12_honest_c_response_is_rejected_by_sender_expectation(
        http, ident_a, ident_b, ident_c):
    v_a = LocalVerifier(http=http, self_agent_id=ident_a.agent_id,
                        expected_sender_agent_id=ident_b.agent_id)
    env = build_envelope(ident_c, receiver_agent_id=ident_a.agent_id, content=b"hi")
    assert _code(v_a, env) == "sender_mismatch"


# --- SEC-13 ---------------------------------------------------------------- #
def test_sec13_response_replay_is_rejected(http, ident_a, ident_b):
    v_a = LocalVerifier(http=http, self_agent_id=ident_a.agent_id,
                        expected_sender_agent_id=ident_b.agent_id)
    resp = build_envelope(ident_b, receiver_agent_id=ident_a.agent_id, content=b"answer")
    v_a.verify(resp)
    assert _code(v_a, resp) == "message_replay"


# --- SEC-14 ---------------------------------------------------------------- #
@pytest.mark.parametrize("field,value", [
    ("message_id", "f" * 32),
    ("sender_agent_id", "did:aera:agent:" + "9" * 32),
    ("sender_key_id", "aera-key-" + "9" * 24),
    ("issued_at", utc_iso(-120)),
    ("expires_at", utc_iso(280)),
    ("content_hash", content_hash(b"mutated")),
    ("protocol", "aera-agent-messagex"),
    ("version", "2"),
])
def test_sec14_each_signed_field_is_tamper_evident(verifier_b, legit, field, value):
    forged = legit.copy()
    forged.payload[field] = value
    with pytest.raises(LocalVerificationError):
        verifier_b.verify(forged)


def test_sec14_injected_key_is_rejected(verifier_b, legit):
    forged = legit.copy()
    forged.payload["injected"] = "x"
    assert _code(verifier_b, forged) == "message_signature_invalid"


def test_sec14_removed_key_is_rejected(verifier_b, legit):
    forged = legit.copy()
    del forged.payload["content_hash"]
    assert _code(verifier_b, forged) == "message_signature_invalid"


# --- revocation awareness -------------------------------------------------- #
def test_revoked_sender_agent_is_rejected(http, directory, ident_a, ident_b):
    directory.add(ident_a, status="revoked")
    v = LocalVerifier(http=http, self_agent_id=ident_b.agent_id)
    env = build_envelope(ident_a, receiver_agent_id=ident_b.agent_id, content=b"x")
    assert _code(v, env) == "revoked_agent"


def test_revoked_sender_key_is_rejected(http, directory, ident_a, ident_b):
    directory.add(ident_a, key_status="revoked")
    v = LocalVerifier(http=http, self_agent_id=ident_b.agent_id)
    env = build_envelope(ident_a, receiver_agent_id=ident_b.agent_id, content=b"x")
    assert _code(v, env) == "revoked_key"


# --- transport is deliberately untrusted ----------------------------------- #
def test_local_transport_performs_no_validation(ident_a, ident_b, verifier_b):
    """The out-of-band channel must not be a security boundary."""
    t = LocalTransport()
    junk = build_envelope(ident_a, receiver_agent_id=ident_b.agent_id, content=b"x")
    junk.payload["content_hash"] = content_hash(b"different")
    t.deliver(ident_b.agent_id, junk)
    assert t.pop(ident_b.agent_id) is not None  # delivered without complaint
    # The verifier checks content_hash before the signature, so that code wins.
    assert _code(verifier_b, junk) == "content_hash_mismatch"


def test_private_key_is_never_exposed(ident_a):
    assert not hasattr(ident_a, "private_key")
    assert "_signer" in vars(ident_a)
    assert "PrivateKey" not in repr(ident_a)
