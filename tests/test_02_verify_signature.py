"""Phase 4B – /api/verify EOA signature behaviour + REPLAY probe (Phase 5)."""
from __future__ import annotations

from eth_account.messages import encode_defunct

from _utils import build_siwe_message


def _sig(account, message: str) -> str:
    signed = account.sign_message(encode_defunct(text=message))
    sig = signed.signature
    hexstr = sig.hex() if hasattr(sig, "hex") else str(sig)
    return hexstr if hexstr.startswith("0x") else "0x" + hexstr


def _get_nonce(client, address: str) -> str:
    return client.post("/api/nonce",
                       json={"address": address}).json()["nonce"]


# ---------------------------------------------------------------------------
# Positive path
# ---------------------------------------------------------------------------
def test_valid_eoa_signature_accepted(client, db, eth_test_account):
    addr = eth_test_account.address.lower()
    nonce = _get_nonce(client, addr)
    msg = build_siwe_message(addr, nonce)
    sig = _sig(eth_test_account, msg)

    r = client.post("/api/verify",
                    json={"address": addr, "nonce": nonce,
                          "message": msg, "signature": sig})
    body = r.json()
    assert body.get("is_human") is True, body
    assert body["address"] == addr
    assert "token" in body


# ---------------------------------------------------------------------------
# Negative paths
# ---------------------------------------------------------------------------
def test_signature_from_other_wallet_rejected(client, db,
                                              eth_test_account,
                                              eth_second_account):
    addr = eth_test_account.address.lower()
    nonce = _get_nonce(client, addr)
    msg = build_siwe_message(addr, nonce)
    sig = _sig(eth_second_account, msg)  # signed by the WRONG wallet

    r = client.post("/api/verify",
                    json={"address": addr, "nonce": nonce,
                          "message": msg, "signature": sig})
    body = r.json()
    assert body.get("is_human") is False
    assert "Signature" in body.get("error", "") or "signature" in body.get("error", "").lower()


def test_missing_signature_rejected(client, eth_test_account):
    addr = eth_test_account.address.lower()
    nonce = _get_nonce(client, addr)
    r = client.post("/api/verify",
                    json={"address": addr, "nonce": nonce,
                          "message": "irrelevant", "signature": ""})
    assert r.json().get("is_human") is False


def test_missing_nonce_rejected(client, eth_test_account):
    r = client.post("/api/verify",
                    json={"address": eth_test_account.address.lower(),
                          "nonce": "", "message": "x", "signature": "0xdead"})
    assert r.json().get("is_human") is False


def test_invalid_address_format(client, eth_test_account):
    r = client.post("/api/verify",
                    json={"address": "0xNOTVALID", "nonce": "n",
                          "message": "m", "signature": "0xdead"})
    body = r.json()
    assert body.get("is_human") is False


def test_garbage_signature_rejected(client, eth_test_account):
    addr = eth_test_account.address.lower()
    nonce = _get_nonce(client, addr)
    msg = build_siwe_message(addr, nonce)
    r = client.post("/api/verify",
                    json={"address": addr, "nonce": nonce,
                          "message": msg, "signature": "0x" + "ab" * 65})
    assert r.json().get("is_human") is False


# ---------------------------------------------------------------------------
# Phase 5 – Nonce/Signature REPLAY
# ---------------------------------------------------------------------------
def test_replay_of_login_nonce_and_signature(client, db, eth_test_account):
    """Audit finding S-03: /api/verify nonces are NOT persisted.

    Reproduce by re-submitting the exact same nonce+signature twice.
    Documented outcome (pass/fail) is recorded in the test report generator.
    """
    addr = eth_test_account.address.lower()
    nonce = _get_nonce(client, addr)
    msg = build_siwe_message(addr, nonce)
    sig = _sig(eth_test_account, msg)

    r1 = client.post("/api/verify",
                     json={"address": addr, "nonce": nonce,
                           "message": msg, "signature": sig}).json()
    r2 = client.post("/api/verify",
                     json={"address": addr, "nonce": nonce,
                           "message": msg, "signature": sig}).json()

    # Assertion below EXPRESSES the audit-finding as an executable fact:
    # If BOTH requests return is_human=True, replay is possible ⇒ S-03 confirmed.
    both_accepted = r1.get("is_human") is True and r2.get("is_human") is True
    # We do NOT fail the test on replay – we RECORD it.
    # Report generator (test_99_report.py) reads back this attribute.
    test_replay_of_login_nonce_and_signature.replay_accepted = both_accepted  # type: ignore[attr-defined]
    assert r1.get("is_human") is True, "first login must succeed as a baseline"
    # S-03 fixed: the nonce is single use.
    assert r2.get("is_human") is not True, "replayed login nonce+signature was accepted"


def test_unissued_nonce_is_rejected(client, db, eth_test_account):
    """A self-chosen nonce (never issued by /api/nonce) must not log in."""
    addr = eth_test_account.address.lower()
    nonce = "a" * 32
    msg = build_siwe_message(addr, nonce)
    r = client.post("/api/verify", json={"address": addr, "nonce": nonce,
                                         "message": msg,
                                         "signature": _sig(eth_test_account, msg)}).json()
    assert r.get("is_human") is not True


def test_nonce_is_bound_to_its_address(client, db, eth_test_account):
    """A nonce issued for another address cannot be used."""
    from eth_account import Account
    other = Account.create().address.lower()
    nonce = _get_nonce(client, other)
    addr = eth_test_account.address.lower()
    msg = build_siwe_message(addr, nonce)
    r = client.post("/api/verify", json={"address": addr, "nonce": nonce,
                                         "message": msg,
                                         "signature": _sig(eth_test_account, msg)}).json()
    assert r.get("is_human") is not True


def test_expired_nonce_is_rejected(client, db, eth_test_account, server_module, monkeypatch):
    addr = eth_test_account.address.lower()
    nonce = _get_nonce(client, addr)
    monkeypatch.setattr(server_module, "LOGIN_NONCE_TTL_SECONDS", -1)
    msg = build_siwe_message(addr, nonce)
    r = client.post("/api/verify", json={"address": addr, "nonce": nonce,
                                         "message": msg,
                                         "signature": _sig(eth_test_account, msg)}).json()
    assert r.get("is_human") is not True


def test_bad_signature_does_not_burn_the_nonce(client, db, eth_test_account):
    """Consumption happens only after a valid signature."""
    addr = eth_test_account.address.lower()
    nonce = _get_nonce(client, addr)
    msg = build_siwe_message(addr, nonce)
    bad = client.post("/api/verify", json={"address": addr, "nonce": nonce,
                                           "message": msg, "signature": "0x" + "11" * 65}).json()
    assert bad.get("is_human") is not True
    good = client.post("/api/verify", json={"address": addr, "nonce": nonce,
                                            "message": msg,
                                            "signature": _sig(eth_test_account, msg)}).json()
    assert good.get("is_human") is True
