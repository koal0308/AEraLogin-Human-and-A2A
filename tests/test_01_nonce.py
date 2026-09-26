"""Phase 4A – /api/nonce baseline."""
from __future__ import annotations


def test_nonce_endpoint_returns_success(client):
    r = client.post("/api/nonce",
                    json={"address": "0x" + "a" * 40})
    assert r.status_code == 200
    data = r.json()
    assert data["success"] is True
    assert isinstance(data["nonce"], str) and len(data["nonce"]) == 32


def test_nonces_are_random_and_distinct(client):
    addr = "0x" + "b" * 40
    nonces = {client.post("/api/nonce", json={"address": addr})
                    .json()["nonce"] for _ in range(20)}
    assert len(nonces) == 20, "Nonces must be unique across requests"


def test_invalid_address_rejected(client):
    r = client.post("/api/nonce", json={"address": "not-an-eth-address"})
    body = r.json()
    assert body.get("success") is False
    assert "Invalid address" in body.get("error", "")


def test_missing_address_is_rejected_softly(client):
    r = client.post("/api/nonce", json={})
    body = r.json()
    assert body.get("success") is False
