"""Human Identity layer wired into the existing agent system (HTTP level)."""
from __future__ import annotations

import pytest

from agent import repository as agent_repo
from identity import repository as id_repo

from tests.agent.testclient import ANVIL_KEY_1, ANVIL_KEY_2, AgentTestClient


def _hdr(server_module, wallet):
    return {"Authorization": f"Bearer {server_module.generate_dashboard_jwt(wallet)}"}


def _owner_id(agent_id):
    c = agent_repo.get_connection()
    try:
        return c.execute("SELECT owner_id FROM agents WHERE agent_id=?",
                         (agent_id,)).fetchone()[0]
    finally:
        c.close()


def _human(wallet):
    c = agent_repo.get_connection()
    try:
        h = id_repo.resolve_wallet(c, wallet)
        return h.human_id if h else None
    finally:
        c.close()


@pytest.fixture()
def alice(client, wipe_agent_tables):
    a = AgentTestClient(client, eth_priv=ANVIL_KEY_1)
    a.register()
    return a


@pytest.fixture()
def bob(client, wipe_agent_tables):
    b = AgentTestClient(client, eth_priv=ANVIL_KEY_2)
    b.register()
    return b


def test_register_links_agent_to_wallet_human(alice):
    hid = _human(alice.owner)
    assert hid and hid.startswith("did:aera:human:")
    assert _owner_id(alice.agent_id) == hid


def test_second_agent_same_wallet_same_human(client, alice):
    first = alice.agent_id
    alice.register()
    assert _owner_id(first) == _owner_id(alice.agent_id) == _human(alice.owner)


def test_agents_of_different_wallets_have_different_humans(alice, bob):
    assert _owner_id(alice.agent_id) != _owner_id(bob.agent_id)


def test_existing_agent_still_authenticates(alice):
    alice.authenticate()


def test_public_agent_view_does_not_expose_owner_id(client, alice):
    body = client.get(f"/api/agents/{alice.agent_id}").json()
    assert "owner_id" not in body and "did:aera:human" not in str(body)


def test_dashboard_lists_only_own_agents(client, server_module, alice, bob):
    ids = [a["agent_id"] for a in client.get(
        "/api/dashboard/agents", headers=_hdr(server_module, alice.owner)).json()["agents"]]
    assert ids == [alice.agent_id]
    r = client.get(f"/api/dashboard/agents/{bob.agent_id}",
                   headers=_hdr(server_module, alice.owner))
    assert r.status_code == 404


def test_dashboard_hides_agent_whose_owner_id_points_to_other_human(
        client, server_module, alice, bob):
    # Tamper the DB: alice's agent still has alice's wallet but bob's human.
    c = agent_repo.get_connection()
    c.execute("UPDATE agents SET owner_id=? WHERE agent_id=?",
              (_human(bob.owner), alice.agent_id))
    c.commit(); c.close()
    h = _hdr(server_module, alice.owner)
    assert client.get("/api/dashboard/agents", headers=h).json()["agents"] == []
    assert client.get(f"/api/dashboard/agents/{alice.agent_id}",
                      headers=h).status_code == 404


def test_client_supplied_owner_id_is_ignored_on_register(client, wipe_agent_tables):
    a = AgentTestClient(client, eth_priv=ANVIL_KEY_1)
    b = AgentTestClient(client, eth_priv=ANVIL_KEY_2)
    b.register()
    bob_human = _human(b.owner)
    ch = a.owner_challenge("register")
    payload = {
        "owner_wallet": a.owner, "public_key": a.signer.public_key_encoded(),
        "owner_challenge_id": ch["challenge_id"],
        "owner_signature": a._owner_sign(ch), "owner_id": bob_human,
        "human_id": bob_human,
    }
    r = client.post("/api/agents/register", json=payload)
    if r.status_code == 200:
        assert _owner_id(r.json()["agent_id"]) == _human(a.owner) != bob_human
    else:  # strict models may reject unknown fields - also acceptable
        assert r.status_code in (400, 422)


def test_invalid_session_gets_nothing(client, alice):
    for h in ({}, {"Authorization": "Bearer x.y.z"}):
        assert client.get("/api/dashboard/agents", headers=h).status_code == 401
