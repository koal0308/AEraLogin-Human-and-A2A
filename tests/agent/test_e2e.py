"""End-to-End demo: Owner → Registration → Agent A ↔ Agent B → Interaction.

Everything in-process, no mainnet. web3_service is stubbed by root conftest.
"""
from __future__ import annotations

from agent.constants import AUD_AGENT_API, AUD_AGENT_RELAY
from tests.agent.testclient import ANVIL_KEY_2, AgentTestClient


def test_e2e_full_flow(client, wipe_agent_tables):
    # 1) Owner registers Agent A + Agent B
    a = AgentTestClient(client)
    b = AgentTestClient(client, eth_priv=ANVIL_KEY_2)
    a.register(capabilities=["agent.authenticate", "agent.read.profile",
                             "agent.communicate", "agent.interaction.record"])
    b.register(capabilities=["agent.authenticate", "agent.communicate"])

    # 2) Both authenticate for the relay
    assert a.authenticate(aud=AUD_AGENT_RELAY).status_code == 200
    assert b.authenticate(aud=AUD_AGENT_RELAY).status_code == 200

    # 3) A sends signed message to B via relay
    r = a.send_message(receiver=b.agent_id, content=b"hello B")
    assert r.status_code == 200, r.text

    # 4) A separately authenticates for API + records interaction
    assert a.authenticate(aud=AUD_AGENT_API).status_code == 200
    payload, sig = a.build_message(receiver=b.agent_id, content=b"ping")
    r2 = client.post("/api/agents/interactions", json={
        "payload": payload, "signature": sig,
        "interaction_type": 1, "metadata": {"kind": "greet"},
    }, headers=a.auth_headers())
    assert r2.status_code == 200, r2.text

    # 5) Audit log has expected events
    from agent import repository as _repo
    conn = _repo.get_connection()
    events = [row["event"] for row in conn.execute(
        "SELECT event FROM agent_audit_log ORDER BY id"
    ).fetchall()]
    conn.close()
    assert "agent.created" in events
    assert "agent.token_issued" in events
    assert "agent.message_received" in events
    assert "agent.interaction_recorded" in events

    # 6) Pure /messages replay attempt rejected
    assert a.authenticate(aud=AUD_AGENT_RELAY).status_code == 200
    payload2, sig2 = a.build_message(receiver=b.agent_id, content=b"twice")
    r_ok = client.post("/api/agents/messages",
                       json={"payload": payload2, "signature": sig2},
                       headers=a.auth_headers())
    assert r_ok.status_code == 200
    r_replay2 = client.post("/api/agents/messages",
                            json={"payload": payload2, "signature": sig2},
                            headers=a.auth_headers())
    assert r_replay2.status_code == 401
