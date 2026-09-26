"""Controlled LIVE production smoke test for the Agent Identity Layer.

Touches ONLY agent_* tables. Uses freshly generated throwaway keys.
Performs NO blockchain transaction: verified that
`web3_service.record_interaction` is not a module-level callable, so the
optional on-chain branch in agent/interactions.py is a no-op.

Run:  ./venv/bin/python tools/agent_live_smoke.py
"""
from __future__ import annotations

import secrets
import sqlite3
import sys

import httpx

sys.path.insert(0, ".")

from agent.constants import AUD_AGENT_API, AUD_AGENT_RELAY
from tests.agent.testclient import AgentTestClient

BASE = "http://127.0.0.1:8840"

ok: list[str] = []
fail: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    (ok if cond else fail).append(name)
    tag = "PASS" if cond else "FAIL"
    extra = f"  <- {detail[:200]}" if detail and not cond else ""
    print(f"  [{tag}] {name}{extra}")


def main() -> int:
    http = httpx.Client(base_url=BASE, timeout=30.0)

    # fresh throwaway owner EOAs - never reuse an existing production key
    a = AgentTestClient(http, eth_priv="0x" + secrets.token_hex(32))
    b = AgentTestClient(http, eth_priv="0x" + secrets.token_hex(32))

    print("\n=== A + B: owner challenge & agent registration ===")
    a.register(capabilities=["agent.authenticate", "agent.read.profile",
                             "agent.communicate", "agent.interaction.record"])
    check("A owner challenge signed & accepted (agent A)", bool(a.agent_id))
    check("B agent A registered", bool(a.key_id))

    print("\n=== H: second agent ===")
    b.register(capabilities=["agent.authenticate", "agent.communicate"])
    check("H agent B registered & distinct",
          bool(b.agent_id) and a.agent_id != b.agent_id)

    print("\n=== C + D + E + I: challenge -> authenticate -> JWT ===")
    r = a.authenticate(aud=AUD_AGENT_RELAY)
    check("C+D agent A challenge+auth (relay)", r.status_code == 200, r.text)
    check("E agent A received JWT", bool(a.token))
    relay_token_a = a.token
    r = b.authenticate(aud=AUD_AGENT_RELAY)
    check("I agent B authenticated (relay)", r.status_code == 200, r.text)
    relay_token_b = b.token

    print("\n=== G: second token, different audience ===")
    r = a.authenticate(aud=AUD_AGENT_API)
    check("G agent A got api-audience token", r.status_code == 200, r.text)
    api_token_a = a.token
    check("G tokens are distinct", relay_token_a != api_token_a)

    print("\n=== F: live JWT verification endpoint ===")
    v = http.post("/api/agents/verify-jwt",
                  headers={"Authorization": f"Bearer {api_token_a}"})
    check("F valid api JWT accepted", v.status_code == 200, v.text)
    if v.status_code == 200:
        body = v.json()
        check("F verify returns correct agent_id", body.get("agent_id") == a.agent_id)
        check("F verify returns typ=agent", body.get("typ") == "agent")
        check("F verify returns correct aud", body.get("aud") == AUD_AGENT_API)

    v_bad = http.post("/api/agents/verify-jwt",
                      headers={"Authorization": f"Bearer {relay_token_a}"})
    check("F audience separation enforced (relay token rejected on api)",
          v_bad.status_code == 401, f"got {v_bad.status_code}")

    v_again = http.post("/api/agents/verify-jwt",
                        headers={"Authorization": f"Bearer {api_token_a}"})
    check("G JWT reusable before exp (not one-time-use)", v_again.status_code == 200)

    print("\n=== J + K + L + M: A2A message A -> B ===")
    payload, sig = a.build_message(receiver=b.agent_id,
                                   content=b"release-smoke-test")
    m = http.post("/api/agents/messages",
                  json={"payload": payload, "signature": sig},
                  headers={"Authorization": f"Bearer {relay_token_a}"})
    check("J+K+L A2A message accepted (Ed25519 + JWT verified)",
          m.status_code == 200, m.text)

    m_wrong = http.post("/api/agents/messages",
                        json={"payload": payload, "signature": sig},
                        headers={"Authorization": f"Bearer {relay_token_b}"})
    check("M sender/JWT binding enforced (foreign token rejected)",
          m_wrong.status_code in (401, 403, 409), f"got {m_wrong.status_code}")

    print("\n=== N + O: replay rejection ===")
    m_replay = http.post("/api/agents/messages",
                         json={"payload": payload, "signature": sig},
                         headers={"Authorization": f"Bearer {relay_token_a}"})
    check("N+O identical message replay rejected",
          m_replay.status_code in (401, 409), f"got {m_replay.status_code}")

    print("\n=== P: interaction proof (off-chain only) ===")
    ip, isig = a.build_message(receiver=b.agent_id, content=b"interaction-proof")
    inter = http.post("/api/agents/interactions",
                      json={"payload": ip, "signature": isig,
                            "interaction_type": 1,
                            "responder_agent_id": b.agent_id},
                      headers={"Authorization": f"Bearer {api_token_a}"})
    check("P interaction recorded", inter.status_code == 200, inter.text)
    if inter.status_code == 200:
        check("P NO on-chain transaction performed",
              not inter.json().get("onchain_tx_hash"),
              str(inter.json().get("onchain_tx_hash")))

    print("\n=== Q: audit trail ===")
    c = sqlite3.connect("file:./aera.db?mode=ro", uri=True)
    events = [row[0] for row in c.execute(
        "SELECT event FROM agent_audit_log WHERE agent_id IN (?,?)",
        (a.agent_id, b.agent_id))]
    c.close()
    uniq = sorted(set(events))
    for want in ("agent.created", "agent.token_issued"):
        check(f"Q audit event '{want}' written", want in events, str(uniq))
    check("Q audit trail non-empty", len(events) > 0)
    print("     audit events observed:", uniq)

    print("\n" + "=" * 62)
    print(f"LIVE SMOKE TEST: {len(ok)} passed, {len(fail)} failed")
    if fail:
        print("FAILED CHECKS:", fail)
    print("test agent A:", a.agent_id)
    print("test agent B:", b.agent_id)
    return 1 if fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
