"""Live interoperability check for the INBOUND A2A gateway.

Direction under test (the opposite of Phase 1):

    standard A2A client  ->  public Agent Card  ->  AEra inbound gateway
                         ->  target AEra agent  ->  standard A2A response

The client used is `src/external_a2a` -- the same standards-compatible client
that was interoperability-tested against a real third-party agent in Phase 1.
It is driven with the STRICT default network policy (https only, public
addresses only, DNS pinning), so the gateway is exercised exactly as an outside
caller would reach it.

Honest scope note: this proves the gateway is reachable and correct over the
public internet using a standard A2A client. It does NOT prove that a
third-party-operated agent has called in -- see docs/a2a-gateway.md.

    ./venv/bin/python tools/a2a_gateway_livecheck.py
"""
from __future__ import annotations

import argparse
import pathlib
import sys
import uuid

import httpx

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "aera-agent-security-lab"))

from a2a_gateway.constants import SKILL_READ_PROFILE, TARGET_AGENT_FIELD  # noqa: E402
from src.external_a2a import A2AClient, NetPolicy, select_adapter  # noqa: E402
from src.identity.aera_client import AeraIdentityClient  # noqa: E402

CAP_PROFILE = "agent.read.profile"
RULE = "-" * 62
BAR = "=" * 62


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--public", default="https://aeralogin.com",
                    help="public origin the external caller uses")
    ap.add_argument("--admin", default="http://127.0.0.1:8840",
                    help="local origin used only to create/revoke the test agent")
    args = ap.parse_args()

    stages: dict[str, str] = {}
    agent = None
    admin = httpx.Client(base_url=args.admin, timeout=30.0)

    print(BAR)
    print("Inbound A2A gateway — live interoperability check")
    print(BAR)

    try:
        # 1) an ordinary AEra agent, created through the unchanged public API
        agent = AeraIdentityClient(admin, name="inbound-gateway-target")
        agent.register(capabilities=[CAP_PROFILE, "agent.authenticate"],
                       label="inbound-gateway-target")
        stages["AEra target agent"] = f"PASS ({agent.agent_id})"
        print(f"{RULE}\nTarget AEra agent: {agent.agent_id}")

        # 2) discovery over the public internet, strict policy + DNS pinning
        client = A2AClient(policy=NetPolicy())
        card, iface = client.discover_agent(args.public)
        stages["Agent Card discovery"] = f"PASS ({card.name})"
        print(f"Agent Card       : {card.card_url}")
        print(f"Protocol         : {iface.protocol_binding} {iface.protocol_version}")
        print(f"Endpoint         : {iface.url}")
        print(f"Skills           : {', '.join(card.skill_ids())}")

        # 3) auth mode declared by the card
        adapter = select_adapter(card)
        stages["Authentication"] = f"PASS (scheme={adapter.describe()})"
        print(f"Auth             : {adapter.describe()}")

        # 4) a real A2A request naming the target agent
        message_id = uuid.uuid4().hex
        body = {
            "jsonrpc": "2.0",
            "id": f"live-{uuid.uuid4()}",
            "method": "message/send",
            "params": {"message": {
                "messageId": message_id,
                "role": "user",
                "parts": [{"kind": "text", "text": f"{SKILL_READ_PROFILE}: who is this agent?"}],
                "metadata": {TARGET_AGENT_FIELD: agent.agent_id,
                             "skillId": SKILL_READ_PROFILE},
            }},
        }
        status, _, raw = _post(client, iface.url, body)
        stages["A2A request"] = f"PASS (HTTP {status}, id={body['id']})"
        print(f"{RULE}\n-> {SKILL_READ_PROFILE} for {agent.agent_id}")

        payload = raw
        if "error" in payload:
            stages["A2A response"] = f"FAIL ({payload['error']})"
            raise SystemExit(_finish(stages, 1))

        result = payload["result"]
        text = next(p["text"] for p in result["parts"] if p.get("kind") == "text")
        data = next((p["data"] for p in result["parts"] if p.get("kind") == "data"), {})
        print(f"<- [{result['kind']}] {text}")
        print(f"   profile: {data.get('agent')}")

        ok = (result["kind"] == "message"
              and data.get("agent", {}).get("agent_id") == agent.agent_id)
        stages["A2A response"] = "PASS (message, correct target)" if ok else "FAIL"

        # 5) replay of the same messageId must be refused
        status2, _, replayed = _post(client, iface.url, body)
        refused = "error" in replayed and "duplicate" in replayed["error"]["message"]
        stages["Replay protection"] = "PASS (duplicate refused)" if refused else "FAIL"
        print(f"{RULE}\nreplay -> {replayed.get('error', {}).get('message', replayed)}")

        # 6) nothing sensitive came back
        blob = str(payload)
        leaks = [s for s in ("owner_wallet", "eyJ", "ed25519:", "public_key", "0x")
                 if s in blob]
        stages["No leakage"] = "PASS" if not leaks else f"FAIL ({leaks})"

    except Exception as exc:  # noqa: BLE001
        stages.setdefault("ERROR", f"{type(exc).__name__}: {exc}")
    finally:
        if agent is not None and agent.agent_id:
            try:
                r = agent.revoke()
                print(f"{RULE}\nTarget agent revoked: HTTP {r.status_code}")
            except Exception as exc:  # noqa: BLE001
                print(f"{RULE}\nrevoke failed: {type(exc).__name__}")
        admin.close()

    return _finish(stages, 0)


def _post(client: A2AClient, url: str, body: dict) -> tuple[int, dict, dict]:
    from src.external_a2a.net import decode_json, request

    status, headers, raw = request(
        "POST", url, policy=client.policy,
        headers={"Content-Type": "application/json", "Accept": "application/json",
                 "A2A-Version": "0.3"},
        json_body=body)
    return status, headers, decode_json(raw, what="gateway response")


def _finish(stages: dict[str, str], _unused: int) -> int:
    print(BAR)
    for name, value in stages.items():
        print(f"{name}: {value}")
    print(BAR)
    failed = [k for k, v in stages.items() if not v.startswith("PASS")]
    if failed:
        print(f"RESULT: FAIL ({', '.join(failed)})")
        return 1
    print("RESULT: an external standard A2A client reached an AEra agent "
          "through the public AEra gateway.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
