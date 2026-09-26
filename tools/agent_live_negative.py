"""LIVE negative security tests against the running production instance.

Simulates an attacker in possession of AGENT_JWT_SECRET and proves that the
JTI binding (sub / key_id / aud / owner_wallet) blocks every forgery.

No production data is corrupted: only freshly created throwaway agents are
used, and only read/verify endpoints are exercised with forged tokens.

Run:  ./venv/bin/python tools/agent_live_negative.py
"""
from __future__ import annotations

import secrets
import sys
import uuid

import httpx
import jwt as pyjwt
from dotenv import dotenv_values

sys.path.insert(0, ".")

from agent.constants import AUD_AGENT_API, AUD_AGENT_RELAY, JWT_ALG
from agent.crypto import Ed25519Signer
from tests.agent.testclient import AgentTestClient

BASE = "http://127.0.0.1:8840"
SECRET = dotenv_values(".env")["AGENT_JWT_SECRET"]  # never printed

ok: list[str] = []
fail: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
          f"{('  <- ' + detail) if detail and not cond else ''}")


def claims_of(tok: str) -> dict:
    return pyjwt.decode(tok, options={"verify_signature": False,
                                      "verify_aud": False,
                                      "verify_exp": False},
                        algorithms=[JWT_ALG])


def remint(base: dict, **over) -> str:
    p = dict(base)
    p.update(over)
    return pyjwt.encode(p, SECRET, algorithm=JWT_ALG)


def main() -> int:
    http = httpx.Client(base_url=BASE, timeout=30.0)

    def verify(tok: str) -> int:
        return http.post("/api/agents/verify-jwt",
                         headers={"Authorization": f"Bearer {tok}"}).status_code

    a = AgentTestClient(http, eth_priv="0x" + secrets.token_hex(32))
    a.register(capabilities=["agent.authenticate", "agent.read.profile",
                             "agent.communicate", "agent.interaction.record"])
    b = AgentTestClient(http, eth_priv="0x" + secrets.token_hex(32))
    b.register(capabilities=["agent.authenticate", "agent.communicate"])

    assert a.authenticate(aud=AUD_AGENT_API).status_code == 200
    token = a.token
    c = claims_of(token)

    other_key = a.add_key(Ed25519Signer.generate())

    print("\n=== LIVE negative authentication tests ===")
    check("baseline: correctly bound token accepted", verify(token) == 200)

    check("invalid JWT (garbage) -> 401",
          verify("aaa.bbb.ccc") == 401)
    check("token signed with wrong secret -> 401",
          verify(pyjwt.encode(c, "wrong-secret-" + secrets.token_hex(8),
                              algorithm=JWT_ALG)) == 401)
    check("wrong audience (relay token on api endpoint) -> 401",
          verify(remint(c, aud=AUD_AGENT_RELAY)) == 401)
    check("wrong issuer -> 401",
          verify(remint(c, iss="evil.example")) == 401)
    check("altered sub with valid active JTI -> 401",
          verify(remint(c, sub=b.agent_id)) == 401)
    check("altered key_id with valid active JTI -> 401",
          verify(remint(c, key_id=other_key)) == 401)
    check("altered owner_wallet with valid active JTI -> 401",
          verify(remint(c, owner_wallet="0x" + "de" * 20)) == 401)
    check("unknown JTI -> 401",
          verify(remint(c, jti=uuid.uuid4().hex)) == 401)
    check("escalated capabilities -> 401/403",
          verify(remint(c, capabilities=["agent.admin"])) in (401, 403))
    check("wrong typ -> 401",
          verify(remint(c, typ="access")) == 401)

    print("\n=== revoked JTI ===")
    rv = http.post("/api/agents/tokens/revoke",
                   headers={"Authorization": f"Bearer {token}"},
                   json={"jti": c["jti"]})
    check("token revoke accepted", rv.status_code == 200, rv.text)
    check("revoked JTI -> 401", verify(token) == 401)

    print("\n=== A2A replay ===")
    assert a.authenticate(aud=AUD_AGENT_RELAY).status_code == 200
    relay = a.token
    payload, sig = a.build_message(receiver=b.agent_id, content=b"neg-test")
    first = http.post("/api/agents/messages",
                      json={"payload": payload, "signature": sig},
                      headers={"Authorization": f"Bearer {relay}"})
    check("first A2A message accepted", first.status_code == 200, first.text)
    again = http.post("/api/agents/messages",
                      json={"payload": payload, "signature": sig},
                      headers={"Authorization": f"Bearer {relay}"})
    check("replayed A2A message rejected",
          again.status_code in (401, 409), f"got {again.status_code}")

    tampered = dict(payload)
    tampered["content_hash"] = "sha256:" + "A" * 43
    bad = http.post("/api/agents/messages",
                    json={"payload": tampered, "signature": sig},
                    headers={"Authorization": f"Bearer {relay}"})
    check("tampered payload (invalid Ed25519 sig) rejected",
          bad.status_code in (401, 409), f"got {bad.status_code}")

    print("\n" + "=" * 62)
    print(f"LIVE NEGATIVE TESTS: {len(ok)} passed, {len(fail)} failed")
    if fail:
        print("FAILED:", fail)
    return 1 if fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
