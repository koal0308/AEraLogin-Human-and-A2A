"""AEra Agent Security Lab -- live runner (phases 5-9).

Usage:
    ./venv/bin/python -m aera-agent-security-lab.src.cli.lab      # not importable (dash)
Prefer:
    cd aera-agent-security-lab && ../venv/bin/python -m src.cli.lab --provider deepseek

Safety:
  * disposable owner EOAs, generated locally
  * every agent is revoked in a `finally:` block
  * no secret is ever printed
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.a2a.protocol import LocalTransport  # noqa: E402
from src.agents.legit import AgentA, AgentB  # noqa: E402
from src.attacker.attacks import ATTACKS, AgentX, LabContext  # noqa: E402
from src.config.settings import get_settings  # noqa: E402
from src.crypto.aera_crypto import AUD_AGENT_API, AUD_AGENT_RELAY  # noqa: E402
from src.providers.base import LLMProvider  # noqa: E402
from src.providers.deepseek import DeepSeekProvider  # noqa: E402
from src.providers.mock import MockProvider  # noqa: E402

DEFAULT_QUESTION = ("Explain the difference between proof-of-human and "
                    "proof-of-agent in two sentences.")


def hr(title: str) -> None:
    print(f"\n{'=' * 70}\n{title}\n{'=' * 70}")


def ok(name: str, cond: bool, note: str = "") -> bool:
    print(f"  [{'PASS' if cond else 'FAIL':4}] {name}{('  <- ' + note) if note else ''}")
    return cond


def build_provider(settings, kind: str) -> LLMProvider:
    if kind == "deepseek":
        return DeepSeekProvider(settings.deepseek_api_key,
                                base_url=settings.deepseek_base_url,
                                model=settings.deepseek_model,
                                timeout=settings.http_timeout)
    return MockProvider(reply="MOCK")


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description="AEra Agent Security Lab")
    p.add_argument("--provider", default=None, choices=["mock", "deepseek"])
    p.add_argument("--question", default=DEFAULT_QUESTION)
    p.add_argument("--base-url", default=None)
    p.add_argument("--json-out", default=None)
    p.add_argument("--skip-attacks", action="store_true")
    args = p.parse_args(argv)

    settings = get_settings()
    base = args.base_url or settings.aera_base_url
    kind = args.provider or settings.provider

    hr("AEra Agent Security Lab")
    print("  config:", json.dumps(settings.redacted() | {"aera_base_url": base,
                                                         "provider": kind}))

    http = httpx.Client(base_url=base, timeout=settings.http_timeout)
    provider = build_provider(settings, kind)
    print("  provider:", repr(provider))

    a = AgentA(http)
    b = AgentB(http, provider)
    x = AgentX(http)  # ATTACKER (not the Claude reviewer)
    transport = LocalTransport()
    checks: list[bool] = []
    summary: dict = {"base_url": base, "provider": kind}

    try:
        # ---- PHASE 5: live registration ---------------------------------- #
        hr("PHASE 5 - live disposable agent registration")
        for agent, label in ((a, "lab-agent-a"), (b, "lab-agent-b"), (x, "lab-agent-x")):
            agent.bootstrap(label=label)
            print(f"  {agent.name}: {agent.agent_id}")
        checks.append(ok("A registered", bool(a.agent_id)))
        checks.append(ok("B registered", bool(b.agent_id)))
        checks.append(ok("X (attacker) registered", bool(x.agent_id)))
        checks.append(ok("all agent_ids distinct",
                         len({a.agent_id, b.agent_id, x.agent_id}) == 3))
        checks.append(ok("all owner wallets distinct",
                         len({a.identity.owner_wallet, b.identity.owner_wallet,
                              x.identity.owner_wallet}) == 3))
        checks.append(ok("all Ed25519 public keys distinct",
                         len({a.identity.public_key, b.identity.public_key,
                              x.identity.public_key}) == 3))
        a.bind_peer(b.agent_id or "")

        # ---- PHASE 6: live authentication -------------------------------- #
        hr("PHASE 6 - live agent authentication (real JWTs)")
        for agent in (a, b, x):
            agent.identity.authenticate(aud=AUD_AGENT_API)
            agent.identity.authenticate(aud=AUD_AGENT_RELAY)
            print(f"  {agent.name}: api jti={agent.identity.jti(aud=AUD_AGENT_API)} "
                  f"relay jti={agent.identity.jti(aud=AUD_AGENT_RELAY)}")
        va = a.identity.verify_jwt()
        checks.append(ok("A authentication (api)", va.status_code == 200))
        checks.append(ok("A verify-jwt returns A's agent_id",
                         va.status_code == 200 and va.json().get("agent_id") == a.agent_id))
        vb = b.identity.verify_jwt()
        checks.append(ok("B authentication (api)", vb.status_code == 200))
        checks.append(ok("api and relay tokens differ",
                         a.identity.token(aud=AUD_AGENT_API)
                         != a.identity.token(aud=AUD_AGENT_RELAY)))
        summary["auth"] = {"A": va.status_code == 200, "B": vb.status_code == 200}

        # ---- PHASE 7: legitimate round trip ------------------------------ #
        hr("PHASE 7 - legitimate A -> B -> LLM -> B -> A")
        req_env, req_outcome = a.send_request(transport, question=args.question)
        checks.append(ok("A -> B notarised by AEra", req_outcome.accepted,
                         f"http={req_outcome.status} err={req_outcome.agent_error}"))
        print(f"    message_id: {req_env.message_id}")

        resp_env, resp_outcome, reject = b.handle(transport)
        provider_down = reject == "provider_error"
        if provider_down:
            print(f"  [WARN] provider unavailable: {b.last_provider_error}")
            summary["provider_error"] = b.last_provider_error
        checks.append(ok("B verified A's message locally",
                         reject is None or provider_down, str(reject)))
        llm_ok = resp_env is not None
        checks.append(ok(f"B -> {kind} -> B", llm_ok,
                         "provider unavailable" if provider_down else ""))
        checks.append(ok("B -> A notarised by AEra",
                         bool(resp_outcome and resp_outcome.accepted),
                         f"http={resp_outcome.status if resp_outcome else '-'}"))
        answer, a_reject = a.receive_response(transport)
        checks.append(ok("A verified B's response locally", a_reject is None, str(a_reject)))
        round_trip = bool(answer)
        checks.append(ok("full round trip", round_trip))
        if answer:
            print("\n  --- answer ---")
            for line in answer.strip().splitlines()[:12]:
                print("   ", line)
            print("  --------------")

        if resp_env is None:
            # The attack phase needs a genuine, notarised B -> A envelope for
            # SEC-13. Produce one WITHOUT the provider so that an LLM outage
            # cannot silently skip a security test.
            from src.a2a.protocol import build_envelope
            resp_env = build_envelope(b.identity, receiver_agent_id=a.agent_id or "",
                                      content=b"security-probe-response")
            probe = b.notarise(resp_env)
            print(f"  [INFO] synthetic B->A envelope for SEC-13: http={probe.status}")
            summary["synthetic_response_used"] = True

        summary["round_trip"] = {
            "a_to_b": req_outcome.accepted,
            "b_local_verify": reject is None,
            "llm": llm_ok,
            "b_to_a": bool(resp_outcome and resp_outcome.accepted),
            "a_local_verify": a_reject is None,
            "full": round_trip,
            "request_message_id": req_env.message_id,
            "response_message_id": resp_env.message_id if resp_env else None,
        }

        # ---- PHASE 8: attacks -------------------------------------------- #
        attack_results = []
        if not args.skip_attacks:
            hr("PHASE 8 - attacker Agent C: SEC-01 .. SEC-14")
            ctx = LabContext(http=http, a=a, b=b, x=x,
                             captured_request=req_env,
                             captured_response=resp_env)
            for fn in ATTACKS:
                try:
                    fn(ctx)
                except Exception as e:  # an attack harness bug must not be silent
                    from src.attacker.attacks import AttackResult
                    ctx.add(AttackResult(fn.__name__, "HARNESS ERROR", "LAB", False,
                                         note=f"{type(e).__name__}: {e}"))
            attack_results = [r.as_dict() for r in ctx.results]
            checks.append(ok("all 14 attacks blocked",
                             len(ctx.results) == 14 and all(r.blocked for r in ctx.results)))
        summary["attacks"] = attack_results

    finally:
        # ---- PHASE 9: teardown ------------------------------------------- #
        hr("PHASE 9 - teardown & revocation verification")
        revoked = {}
        for agent in (a, b, x):
            if not agent.agent_id:
                continue
            try:
                r = agent.identity.revoke()
                revoked[agent.name] = r.status_code
                print(f"  revoke {agent.name}: HTTP {r.status_code}")
            except Exception as e:
                revoked[agent.name] = f"ERROR {type(e).__name__}"
                print(f"  revoke {agent.name}: ERROR {e}")
        summary["teardown"] = revoked

        for agent in (a, b, x):
            if not agent.agent_id:
                continue
            meta = agent.identity.get_public_metadata()
            st = meta.json().get("status") if meta.status_code == 200 else None
            checks.append(ok(f"{agent.name} status == revoked", st == "revoked", str(st)))
            keys_dead = (meta.status_code == 200
                         and all(k["status"] != "active" for k in meta.json().get("keys", [])))
            checks.append(ok(f"{agent.name} keys no longer active", keys_dead))
            v = http.post("/api/agents/verify-jwt",
                          headers={"Authorization":
                                   f"Bearer {agent.identity._tokens.get(AUD_AGENT_API, ('',))[0]}"})
            checks.append(ok(f"{agent.name} old JWT rejected", v.status_code != 200,
                             f"http={v.status_code}"))

        hr("SUMMARY")
        passed = sum(1 for c_ in checks if c_)
        print(f"  checks: {passed}/{len(checks)} passed")
        summary["checks"] = {"passed": passed, "total": len(checks)}
        if args.json_out:
            Path(args.json_out).write_text(json.dumps(summary, indent=2), encoding="utf-8")
            print(f"  wrote {args.json_out}")
        http.close()

    return 0 if passed == len(checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
