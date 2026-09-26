"""AEra Multi-Model Agent Network -- live runner.

    Agent A (orchestrator) -> Agent B (analyst) -> Agent C (reviewer) -> Agent A

Each agent is an independent AEra identity. The LLM provider behind each agent
is injected and interchangeable -- proving that AEra identity belongs to the
Agent Runtime, not to the model provider.

Usage:
    cd aera-agent-security-lab
    ../venv/bin/python -m src.cli.network \
        --agent-a-provider grok \
        --agent-b-provider deepseek \
        --agent-c-provider claude \
        --question "Analyze the AEra Agent Identity architecture."
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
from src.agents.roles import (  # noqa: E402
    ANALYST,
    ANALYST_SYSTEM,
    ANALYST_TASK,
    ORCHESTRATOR,
    ORCHESTRATOR_SYSTEM,
    REVIEWER,
    REVIEWER_SYSTEM,
    REVIEWER_TASK,
    SYNTHESIS_TASK,
    HopResult,
    RoleAgent,
    hop,
)
from src.agents.reference import load_context  # noqa: E402
from src.config.settings import get_settings  # noqa: E402
from src.crypto.aera_crypto import AUD_AGENT_API, AUD_AGENT_RELAY  # noqa: E402
from src.providers.registry import (  # noqa: E402
    PROVIDER_NAMES,
    ProviderConfigError,
    available_providers,
    build_provider,
)

DEFAULT_QUESTION = (
    "Analyze the security architecture of AEraLogIn and identify the most "
    "important security properties, possible limitations and areas requiring "
    "further work."
)
RULE = "-" * 62
BAR = "=" * 62


def head(title: str) -> None:
    print(f"\n{BAR}\n{title}\n{BAR}")


def sub(title: str) -> None:
    print(f"\n{RULE}\n{title}\n{RULE}\n")


def ok(name: str, cond: bool, note: str = "") -> bool:
    print(f"  {name + ':':<26} {'PASS' if cond else 'FAIL'}"
          f"{('   (' + note + ')') if note else ''}")
    return cond


def show_hop(h: HopResult) -> list[bool]:
    """Print the per-hop security evidence."""
    return [
        ok("AEra relay", h.relay_ok,
           f"http={h.relay_status}" + (f" {h.relay_error}" if h.relay_error else "")),
        ok("Ed25519 signature", h.local_ok, h.local_error or ""),
        ok("content_hash", h.local_ok, h.local_error or ""),
        ok("receiver binding", h.local_ok, h.local_error or ""),
    ]


def excerpt(text: str, limit: int = 700) -> str:
    t = text.strip()
    return t if len(t) <= limit else t[:limit].rstrip() + " […]"


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description="AEra Multi-Model Agent Network")
    p.add_argument("--agent-a-provider", default="grok", choices=PROVIDER_NAMES)
    p.add_argument("--agent-b-provider", default="deepseek", choices=PROVIDER_NAMES)
    p.add_argument("--agent-c-provider", default="claude", choices=PROVIDER_NAMES)
    p.add_argument("--question", default=DEFAULT_QUESTION)
    p.add_argument("--base-url", default=None)
    p.add_argument("--json-out", default=None)
    p.add_argument("--context-file", default=None,
                   help="reference material for the agents (default: built-in "
                        "verified AEra facts)")
    p.add_argument("--full-output", action="store_true",
                   help="print complete model outputs instead of excerpts")
    args = p.parse_args(argv)

    settings = get_settings()
    base = args.base_url or settings.aera_base_url

    head("AEra MULTI-MODEL AGENT NETWORK")
    print("  AEra:      ", base)
    print("  providers: ", available_providers(settings))

    try:
        prov_a = build_provider(args.agent_a_provider, settings)
        prov_b = build_provider(args.agent_b_provider, settings)
        prov_c = build_provider(args.agent_c_provider, settings)
    except ProviderConfigError as e:
        print(f"\n  CONFIGURATION ERROR: {e}")
        return 2

    http = httpx.Client(base_url=base, timeout=settings.http_timeout)
    a = RoleAgent(http, prov_a, name="Agent A", role=ORCHESTRATOR)
    b = RoleAgent(http, prov_b, name="Agent B", role=ANALYST)
    c = RoleAgent(http, prov_c, name="Agent C", role=REVIEWER)
    transport = LocalTransport()

    checks: list[bool] = []
    summary: dict = {
        "aera_base_url": base,
        "providers": {"A": args.agent_a_provider, "B": args.agent_b_provider,
                      "C": args.agent_c_provider},
        "question": args.question,
    }

    try:
        # -- identities ---------------------------------------------------- #
        for agent, tag in ((a, "a"), (b, "b"), (c, "c")):
            agent.bootstrap(label=f"lab-agent-{tag}")
        print()
        for agent in (a, b, c):
            print(agent.describe())
            print()

        checks.append(ok("A/B/C distinct agent_ids",
                         len({a.agent_id, b.agent_id, c.agent_id}) == 3))
        checks.append(ok("A/B/C distinct key_ids",
                         len({a.identity.key_id, b.identity.key_id,
                              c.identity.key_id}) == 3))
        checks.append(ok("A/B/C distinct Ed25519 keys",
                         len({a.identity.public_key, b.identity.public_key,
                              c.identity.public_key}) == 3))
        checks.append(ok("A/B/C distinct owner EOAs",
                         len({a.identity.owner_wallet, b.identity.owner_wallet,
                              c.identity.owner_wallet}) == 3))

        # -- authentication ------------------------------------------------ #
        sub("AGENT AUTHENTICATION (real AEra JWTs)")
        for agent in (a, b, c):
            agent.identity.authenticate(aud=AUD_AGENT_API)
            agent.identity.authenticate(aud=AUD_AGENT_RELAY)
            v = agent.identity.verify_jwt()
            checks.append(ok(f"{agent.name} authentication",
                             v.status_code == 200 and v.json().get("agent_id") == agent.agent_id,
                             f"http={v.status_code}"))
        checks.append(ok("api != relay JWT",
                         len({a.identity.jti(aud=AUD_AGENT_API),
                              a.identity.jti(aud=AUD_AGENT_RELAY)}) == 2))
        summary["identities"] = {
            ag.name: {"agent_id": ag.agent_id, "key_id": ag.identity.key_id,
                      "provider": ag.provider_name, "model": ag.model,
                      "role": ag.role}
            for ag in (a, b, c)
        }

        hops: dict[str, HopResult] = {}
        calls: dict[str, dict] = {}

        # -- STEP 1/2: A -> B ---------------------------------------------- #
        sub("A -> B")
        context = load_context(args.context_file)
        summary["context_chars"] = len(context)
        task = ANALYST_TASK.format(question=args.question, context=context)
        analysis_task, h_ab = hop(a, b, transport, task)
        hops["A->B"] = h_ab
        checks.extend(show_hop(h_ab))

        # -- STEP 3: B -> DeepSeek ----------------------------------------- #
        sub(f"B -> {b.provider_name}")
        analysis, call_b = (None, None)
        if analysis_task is not None:
            analysis, call_b = b.think(analysis_task, system=ANALYST_SYSTEM)
            print(f"  Provider: {b.provider_name} ({b.model})")
            checks.append(ok("API call", call_b.ok, call_b.error or f"{call_b.chars} chars"))
            calls["B"] = call_b.__dict__
        else:
            checks.append(ok("API call", False, "no verified task received"))

        # -- STEP 4: B -> C ------------------------------------------------ #
        sub("B -> C")
        review_task = REVIEWER_TASK.format(question=args.question,
                                           context=context,
                                           analysis=analysis or "")
        if analysis:
            received_review_task, h_bc = hop(b, c, transport, review_task)
            hops["B->C"] = h_bc
            checks.extend(show_hop(h_bc))
        else:
            received_review_task = None
            print("  skipped: analyst produced no output")
            checks.append(ok("AEra relay", False, "upstream provider failure"))

        # -- STEP 5: C -> Claude ------------------------------------------- #
        sub(f"C -> {c.provider_name}")
        review, call_c = (None, None)
        if received_review_task is not None:
            review, call_c = c.think(received_review_task, system=REVIEWER_SYSTEM)
            print(f"  Provider: {c.provider_name} ({c.model})")
            checks.append(ok("API call", call_c.ok, call_c.error or f"{call_c.chars} chars"))
            calls["C"] = call_c.__dict__
        else:
            checks.append(ok("API call", False, "no verified task received"))

        # -- STEP 6: C -> A ------------------------------------------------ #
        sub("C -> A")
        if review:
            received_review, h_ca = hop(c, a, transport, review)
            hops["C->A"] = h_ca
            checks.extend(show_hop(h_ca))
        else:
            received_review = None
            print("  skipped: reviewer produced no output")
            checks.append(ok("AEra relay", False, "upstream provider failure"))

        # -- STEP 7: A -> Grok --------------------------------------------- #
        sub(f"A -> {a.provider_name}")
        final, call_a = (None, None)
        if received_review is not None and analysis is not None:
            final, call_a = a.think(
                SYNTHESIS_TASK.format(question=args.question, analysis=analysis,
                                      review=received_review),
                system=ORCHESTRATOR_SYSTEM)
            print(f"  Provider: {a.provider_name} ({a.model})")
            checks.append(ok("Final synthesis", call_a.ok,
                             call_a.error or f"{call_a.chars} chars"))
            calls["A"] = call_a.__dict__
        else:
            checks.append(ok("Final synthesis", False, "incomplete upstream chain"))

        summary["hops"] = {k: v.__dict__ for k, v in hops.items()}
        summary["provider_calls"] = calls
        summary["content_hash_verified_hops"] = sum(1 for h in hops.values() if h.local_ok)

        # -- STEP 8: transcript -------------------------------------------- #
        head("TRANSCRIPT")
        show = (lambda t: t.strip()) if args.full_output else excerpt
        print(f"\n### Original question\n{args.question}")
        if analysis:
            print(f"\n### {b.provider_name} analysis (Agent B, {b.model})\n{show(analysis)}")
        if review:
            print(f"\n### {c.provider_name} review (Agent C, {c.model})\n{show(review)}")
        if final:
            print(f"\n### {a.provider_name} final synthesis (Agent A, {a.model})\n{show(final)}")
        summary["outputs"] = {"analysis": analysis, "review": review, "final": final}

        head("FINAL RESULT")
        network_ok = all(checks)
        print(f"  Multi-model AEra network: {'PASS' if network_ok else 'FAIL'}")

    finally:
        # -- teardown ------------------------------------------------------ #
        sub("TEARDOWN")
        revoked = {}
        for agent in (a, b, c):
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

        for agent in (a, b, c):
            if not agent.agent_id:
                continue
            meta = agent.identity.get_public_metadata()
            body = meta.json() if meta.status_code == 200 else {}
            checks.append(ok(f"{agent.name} revoked", body.get("status") == "revoked"))
            checks.append(ok(f"{agent.name} keys inactive",
                             all(k["status"] != "active" for k in body.get("keys", []))))
            tok = agent.identity._tokens.get(AUD_AGENT_API, ("",))[0]
            v = http.post("/api/agents/verify-jwt",
                          headers={"Authorization": f"Bearer {tok}"})
            checks.append(ok(f"{agent.name} old JWT rejected", v.status_code != 200,
                             f"http={v.status_code}"))

        passed = sum(1 for c_ in checks if c_)
        print(f"\n  checks: {passed}/{len(checks)} passed")
        summary["checks"] = {"passed": passed, "total": len(checks)}
        if args.json_out:
            Path(args.json_out).write_text(json.dumps(summary, indent=2), encoding="utf-8")
            print(f"  wrote {args.json_out}")
        http.close()

    return 0 if passed == len(checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
