"""Negative proof for the gateway rate-limiting tests.

Same contract as negproof_a2a_gateway.py: each mutant removes exactly one
abuse-control property. A surviving mutant means the corresponding test proves
nothing. Every mutant here corresponds to a bypass that is realistic, not
theoretical -- each one is a mistake that has shipped in real rate limiters.
"""
from __future__ import annotations

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent
GW = ROOT / "a2a_gateway"
TESTS = ["tests/agent/test_a2a_gateway_ratelimit.py", "tests/agent/test_a2a_gateway.py"]

AGENT_CHECK = (
    "        agent_decision = get_limiter().check(SCOPE_AGENT, inbound.target_agent_id)\n"
    "        if not agent_decision.allowed:\n"
    "            raise GatewayError(ERR_RATE_LIMITED, RATE_LIMIT_MESSAGE,\n"
    "                               retry_after=agent_decision.retry_after)\n"
)

RESOLVE = (
    "            target = resolve_target_agent(conn, inbound.target_agent_id,\n"
    "                                          skill_id=inbound.skill_id)\n"
)

PEER_CHECK = (
    "    decision = limiter.check(SCOPE_PEER, source)\n"
    "    if not decision.allowed:\n"
    "        return _rate_limited(decision)\n"
)


def _move_agent_check_after_db(s: str) -> str:
    """Enforce the per-agent limit only after the database has been queried."""
    s = s.replace(AGENT_CHECK, "", 1)
    return s.replace(
        RESOLVE,
        RESOLVE
        + "            agent_decision = get_limiter().check(SCOPE_AGENT,\n"
          "                                                 inbound.target_agent_id)\n"
          "            if not agent_decision.allowed:\n"
          "                raise GatewayError(ERR_RATE_LIMITED, RATE_LIMIT_MESSAGE,\n"
          "                                   retry_after=agent_decision.retry_after)\n",
        1)


MUTANTS = [
    ("ratelimit.py: the limiter allows everything (rate limiting disabled)",
     "ratelimit.py",
     lambda s: s.replace(
         '        """Consume one token from (scope, key). O(1), no I/O."""\n',
         '        """Consume one token from (scope, key). O(1), no I/O."""\n'
         "        return ALLOWED\n", 1)),

    ("routes.py: the per-peer limit is not enforced (only the global one)",
     "routes.py",
     lambda s: s.replace(PEER_CHECK, "", 1)),

    ("handler.py: the per-agent limit is not enforced",
     "handler.py",
     lambda s: s.replace(AGENT_CHECK, "", 1)),

    ("routes.py: the 429 no longer carries Retry-After",
     "routes.py",
     lambda s: s.replace(
         '            "Retry-After": str(decision.retry_after),\n', "", 1)),

    ("ratelimit.py: X-Forwarded-For is trusted from any caller",
     "ratelimit.py",
     lambda s: s.replace(
         "    if direct not in proxies:\n        return direct\n",
         "    if False:\n        return direct\n", 1)),

    ("handler.py: the per-agent limit runs only after the database lookup",
     "handler.py",
     _move_agent_check_after_db),

    ("routes.py: the limit is keyed per request instead of per caller",
     "routes.py",
     lambda s: s.replace("    source = client_source(request)",
                         "    source = client_source(request) + str(id(request))", 1)),
]


def run() -> tuple[int, int, str]:
    p = subprocess.run(
        [sys.executable, "-m", "pytest", *TESTS, "-q", "-p", "no:cacheprovider"],
        cwd=ROOT, capture_output=True, text=True)
    lines = [l for l in p.stdout.strip().splitlines() if l.strip()]
    tail = lines[-1] if lines else ""
    failed = int(m.group(1)) if (m := re.search(r"(\d+) failed", tail)) else 0
    passed = int(m.group(1)) if (m := re.search(r"(\d+) passed", tail)) else 0
    if failed == 0 and passed == 0 and "error" in p.stdout.lower():
        failed = -1
    return passed, failed, tail


def main() -> int:
    passed, failed, tail = run()
    print(f"BASELINE: {tail}")
    if failed:
        print("baseline not green; aborting")
        return 1
    baseline = passed

    caught = 0
    for label, filename, mutate in MUTANTS:
        path = GW / filename
        original = path.read_text()
        mutated = mutate(original)
        if mutated == original:
            print(f"SKIPPED (no textual change): {label}")
            continue
        path.write_text(mutated)
        try:
            _, mfailed, _ = run()
        finally:
            path.write_text(original)
        print(f"{'CAUGHT' if mfailed else 'MISSED':7} {mfailed:>3} failures | {label}")
        caught += bool(mfailed)

    passed, failed, tail = run()
    print(f"RESTORED: {tail}")
    ok = passed == baseline and failed == 0 and caught == len(MUTANTS)
    print(f"RESULT: {caught}/{len(MUTANTS)} caught; restored: "
          f"{passed == baseline and failed == 0}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
