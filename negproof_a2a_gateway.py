"""Negative proof for the inbound A2A gateway tests.

Each mutant disables exactly one security property. A mutant that survives means
the corresponding test is decorative.
"""
from __future__ import annotations

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent
GW = ROOT / "a2a_gateway"
TEST = "tests/agent/test_a2a_gateway.py"

MUTANTS = [
    ("routing.py: revoked/inactive agents become routable",
     "routing.py",
     lambda s: s.replace('    if status != "active":', "    if False:", 1)),

    ("routing.py: capability check removed",
     "routing.py",
     lambda s: s.replace("        if required not in capabilities:",
                         "        if False:", 1)),

    ("routing.py: unknown and revoked agents get distinguishable errors",
     "routing.py",
     lambda s: s.replace(
         'raise GatewayError(ERR_INVALID_PARAMS, _OPAQUE_UNKNOWN,\n'
         '                           internal=f"agent {agent_id} has status {status!r}")',
         'raise GatewayError(ERR_INVALID_PARAMS, f"agent is {status}")', 1)),

    ("handler.py: replay/duplicate protection disabled",
     "handler.py",
     lambda s: s.replace("            if not remember(conn, message_id=inbound.message_id,",
                         "            if False and remember(conn, message_id=inbound.message_id,", 1)),

    ("handler.py: internal exception text leaks to the caller",
     "handler.py",
     lambda s: s.replace(
         'return _error_response(rpc_id, ERR_INTERNAL, "internal error"), 500',
         'return _error_response(rpc_id, ERR_INTERNAL, internal_note), 500', 1)),

    ("auth.py: an AEra JWT is accepted as an external credential",
     "auth.py",
     lambda s: s.replace("    if _looks_like_a_jwt(credential):", "    if False:", 1)),

    ("card.py: the card publishes the owner wallet",
     "card.py",
     lambda s: s.replace('            "url": base,',
                         '            "url": base, "owner_wallet": "0xdeadbeef",', 1)),

    ("validation.py: expiry is ignored",
     "validation.py",
     lambda s: s.replace(
         '        if _parse_timestamp(raw_expiry, "expiresAt") <= current:',
         "        if False:", 1)),

    ("validation.py: the target agent guard is removed entirely",
     "validation.py",
     lambda s: s.replace(
         '    if target is None:\n'
         '        raise GatewayError(\n'
         '            ERR_INVALID_PARAMS,\n'
         '            f"no target AEra agent specified; set metadata.{TARGET_AGENT_FIELD}")\n'
         '    if not isinstance(target, str) or not ID_PATTERN.match(target):\n'
         '        raise GatewayError(ERR_INVALID_PARAMS,\n'
         '                           f"metadata.{TARGET_AGENT_FIELD} is not a valid agent id")\n',
         '    target = target if isinstance(target, str) else "did:aera:agent:any"\n', 1)),

    ("peer.py: an anonymous peer is treated as an authenticated principal",
     "peer.py",
     lambda s: s.replace("        authenticated_principal=None,\n    )\n",
                         '        authenticated_principal="external",\n    )\n')),
]


def run() -> tuple[int, int, str]:
    p = subprocess.run(
        [sys.executable, "-m", "pytest", TEST, "-q", "-p", "no:cacheprovider"],
        cwd=ROOT, capture_output=True, text=True)
    lines = [l for l in p.stdout.strip().splitlines() if l.strip()]
    tail = lines[-1] if lines else ""
    failed = int(m.group(1)) if (m := re.search(r"(\d+) failed", tail)) else 0
    passed = int(m.group(1)) if (m := re.search(r"(\d+) passed", tail)) else 0
    if failed == 0 and passed == 0 and "error" in p.stdout.lower():
        failed = -1  # collection error counts as "not green"
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
