"""Negative proof for the Human Identity tests (Phase 0.1).

Each mutant removes exactly one identity/ownership property. A mutant that
survives (tests still green) means the corresponding test proves nothing.
SKIPPED counts as a failure of this script: a mutant must change the code.
"""
from __future__ import annotations

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent
TESTS = ["tests/human_identity", "tests/agent/test_human_identity_integration.py"]

MUTANTS = [
    ("repository: UNIQUE(provider, provider_subject) dropped",
     "identity/repository.py",
     lambda s: s.replace("        UNIQUE(provider, provider_subject),\n", "", 1)),

    ("repository: existing binding not looked up (new human on every login)",
     "identity/repository.py",
     lambda s: s.replace("    existing = resolve(conn, provider, subject)\n",
                         "    existing = None\n", 1)),

    ("repository: race loser does not roll back its human (orphans)",
     "identity/repository.py",
     lambda s: s.replace('        conn.execute("ROLLBACK TO SAVEPOINT identity_create")\n',
                         "", 1)),

    ("repository: human_id derived from the wallet instead of random",
     "identity/repository.py",
     lambda s: s.replace("    human_id = new_human_id()\n",
                         "    human_id = HUMAN_ID_PREFIX + subject[2:34]\n", 1)),

    ("providers: wallet address not validated",
     "identity/providers.py",
     lambda s: s.replace("    if not _WALLET_RE.match(value):\n", "    if False:\n", 1)),

    ("providers: future providers (google/github) accepted",
     "identity/providers.py",
     lambda s: s.replace('IMPLEMENTED_PROVIDERS = frozenset({WALLET})',
                         'IMPLEMENTED_PROVIDERS = frozenset({WALLET, "google", "github"})', 1)
     .replace('    raise ProviderError("unsupported_provider")  # pragma: no cover\n',
              "    return subject\n", 1)),

    ("authorization: owner_id mismatch ignored (wallet-only check)",
     "identity/authorization.py",
     lambda s: s.replace("    return owner_id is None or owner_id == human_id\n",
                         "    return True\n", 1)),

    ("authorization: wallet mismatch ignored (human-only check)",
     "identity/authorization.py",
     lambda s: s.replace("    if (owner_wallet or \"\").lower() != wallet.lower():\n        return False\n",
                         "", 1)),

    ("authorization: disabled humans still authorized",
     "identity/authorization.py",
     lambda s: s.replace("    return human.human_id if human.is_active else None\n",
                         "    return human.human_id\n", 1)),

    ("migration: overwrites existing owner_id",
     "identity/migration.py",
     lambda s: s.replace("               WHERE owner_id IS NULL\n                 AND EXISTS",
                         "               WHERE EXISTS", 1)),

    ("migration: invalid wallets not skipped",
     "identity/migration.py",
     lambda s: s.replace("                wallets.add(wallet_subject(raw))\n",
                         "                wallets.add(str(raw).lower())\n", 1)),

    ("create_agent: owner_id not set on new agents",
     "agent/routes.py",
     lambda s: s.replace('    conn.execute("UPDATE agents SET owner_id = ? WHERE agent_id = ?",\n'
                         "                 (human_id, agent_id))\n", "", 1)),

    ("dashboard: owner_id not checked (wallet-only)",
     "server.py",
     lambda s: s.replace("    return linked is None or linked == human_id\n",
                         "    return True\n", 1)),
]


def run() -> tuple[int, int, str]:
    p = subprocess.run(
        [sys.executable, "-m", "pytest", *TESTS, "-q", "-p", "no:cacheprovider"],
        cwd=ROOT, capture_output=True, text=True)
    lines = [l for l in p.stdout.strip().splitlines() if l.strip()]
    tail = lines[-1] if lines else ""
    failed = int(m.group(1)) if (m := re.search(r"(\d+) failed", tail)) else 0
    errors = int(m.group(1)) if (m := re.search(r"(\d+) error", tail)) else 0
    passed = int(m.group(1)) if (m := re.search(r"(\d+) passed", tail)) else 0
    return passed, failed + errors, tail


def main() -> int:
    passed, failed, tail = run()
    print(f"BASELINE: {tail}")
    if failed:
        print("baseline not green; aborting")
        return 1
    baseline = passed

    caught = 0
    for label, filename, mutate in MUTANTS:
        path = ROOT / filename
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
