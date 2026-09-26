"""Negative proof for the external A2A tests.

Each mutant breaks exactly one safety property. A mutant that does NOT cause a
failure would mean the corresponding test is decorative.
"""
from __future__ import annotations

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent
SRC = ROOT / "src" / "external_a2a"
TESTS = [
    "tests/unit/test_external_a2a_card.py",
    "tests/unit/test_external_a2a_auth.py",
    "tests/unit/test_external_a2a_net.py",
    "tests/unit/test_external_a2a_audit.py",
    "tests/integration/test_external_a2a_client.py",
]

MUTANTS = [
    ("net.py: every address is considered public (SSRF guard disabled)",
     "net.py",
     lambda s: s.replace(
         "def _address_is_public(ip: str) -> bool:\n",
         "def _address_is_public(ip: str) -> bool:\n    return True\n", 1)),

    ("auth.py: AEra credential rejection removed",
     "auth.py",
     lambda s: s.replace(
         '    """Refuse anything that smells like an AEra-issued token or key material."""\n',
         '    """MUTANT"""\n    return\n', 1)),

    ("client.py: JSON-RPC method hardcoded to the 0.3 name",
     "client.py",
     lambda s: s.replace(
         'SEND_METHOD_BY_VERSION = {"0.3": "message/send", "1.0": "SendMessage"}',
         'SEND_METHOD_BY_VERSION = {"0.3": "message/send", "1.0": "message/send"}', 1)),

    ("client.py: JSON-RPC error objects ignored",
     "client.py",
     lambda s: s.replace('if "error" in data and data.get("error") is not None:',
                         "if False:", 1)),

    ("card.py: publishing a securityScheme wrongly implies auth is required",
     "card.py",
     lambda s: s.replace(
         "        return bool(self.security_requirements)\n",
         "        return bool(self.security_schemes or self.security_requirements)\n", 1)),

    ("audit.py: scrubbing disabled (secrets would be persisted)",
     "audit.py",
     lambda s: s.replace(
         '    """Replace anything that looks like a credential. Defence in depth."""\n',
         '    """MUTANT"""\n    return value\n', 1)),
]


def run() -> tuple[int, int, str]:
    p = subprocess.run(
        [sys.executable, "-m", "pytest", *TESTS, "-q", "-p", "no:cacheprovider"],
        cwd=ROOT, capture_output=True, text=True)
    tail = p.stdout.strip().splitlines()[-1] if p.stdout.strip() else ""
    failed = int(m.group(1)) if (m := re.search(r"(\d+) failed", tail)) else 0
    passed = int(m.group(1)) if (m := re.search(r"(\d+) passed", tail)) else 0
    return passed, failed, tail


def main() -> int:
    passed, failed, tail = run()
    print(f"BASELINE: {tail}")
    if failed:
        print("baseline is not green; aborting")
        return 1
    baseline = passed

    caught = 0
    for label, filename, mutate in MUTANTS:
        path = SRC / filename
        original = path.read_text()
        mutated = mutate(original)
        if mutated == original:
            print(f"SKIPPED (no textual change): {label}")
            continue
        path.write_text(mutated)
        try:
            _, mfailed, mtail = run()
        finally:
            path.write_text(original)
        status = "CAUGHT" if mfailed else "MISSED"
        caught += bool(mfailed)
        print(f"{status:7} {mfailed:>3} failures | {label}")

    passed, failed, tail = run()
    print(f"RESTORED: {tail}")
    ok = passed == baseline and failed == 0 and caught == len(MUTANTS)
    print(f"RESULT: {caught}/{len(MUTANTS)} mutants caught; "
          f"baseline restored: {passed == baseline and failed == 0}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
