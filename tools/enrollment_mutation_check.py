"""Mutation check for the enrollment security controls.

Each mutation removes ONE control from agent/enrollment.py or agent/routes.py,
runs the enrollment test module, and asserts that at least one test FAILS.
The original file is always restored.

    ./venv/bin/python tools/enrollment_mutation_check.py
"""
from __future__ import annotations

import pathlib
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[1]
TEST = "tests/agent/test_agent_enrollment.py"

MUTATIONS = [
    ("PoP signature check", "agent/enrollment.py",
     "        if not verify_signature(public_key, signature,",
     "        if False and not verify_signature(public_key, signature,"),
    # Two layers (status check + conditional UPDATE); both must go for the
    # attack to work, so the mutation removes both.
    ("single-claim guard (both layers)", "agent/enrollment.py",
     '        if row["status"] != STATUS_PENDING:\n            raise EnrollmentError("enrollment_already_claimed", 409)',
     '        if False:\n            raise EnrollmentError("enrollment_already_claimed", 409)',
     '            "WHERE enrollment_id=? AND status=?",\n            (STATUS_KEY_SUBMITTED, public_key, _now(), row["enrollment_id"], STATUS_PENDING),',
     '            "WHERE enrollment_id=? AND ?=?",\n            (STATUS_KEY_SUBMITTED, public_key, _now(), row["enrollment_id"], 1, 1),'),
    ("secret comparison", "agent/enrollment.py",
     'if row is None or not hmac.compare_digest(row["secret_hash"], _hash_secret(secret)):',
     "if row is None:"),
    ("secret hashing at rest", "agent/enrollment.py",
     "(eid, owner, _hash_secret(secret), label,",
     "(eid, owner, secret, label,"),
    ("expiry check on claim", "agent/enrollment.py",
     '        if _expired(row):\n            raise EnrollmentError("enrollment_expired", 410)\n        if row["status"] != STATUS_PENDING:',
     '        if row["status"] != STATUS_PENDING:'),
    ("owner binding on completion", "agent/enrollment.py",
     '    if row is None or row["owner_wallet"] != (owner or "").lower():',
     "    if row is None:"),
    ("challenge bound to enrollment", "agent/routes.py",
     "            agent_id=enrollment.challenge_binding(enrollment_id),",
     "            agent_id=None,"),
    ("duplicate active key", "agent/enrollment.py",
     "        if dup is not None:",
     "        if False:"),
    ("open-enrollment cap", "agent/enrollment.py",
     "        if open_count >= MAX_OPEN_ENROLLMENTS_PER_OWNER:",
     "        if False:"),
]


def run_tests() -> int:
    return subprocess.run([sys.executable, "-m", "pytest", TEST, "-q", "-x",
                           "-p", "no:warnings", "-p", "no:cacheprovider"],
                          cwd=REPO, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode


def main() -> int:
    assert run_tests() == 0, "baseline must pass before mutating"
    survived = []
    for name, rel, *pairs in MUTATIONS:
        path = REPO / rel
        original = path.read_text(encoding="utf-8")
        mutated = original
        for old, new in zip(pairs[::2], pairs[1::2]):
            assert mutated.count(old) == 1, f"mutation anchor not unique/absent: {name}"
            mutated = mutated.replace(old, new)
        try:
            path.write_text(mutated, encoding="utf-8")
            killed = run_tests() != 0
        finally:
            path.write_text(original, encoding="utf-8")
        print(f"{'KILLED ' if killed else 'SURVIVED'}  {name}")
        if not killed:
            survived.append(name)
    print(f"\n{len(MUTATIONS) - len(survived)}/{len(MUTATIONS)} mutations killed")
    return 1 if survived else 0


if __name__ == "__main__":
    raise SystemExit(main())
