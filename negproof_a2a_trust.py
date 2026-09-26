#!/usr/bin/env python3
"""Negative proof for the AEra External Peer Trust Assessment layer.

A green suite proves the code does what the tests expect. It does NOT prove the
tests would notice if the code were wrong. This script breaks the
implementation on purpose, one defect at a time, and asserts the suite turns
red. A mutant that survives means the corresponding property is unguarded and
the green tick was decoration.

Each mutant is a plausible mistake -- the kind a tired developer, a careless
refactor or a bad merge could realistically produce. Several are the specific
mistakes Part J was written to prevent: owner assertion becoming the decision,
absence of evidence becoming good evidence, and trust quietly outranking
revocation.

Usage:  ./venv/bin/python negproof_a2a_trust.py
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
GW = ROOT / "a2a_gateway"
SUITE = "tests/agent/test_a2a_trust.py"

#: Deadlines for the HARNESS ONLY. These bound how long the proof waits for a
#: pytest run; they do not touch, relax or skip a single assertion. A clean run
#: of this suite takes about a second, so both values are orders of magnitude
#: above anything a healthy mutant needs.
BASELINE_TIMEOUT = 120.0
MUTANT_TIMEOUT = 120.0

#: (label, file, find, replace)
MUTANTS: list[tuple[str, Path, str, str]] = [
    # --- the central product decision: AEra derives it, the owner does not ---
    (
        "trust.py: let owner standing dominate the assessment",
        GW / "trust.py",
        "W_OWNER_STANDING = 0.20",
        "W_OWNER_STANDING = 0.80",
    ),
    (
        "trust.py: treat an unknown owner as a good owner by default",
        GW / "trust.py",
        "        if not self.known:\n            return 0.0",
        "        if not self.known:\n            return 1.0",
    ),
    # --- absence of evidence is not evidence ---------------------------------
    (
        "trust.py: drop the confidence gate, so silence becomes trust",
        GW / "trust.py",
        "    if confidence < MIN_CONFIDENCE_FOR_OPINION:",
        "    if False:",
    ),
    (
        "trust.py: let a high score reach 'established' without confidence",
        GW / "trust.py",
        "    if score >= SCORE_ESTABLISHED and confidence >= MIN_CONFIDENCE_FOR_ESTABLISHED:",
        "    if score >= SCORE_ESTABLISHED:",
    ),
    (
        "trust.py: report 'minimal' instead of 'unknown' for a peer with no history",
        GW / "trust.py",
        "        return LEVEL_UNKNOWN\n    if score >= SCORE_ESTABLISHED",
        "        return LEVEL_MINIMAL\n    if score >= SCORE_ESTABLISHED",
    ),
    # --- negative evidence must actually count -------------------------------
    (
        "trust.py: stop subtracting negative evidence from the score",
        GW / "trust.py",
        "    score = _clamp(positive - negative_penalty - revoked_penalty)",
        "    score = _clamp(positive)",
    ),
    (
        "trust.py: let good history average away proven misbehaviour",
        GW / "trust.py",
        "    if penalty >= UNTRUSTED_PENALTY_THRESHOLD:\n        return LEVEL_UNTRUSTED",
        "    if False:\n        return LEVEL_UNTRUSTED",
    ),
    (
        "trust.py: weigh a replay attempt no more than a rate limit",
        GW / "trust.py",
        "    EV_REPLAY_REJECTED: 2.0,",
        "    EV_REPLAY_REJECTED: 0.5,",
    ),
    (
        "trust.py: ignore revoked credentials entirely",
        GW / "trust.py",
        "W_REVOKED_CREDENTIALS = 0.20",
        "W_REVOKED_CREDENTIALS = 0.0",
    ),
    # --- anonymous traffic must stay outside the layer ------------------------
    (
        "trust.py: accept evidence with no peer id (anonymous gets a history)",
        GW / "trust.py",
        "    if not peer_id or not isinstance(peer_id, str):\n        return False",
        "    if not isinstance(peer_id, str):\n        peer_id = 'peer_anonymous'",
    ),
    (
        "trust.py: return an assessment for an anonymous caller",
        GW / "trust.py",
        "    if not peer_id:\n        return None\n    summary = summarize_evidence",
        "    if not peer_id:\n        peer_id = 'peer_anonymous'\n    summary = summarize_evidence",
    ),
    # --- the closed event vocabulary -----------------------------------------
    (
        "trust.py: accept any event type a caller invents",
        GW / "trust.py",
        "    if event_type not in KNOWN_EVENTS:\n        return False",
        "    if False:\n        return False",
    ),
    # --- storage bounds -------------------------------------------------------
    (
        "trust.py: remove the per-peer evidence cap",
        GW / "trust.py",
        "MAX_EVIDENCE_PER_PEER = 500",
        "MAX_EVIDENCE_PER_PEER = 10_000_000",
    ),
    (
        "trust.py: never prune after writing evidence",
        GW / "trust.py",
        "    prune_peer(conn, peer_id, now=moment)\n    return True",
        "    return True",
    ),
    (
        "trust.py: keep evidence forever regardless of the TTL",
        GW / "trust.py",
        "EVIDENCE_TTL_DAYS = 90",
        "EVIDENCE_TTL_DAYS = 100_000",
    ),
    # --- decay ----------------------------------------------------------------
    (
        "trust.py: make trust permanently sticky (no decay)",
        GW / "trust.py",
        "    if idle_days <= DECAY_GRACE_DAYS:\n        return 1.0",
        "    return 1.0\n    if idle_days <= DECAY_GRACE_DAYS:",
    ),
    (
        "trust.py: give a never-seen peer a full positive multiplier",
        GW / "trust.py",
        "    if last_seen is None:\n        return DECAY_FLOOR",
        "    if last_seen is None:\n        return 1.0",
    ),
    # --- peer identity survives credential rotation ---------------------------
    (
        "trust.py: key evidence on the credential instead of the peer",
        GW / "trust.py",
        f'"SELECT event_type, COUNT(*), MIN(occurred_at), MAX(occurred_at) "\n            f"FROM {{TABLE}} WHERE peer_id = ? GROUP BY event_type"',
        f'"SELECT event_type, COUNT(*), MIN(occurred_at), MAX(occurred_at) "\n            f"FROM {{TABLE}} WHERE credential_id = ? GROUP BY event_type"',
    ),
    # --- enforcement stays off ------------------------------------------------
    (
        "trust.py: silently enable authorization enforcement",
        GW / "trust.py",
        "def trust_enforces_authorization() -> bool:",
        "def trust_enforces_authorization() -> bool:\n    return True\n\ndef _unused_trust_enforces_authorization() -> bool:",
    ),
    (
        "trust.py: turn trust observation on by default",
        GW / "trust.py",
        '    return ENFORCEMENT_MONITOR if value == ENFORCEMENT_MONITOR else ENFORCEMENT_OFF',
        '    return ENFORCEMENT_MONITOR',
    ),
    # --- determinism and versioning -------------------------------------------
    (
        "trust.py: drop the policy version from the assessment",
        GW / "trust.py",
        'POLICY_VERSION = "aera-peer-trust-1"',
        'POLICY_VERSION = ""',
    ),
    (
        "trust.py: make the assessment non-deterministic",
        GW / "trust.py",
        "def _clamp(value: float) -> float:\n    return max(0.0, min(1.0, value))",
        "def _clamp(value: float) -> float:\n    import random\n    return max(0.0, min(1.0, value * random.uniform(0.5, 1.0)))",
    ),
    # --- the owner surface stays read-only ------------------------------------
    (
        "trust.py: expose the raw score and factors to the owner",
        GW / "trust.py",
        '            "observed_events": sum(self.evidence_counts.values()),',
        '            "observed_events": sum(self.evidence_counts.values()),\n            "trust_score": self.trust_score,\n            "factors": [f.to_dict() for f in self.factors],',
    ),
    (
        "trust.py: advertise the assessment as owner-settable",
        GW / "trust.py",
        '            "owner_settable": False,',
        '            "owner_settable": True,',
    ),
    # --- the audit line stays minimal -----------------------------------------
    (
        "trust.py: leak the full reasoning into the audit line",
        GW / "trust.py",
        '            "policy": self.policy_version,\n        }',
        '            "policy": self.policy_version,\n            "factors": [f.to_dict() for f in self.factors],\n        }',
    ),
    # --- trust must not reach the request path --------------------------------
    (
        "handler.py: charge the peer for AEra's own internal errors",
        GW / "handler.py",
        '    if result_label == "success":\n        return EV_REQUEST_SUCCESS',
        '    if result_label in ("success", "internal_error"):\n        return EV_REQUEST_SUCCESS',
    ),
    (
        "handler.py: stop distinguishing a replay from a malformed request",
        GW / "handler.py",
        "    if replay_rejected:\n        return EV_REPLAY_REJECTED",
        "    if False:\n        return EV_REPLAY_REJECTED",
    ),
    (
        "handler.py: record evidence for unauthenticated callers too",
        GW / "handler.py",
        '    if not getattr(peer, "is_authenticated", False) or not peer.peer_id:\n        return None',
        '    if False:\n        return None',
    ),
    (
        "handler.py: let a failing trust layer raise into the request path",
        GW / "handler.py",
        "    except Exception:  # noqa: BLE001\n        return None\n    finally:\n        try:\n            conn.close()",
        "    except Exception:  # noqa: BLE001\n        raise\n    finally:\n        try:\n            conn.close()",
    ),
    # --- trust must never outrank credential lifecycle ------------------------
    (
        "credentials.py: let a trusted peer keep using a revoked credential",
        GW / "credentials.py",
        "    if record.status != STATUS_ACTIVE:",
        "    if False:",
    ),
    (
        "credentials.py: let a trusted peer keep using an expired credential",
        GW / "credentials.py",
        "    if expires is None or expires <= moment:",
        "    if False:",
    ),
    # --- level separation ------------------------------------------------------
    (
        "peer.py: let a highly trusted peer become an AEra agent",
        GW / "peer.py",
        "    def is_trusted_aera_agent(self) -> bool:",
        "    def is_trusted_aera_agent(self) -> bool:\n        return True\n\n    def _old_is_trusted_aera_agent(self) -> bool:",
    ),
]


def run_suite(timeout: float | None = None) -> tuple[bool, str, bool]:
    """Run the suite once. Returns (passed, summary, timed_out).

    The timeout exists because a mutant can make the suite *expensive* rather
    than merely wrong. Removing the evidence cap is the clearest example: the
    storage-bound test then tries to write the new cap's worth of rows, and an
    unbounded cap means an unbounded test. Without a deadline the harness waits
    forever, which looks exactly like a hung machine and hides the result of
    every mutant queued behind it.

    A timeout is NOT reported as "caught". The suite did not fail; it never
    finished, so nothing was demonstrated either way. Conflating the two would
    let a genuinely unguarded property hide behind a slow one.
    """
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", SUITE, "-x", "-q", "--no-header"],
            cwd=ROOT, capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        # subprocess.run kills the child before re-raising, so no orphaned
        # pytest survives to keep burning CPU after the harness moves on.
        return False, f"TIMED OUT after {timeout:.0f}s", True
    tail = (proc.stdout or "").strip().splitlines()
    return proc.returncode == 0, tail[-1] if tail else "", False


def main() -> int:
    # Optional "start end" (1-based, inclusive) so the proof can be run in
    # slices on a machine with a command timeout. The totals below always name
    # the slice actually executed, so a partial run can never be mistaken for
    # a full one.
    first, last = 1, len(MUTANTS)
    if len(sys.argv) >= 3:
        first, last = int(sys.argv[1]), int(sys.argv[2])
    selected = [(i, m) for i, m in enumerate(MUTANTS, 1) if first <= i <= last]

    print("=" * 78)
    print("NEGATIVE PROOF -- AEra external peer trust assessment")
    if (first, last) != (1, len(MUTANTS)):
        print(f"SLICE {first}..{last} of {len(MUTANTS)} -- PARTIAL RUN")
    print("=" * 78)

    ok, summary, _ = run_suite(timeout=BASELINE_TIMEOUT)
    if not ok:
        print(f"\nBASELINE IS RED -- fix that first.\n  {summary}")
        return 2
    print(f"\nBaseline: {summary}\n")

    # A mutant gets generously more time than a clean run needs, so a merely
    # slower suite is never mistaken for a hung one, but not so much that a
    # runaway can stall the whole proof.
    deadline = MUTANT_TIMEOUT
    print(f"Per-mutant deadline: {deadline:.0f}s\n")

    caught, survived, timed_out = 0, [], []

    for index, (label, path, find, replace) in selected:
        original = path.read_text(encoding="utf-8")
        if find not in original:
            print(f"[{index:2}/{len(MUTANTS)}] !! ANCHOR MISSING -- {label}")
            survived.append((label, "anchor not found; mutant never applied"))
            continue
        if original.count(find) > 1:
            print(f"[{index:2}/{len(MUTANTS)}] !! AMBIGUOUS ANCHOR -- {label}")
            survived.append((label, "anchor matches more than once"))
            continue
        if find == replace:
            print(f"[{index:2}/{len(MUTANTS)}] !! NO-OP MUTANT -- {label}")
            survived.append((label, "find and replace are identical"))
            continue

        path.write_text(original.replace(find, replace, 1), encoding="utf-8")
        try:
            passed, summary, expired = run_suite(timeout=deadline)
        finally:
            path.write_text(original, encoding="utf-8")

        if expired:
            print(f"[{index:2}/{len(MUTANTS)}] TIMEOUT   {label}")
            timed_out.append((label, summary))
        elif passed:
            print(f"[{index:2}/{len(MUTANTS)}] SURVIVED  {label}")
            survived.append((label, summary))
        else:
            caught += 1
            print(f"[{index:2}/{len(MUTANTS)}] caught    {label}")

    print("\n" + "=" * 78)
    print(f"RESULT: {caught}/{len(selected)} mutants caught "
          f"(slice {first}..{last} of {len(MUTANTS)})")
    if survived:
        print("\nSURVIVING MUTANTS -- these properties are NOT protected:")
        for label, detail in survived:
            print(f"  - {label}\n      {detail}")
    if timed_out:
        print("\nTIMED-OUT MUTANTS -- NOT a pass and NOT a catch.")
        print("The suite never finished, so nothing was demonstrated. Either")
        print("the mutant makes a test unboundedly expensive, or a test's cost")
        print("depends on the value the mutant changed. Both need a human.")
        for label, detail in timed_out:
            print(f"  - {label}\n      {detail}")
    print("=" * 78)

    ok, summary, _ = run_suite(timeout=BASELINE_TIMEOUT)
    print(f"Baseline restored: {summary}")
    return 0 if (not survived and not timed_out and ok) else 1


if __name__ == "__main__":
    raise SystemExit(main())
