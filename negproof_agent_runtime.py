"""Negative proof for the Packaged Agent Runtime tests.

Same contract as the earlier negative proofs: each mutant removes exactly one
security property that the runtime is supposed to hold. If a mutant survives,
the corresponding test is decoration rather than evidence.

The mutants are chosen to match the failure modes that actually matter for a
process that holds a signing key and talks to a model:

  * the key escaping the runtime
  * the internal channel degrading to "local means trusted"
  * revocation being survivable
  * caller text or model output acquiring authority
  * provider trouble being mistaken for identity trouble
"""
from __future__ import annotations

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent
RT = ROOT / "agent_runtime"
TESTS = ["tests/agent/test_agent_runtime.py"]


MUTANTS = [
    # -- the private key boundary -------------------------------------------
    ("keystore.py: the key store exposes the raw private key",
     "keystore.py",
     lambda s: s.replace(
         "    def sign(self, data: bytes) -> bytes:",
         "    @property\n"
         "    def private_key(self) -> bytes:\n"
         "        return self._signer.raw_private()\n\n"
         "    def sign(self, data: bytes) -> bytes:", 1)),

    ("keystore.py: the key file is created world-readable",
     "keystore.py",
     lambda s: s.replace(
         "os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)",
         "os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)", 1)),

    # -- the internal channel boundary --------------------------------------
    ("server.py: internal authentication is skipped (localhost is trusted)",
     "server.py",
     lambda s: s.replace(
         "                payload = verify_envelope(envelope, secret)",
         "                payload = envelope.get(\"payload\") or {}", 1)),

    ("server.py: the runtime serves even without a configured internal secret",
     "server.py",
     lambda s: s.replace(
         '                return self._error("runtime_misconfigured",\n'
         '                                   "internal channel is not configured")',
         '                secret = ""', 1)),

    ("internal_auth.py: the freshness window is not enforced (replayable)",
     "internal_auth.py",
     lambda s: s.replace(
         "    if abs(current - issued_at) > MAX_ENVELOPE_AGE_SECONDS:",
         "    if False:", 1)),

    # -- the routing boundary ------------------------------------------------
    ("server.py: the runtime answers for any agent id, not only its own",
     "server.py",
     lambda s: s.replace(
         '            if payload.get("agent_id") != self.identity.agent_id:',
         "            if False:", 1)),

    # -- revocation ----------------------------------------------------------
    ("server.py: a revoked agent keeps serving inbound messages",
     "server.py",
     lambda s: s.replace("            if self.status.is_revoked:",
                         "            if False:", 1)),

    ("lifecycle.py: revocation is reversible from inside the runtime",
     "lifecycle.py",
     lambda s: s.replace(
         "            if self.state in TERMINAL_STATES and state not in TERMINAL_STATES:",
         "            if False:", 1)),

    # -- the content boundary ------------------------------------------------
    ("messaging.py: caller text is concatenated into the system prompt",
     "messaging.py",
     lambda s: s.replace("    return SYSTEM_PROMPT, text",
                         "    return SYSTEM_PROMPT + \"\\n\" + text, text", 1)),

    ("server.py: replies are signed over different bytes than the gateway verifies",
     "server.py",
     lambda s: s.replace(
         "        canonical = json.dumps(response, sort_keys=True, "
         "separators=(\",\", \":\"),\n"
         "                               ensure_ascii=True).encode(\"utf-8\")",
         "        canonical = json.dumps(response).encode(\"utf-8\")", 1)),

    # -- the provider boundary -----------------------------------------------
    ("server.py: a provider outage revokes the agent identity",
     "server.py",
     lambda s: s.replace(
         '            self.status.set(RuntimeState.DEGRADED, f"provider {exc.kind}")',
         '            self.status.set(RuntimeState.REVOKED, f"provider {exc.kind}")', 1)),

    # The redaction lives in provider.py, not in server.py: by the time the
    # server sees a ProviderFailure the message has already been summarised.
    # Mutating the server's error string therefore changes nothing, which is
    # defence in depth -- so the mutant has to attack the actual guard.
    ("provider.py: the raw provider error text is propagated verbatim",
     "provider.py",
     lambda s: s.replace(
         '    return f"provider call failed ({type(exc).__name__})"',
         "    return str(exc)", 1)),

    ("provider.py: credential resolution reports key values instead of names",
     "provider.py",
     lambda s: s.replace("                resolved.append(canonical)\n"
                         "                break",
                         "                resolved.append(value)\n"
                         "                break", 1)),

    # Note: removing only the early `continue` is an *equivalent* mutant,
    # because the canonical name is itself the first candidate in the tuple --
    # the two mechanisms protect the same property redundantly. So the mutant
    # has to remove both, which is exactly what a rewrite that "simplifies"
    # this function would do.
    ("provider.py: an alias takes precedence over an explicitly pinned key",
     "provider.py",
     lambda s: s.replace(
         '        if target.get(canonical, "").strip():\n'
         "            resolved.append(canonical)\n"
         "            continue\n", "", 1).replace(
         '    "DEEPSEEK_API_KEY": ("DEEPSEEK_API_KEY", "DEEPSEEK1_API_KEY", '
         '"DEEPSEEK2_API_KEY"),',
         '    "DEEPSEEK_API_KEY": ("DEEPSEEK1_API_KEY", "DEEPSEEK2_API_KEY", '
         '"DEEPSEEK_API_KEY"),', 1)),
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
        path = RT / filename
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
