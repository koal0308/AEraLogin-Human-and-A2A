"""Pre-push secret / credential / local-path scanner.

Scans every file that WOULD be committed (i.e. not excluded by .gitignore
rules evaluated by `tools/repo_audit.py --list`) and reports
`path:line  TYPE` only. Secret VALUES are never printed.

    ./venv/bin/python tools/secret_scan.py            # scan candidate files
    ./venv/bin/python tools/secret_scan.py --paths    # also report absolute local paths

Exit code 1 if any finding of severity HIGH remains.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools"))
from repo_audit import candidate_files  # noqa: E402

# (type, severity, regex). Patterns are deliberately specific to avoid
# flagging public identifiers (addresses, key_ids, test vectors).
PATTERNS = [
    ("PEM private key", "HIGH", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")),
    ("GitHub token", "HIGH", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|github_pat_[A-Za-z0-9_]{60,}")),
    ("OpenAI-style key", "HIGH", re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{32,}")),
    ("xAI key", "HIGH", re.compile(r"\bxai-[A-Za-z0-9]{40,}")),
    ("Google API key", "HIGH", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("AWS access key", "HIGH", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Slack token", "HIGH", re.compile(r"\bxox[abpr]-[A-Za-z0-9-]{10,}")),
    ("Telegram bot token", "HIGH", re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b")),
    ("Discord bot token", "HIGH", re.compile(r"\b[MN][A-Za-z\d]{23,25}\.[\w-]{6}\.[\w-]{27,}\b")),
    ("RPC URL with API key", "HIGH", re.compile(r"https://[a-z0-9.-]*(?:alchemy|infura|quiknode|ankr)[a-z0-9./-]*/v\d/[A-Za-z0-9_-]{20,}")),
    ("Hex private key assignment", "HIGH", re.compile(
        r"(?i)(?:private[_ ]?key|priv[_ ]?key|secret|mnemonic|seed)[\"']?\s*[:=]\s*[\"']?(?:0x)?[0-9a-f]{64}\b")),
    ("Secret-like env assignment", "MEDIUM", re.compile(
        r"(?m)^\s*(?:export\s+)?[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|API_KEY|PRIVATE_KEY|PASSPHRASE)[A-Z0-9_]*\s*=\s*[\"']?(?!\s*$)(?!your|change|<|\$|\{|xxx|placeholder|example|TEST-ONLY|test|dummy|none|null|false|true|os\.|getenv)[^\s\"'#]{16,}")),
    ("Enrollment code", "HIGH", re.compile(r"aera-enroll-[0-9a-f]{16}\.[A-Za-z0-9_-]{32}")),
]

# Well-known PUBLIC test vectors (Anvil/Hardhat default accounts). These are
# published and funded on no real network; flagged as INFO, not HIGH.
PUBLIC_TEST_KEYS = {
    "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    "5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
    "7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
}

LOCAL_PATH = re.compile(r"(?:/home/[a-z_][a-z0-9_-]*/|/Users/[A-Za-z]|C:\\Users\\|/Volumes/|/var/www/)")

# Reviewed false positives: (path, finding type) -> reason. Every entry was
# checked by hand; none contains a usable credential. Keep this list short.
ALLOW = {
    (".env.example", "RPC URL with API key"): "placeholder YOUR_ALCHEMY_API_KEY",
    ("tests/agent/test_a2a_gateway.py", "PEM private key"): "truncated non-parseable PEM fixture for redaction test",
    ("aera-agent-security-lab/tests/unit/test_external_a2a_auth.py", "PEM private key"): "truncated non-parseable PEM fixture",
    ("aera-agent-security-lab/tests/unit/test_external_a2a_audit.py", "PEM private key"): "header-only string for scrub test",
    ("tools/secret_scan.py", "Enrollment code"): "the pattern itself",
}


def scan(report_paths: bool) -> int:
    high = 0
    for rel in candidate_files():
        path = REPO / rel
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            if len(line) > 5000:
                line = line[:5000]
            for kind, sev, rx in PATTERNS:
                m = rx.search(line)
                if not m:
                    continue
                if any(k in m.group(0).lower() for k in PUBLIC_TEST_KEYS):
                    sev = "INFO(public test vector)"
                elif (rel, kind) in ALLOW:
                    sev = "ALLOWED"
                print(f"{sev:8} {rel}:{lineno}  {kind}")
                if sev == "HIGH":
                    high += 1
            if report_paths and LOCAL_PATH.search(line):
                print(f"PATH     {rel}:{lineno}  absolute local path")
    print(f"\nHIGH findings: {high}")
    return 1 if high else 0


if __name__ == "__main__":
    raise SystemExit(scan("--paths" in sys.argv))
