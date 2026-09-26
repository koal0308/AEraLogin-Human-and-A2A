"""Standalone DeepSeek reachability probe.

Proves whether the configured key authenticates, WITHOUT printing the key.
    cd aera-agent-security-lab && ../venv/bin/python tools/deepseek_check.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.config.settings import get_settings  # noqa: E402
from src.providers.base import LLMError  # noqa: E402
from src.providers.deepseek import DeepSeekProvider  # noqa: E402


def main() -> int:
    s = get_settings()
    print("config:", s.redacted())
    if not s.deepseek_available:
        print("RESULT: NO KEY CONFIGURED")
        return 2
    p = DeepSeekProvider(s.deepseek_api_key, base_url=s.deepseek_base_url,
                         model=s.deepseek_model, timeout=s.http_timeout)
    try:
        r = p.generate("Reply with exactly: OK")
    except LLMError as e:
        msg = str(e)
        print("RESULT: ERROR")
        print("detail:", msg)
        if "401" in msg or "Authentication" in msg:
            print("interpretation: key REJECTED (authentication failure)")
        elif "402" in msg or "Insufficient Balance" in msg:
            print("interpretation: key ACCEPTED, account has NO BALANCE "
                  "(HTTP 402 is returned only after successful authentication)")
        return 1
    print("RESULT: OK")
    print("model:", r.model)
    print("text:", r.text[:200])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
