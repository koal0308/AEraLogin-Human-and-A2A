"""Runtime configuration.

Three groups are kept deliberately separate (§20):

  AEra      — where the authority lives and which identity we claim
  Runtime   — local operational settings
  Secrets   — the private key and provider credentials

Only the first two are ever printed, logged, returned by `/health` or included
in an audit record. `safe_dict()` is the single place that decides what is
publishable, so there is one thing to review rather than many scattered log
statements.

Secrets are read from the environment and never written back anywhere.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from .internal_auth import DEFAULT_RUNTIME_DIR

DEFAULT_AERA_URL = "http://127.0.0.1:8840"
DEFAULT_KEY_PATH = "~/.aera/agent_key.json"
DEFAULT_PROVIDER = "mock"

#: Substrings that must never appear in anything the runtime publishes.
SECRET_ENV_MARKERS = (
    "AERA_RUNTIME_KEY_PASSPHRASE",
    "AERA_RUNTIME_INTERNAL_SECRET",
    "AGENT_JWT_SECRET",
    "XAI_API_KEY",
    "GROK_API_KEY",
    "DEEPSEEK_API_KEY",
    "ANTHROPIC_API_KEY",
    "CLAUDE_API_KEY",
    "TOKEN_SECRET",
)


class ConfigError(Exception):
    """The runtime cannot start with the configuration it was given."""


def identity_path_for(key_path: str | Path) -> Path:
    """`agent_key.json` -> `agent_key.identity.json` (same directory)."""
    p = Path(key_path).expanduser()
    return p.with_name(p.stem + ".identity.json")


def load_identity_file(path: Path) -> Optional[tuple[str, str]]:
    """Return (agent_id, key_id) or None. Never raises on a missing file."""
    import json

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    agent_id, key_id = data.get("agent_id"), data.get("key_id")
    if isinstance(agent_id, str) and isinstance(key_id, str) and agent_id and key_id:
        return agent_id, key_id
    return None


@dataclass(frozen=True)
class RuntimeConfig:
    # --- AEra (authority) ---
    aera_base_url: str = DEFAULT_AERA_URL
    agent_id: Optional[str] = None
    key_id: Optional[str] = None

    # --- Runtime (local) ---
    key_path: str = DEFAULT_KEY_PATH
    runtime_dir: str = DEFAULT_RUNTIME_DIR
    provider: str = DEFAULT_PROVIDER
    model: Optional[str] = None
    log_level: str = "INFO"
    request_timeout: float = 30.0
    max_reply_chars: int = 2000

    @classmethod
    def from_env(cls) -> "RuntimeConfig":
        key_path = os.getenv("AERA_RUNTIME_KEY_PATH") or DEFAULT_KEY_PATH
        agent_id = os.getenv("AERA_RUNTIME_AGENT_ID") or None
        key_id = os.getenv("AERA_RUNTIME_KEY_ID") or None
        if not agent_id and not key_id:
            # Written by `agent_runtime enroll`. Contains only PUBLIC ids.
            # Explicit env always wins, so existing deployments are unaffected.
            stored = load_identity_file(identity_path_for(key_path))
            if stored:
                agent_id, key_id = stored
        return cls(
            aera_base_url=(os.getenv("AERA_BASE_URL") or DEFAULT_AERA_URL).rstrip("/"),
            agent_id=agent_id,
            key_id=key_id,
            key_path=key_path,
            runtime_dir=os.getenv("AERA_RUNTIME_DIR") or DEFAULT_RUNTIME_DIR,
            provider=(os.getenv("AERA_RUNTIME_PROVIDER") or DEFAULT_PROVIDER).lower(),
            model=os.getenv("AERA_RUNTIME_MODEL") or None,
            log_level=(os.getenv("AERA_RUNTIME_LOG_LEVEL") or "INFO").upper(),
            request_timeout=float(os.getenv("AERA_RUNTIME_TIMEOUT") or 30.0),
            max_reply_chars=int(os.getenv("AERA_RUNTIME_MAX_REPLY") or 2000),
        )

    @property
    def resolved_key_path(self) -> Path:
        return Path(self.key_path).expanduser()

    def require_identity(self) -> None:
        if not self.agent_id or not self.key_id:
            raise ConfigError(
                "AERA_RUNTIME_AGENT_ID and AERA_RUNTIME_KEY_ID must be set; "
                "register the agent first (the owner approves registration, "
                "the runtime never holds the owner wallet key)")

    def safe_dict(self) -> dict[str, Any]:
        """Everything here is safe to log, publish and return. No secrets."""
        return {
            "aera_base_url": self.aera_base_url,
            "agent_id": self.agent_id,
            "key_id": self.key_id,
            "key_path": str(self.resolved_key_path),
            "provider": self.provider,
            "model": self.model,
            "log_level": self.log_level,
        }
