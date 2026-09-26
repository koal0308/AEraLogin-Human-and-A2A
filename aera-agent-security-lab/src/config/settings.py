"""Lab configuration. Secrets are read from the environment only."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

LAB_ROOT = Path(__file__).resolve().parents[2]
AERA_ROOT = LAB_ROOT.parent

#: Canonical env var -> accepted aliases. The deployment .env uses the vendor
#: product names; the spec uses the API-vendor names. Both are honoured.
_ALIASES: dict[str, tuple[str, ...]] = {
    "XAI_API_KEY": ("GROK_API_KEY",),
    "XAI_BASE_URL": ("GROK_BASE_URL",),
    "XAI_MODEL": ("GROK_MODEL",),
    "ANTHROPIC_API_KEY": ("CLAUDE_API_KEY",),
    "ANTHROPIC_BASE_URL": ("CLAUDE_BASE_URL",),
    "ANTHROPIC_MODEL": ("CLAUDE_MODEL",),
}

#: Prefixes the lab may import from the AEra .env. Deliberately excludes every
#: AEra secret (AGENT_JWT_SECRET, OAUTH_JWT_SECRET, TOKEN_SECRET, ...) -- the
#: attacker model requires that the lab cannot forge a server-signed JWT.
_IMPORTABLE = ("DEEPSEEK_", "XAI_", "GROK_", "ANTHROPIC_", "CLAUDE_")


def _first(*names: str, default: str = "") -> str:
    for n in names:
        v = os.getenv(n)
        if v:
            return v
    return default


def _env(canonical: str, default: str = "") -> str:
    return _first(canonical, *_ALIASES.get(canonical, ()), default=default)


def load_env() -> None:
    """Load the lab .env, then fall back to the AEra .env for provider keys only."""
    lab_env = LAB_ROOT / ".env"
    if lab_env.exists():
        load_dotenv(lab_env, override=False)
    parent_env = AERA_ROOT / ".env"
    if not parent_env.exists():
        return
    for line in parent_env.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k = k.strip()
        if k.startswith(_IMPORTABLE) and not os.getenv(k):
            os.environ[k] = v.strip().strip('"').strip("'")


@dataclass(frozen=True, repr=False)
class Settings:
    aera_base_url: str
    # DeepSeek
    deepseek_api_key: str
    deepseek_base_url: str
    deepseek_model: str
    # xAI / Grok
    xai_api_key: str = ""
    xai_base_url: str = ""
    xai_model: str = ""
    # Anthropic / Claude
    anthropic_api_key: str = ""
    anthropic_base_url: str = ""
    anthropic_model: str = ""
    # lab
    provider: str = "mock"
    http_timeout: float = 60.0
    #: LLM calls are far slower than AEra calls, so they get their own budget
    provider_timeout: float = 600.0

    def __repr__(self) -> str:
        # Never render an API key -- covers print(), logging and f-strings.
        return f"Settings({self.redacted()})"

    __str__ = __repr__

    @property
    def deepseek_available(self) -> bool:
        return bool(self.deepseek_api_key)

    @property
    def grok_available(self) -> bool:
        return bool(self.xai_api_key)

    @property
    def claude_available(self) -> bool:
        return bool(self.anthropic_api_key)

    def redacted(self) -> dict:
        """Safe-to-log view: key PRESENCE only, never a value or prefix."""
        def mark(v: str) -> str:
            return "<present>" if v else "<absent>"
        return {
            "aera_base_url": self.aera_base_url,
            "deepseek": {"base_url": self.deepseek_base_url or "<default>",
                         "model": self.deepseek_model or "<default>",
                         "api_key": mark(self.deepseek_api_key)},
            "grok": {"base_url": self.xai_base_url or "<default>",
                     "model": self.xai_model or "<default>",
                     "api_key": mark(self.xai_api_key)},
            "claude": {"base_url": self.anthropic_base_url or "<default>",
                       "model": self.anthropic_model or "<default>",
                       "api_key": mark(self.anthropic_api_key)},
        }


def get_settings() -> Settings:
    load_env()
    return Settings(
        aera_base_url=_env("AERA_BASE_URL", "https://aeralogin.com").rstrip("/"),
        deepseek_api_key=_env("DEEPSEEK_API_KEY"),
        deepseek_base_url=_env("DEEPSEEK_BASE_URL").rstrip("/"),
        deepseek_model=_env("DEEPSEEK_MODEL"),
        xai_api_key=_env("XAI_API_KEY"),
        xai_base_url=_env("XAI_BASE_URL").rstrip("/"),
        xai_model=_env("XAI_MODEL"),
        anthropic_api_key=_env("ANTHROPIC_API_KEY"),
        anthropic_base_url=_env("ANTHROPIC_BASE_URL").rstrip("/"),
        anthropic_model=_env("ANTHROPIC_MODEL"),
        provider=_env("LAB_PROVIDER", "mock"),
        http_timeout=float(_env("LAB_HTTP_TIMEOUT", "60")),
        provider_timeout=float(_env("LAB_PROVIDER_TIMEOUT", "600")),
    )
