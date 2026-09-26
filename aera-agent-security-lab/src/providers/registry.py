"""Provider registry.

Maps a provider name to a constructed `LLMProvider`. The Agent Runtime depends
only on this registry and on `LLMProvider.generate` -- never on
provider-specific authentication details.
"""
from __future__ import annotations

from typing import Callable

from ..config.settings import Settings
from .base import LLMProvider
from .claude import ClaudeProvider
from .deepseek import DeepSeekProvider
from .grok import GrokProvider
from .mock import MockProvider


class ProviderConfigError(Exception):
    """Unknown provider, or a known provider without credentials."""


#: canonical provider names, in stable order for help output
PROVIDER_NAMES = ("grok", "deepseek", "claude", "mock")


def _grok(s: Settings) -> LLMProvider:
    return GrokProvider(s.xai_api_key, base_url=s.xai_base_url or None,
                        model=s.xai_model or None, timeout=s.provider_timeout)


def _deepseek(s: Settings) -> LLMProvider:
    return DeepSeekProvider(s.deepseek_api_key, base_url=s.deepseek_base_url or None,
                            model=s.deepseek_model or None, timeout=s.provider_timeout)


def _claude(s: Settings) -> LLMProvider:
    return ClaudeProvider(s.anthropic_api_key, base_url=s.anthropic_base_url or None,
                          model=s.anthropic_model or None, timeout=s.provider_timeout)


def _mock(s: Settings) -> LLMProvider:
    return MockProvider(reply="MOCK")


_BUILDERS: dict[str, Callable[[Settings], LLMProvider]] = {
    "grok": _grok,
    "deepseek": _deepseek,
    "claude": _claude,
    "mock": _mock,
}

#: which env var each provider needs, for actionable error messages
_KEY_ENV = {"grok": "XAI_API_KEY (or GROK_API_KEY)",
            "deepseek": "DEEPSEEK_API_KEY",
            "claude": "ANTHROPIC_API_KEY (or CLAUDE_API_KEY)"}


def build_provider(name: str, settings: Settings) -> LLMProvider:
    key = (name or "").strip().lower()
    if key not in _BUILDERS:
        raise ProviderConfigError(
            f"unknown provider {name!r}; available: {', '.join(PROVIDER_NAMES)}"
        )
    try:
        return _BUILDERS[key](settings)
    except Exception as e:
        env = _KEY_ENV.get(key)
        hint = f" -- set {env} in .env" if env else ""
        raise ProviderConfigError(f"cannot initialise provider {key!r}: {e}{hint}") from None


def available_providers(settings: Settings) -> dict[str, bool]:
    """Which providers currently have credentials. Never reveals a key."""
    return {
        "grok": bool(settings.xai_api_key),
        "deepseek": bool(settings.deepseek_api_key),
        "claude": bool(settings.anthropic_api_key),
        "mock": True,
    }
