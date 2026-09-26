"""LLM provider access for the runtime.

TWO RULES, BOTH STRUCTURAL
--------------------------
1. **The provider is a tool, never an identity.** Swapping Grok for DeepSeek
   changes which model writes the words. It does not change `agent_id`,
   `key_id` or the keypair — those live in the Identity Layer and this module
   cannot reach them.

2. **Provider credentials never travel to AEra.** They are read from the
   runtime's own environment and used only to call the provider. Nothing in
   this module returns, logs or serialises a key, and `describe()` reports only
   the provider *name*.

The provider abstraction from the security lab is reused rather than
reinvented: it already has a stable `LLMProvider.generate()` contract and
working Grok/DeepSeek/Claude/mock backends that the multi-model work exercised.
Duplicating it would have created two provider layers that could drift apart.

ERROR SEPARATION (§14)
----------------------
A provider outage is an operational problem. An authentication failure is a
security event. Conflating them leads to exactly the wrong reaction — retrying
a revoked identity, or paging someone because an API was slow. `ProviderFailure`
is therefore a distinct type that never inherits from an identity or transport
error, and the runtime maps it to DEGRADED rather than REVOKED.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

#: The lab package is a sibling of the app root and is not an installed module.
_LAB_SRC = Path(__file__).resolve().parent.parent / "aera-agent-security-lab"
if str(_LAB_SRC) not in sys.path:
    sys.path.insert(0, str(_LAB_SRC))


class ProviderFailure(Exception):
    """The model could not be reached, timed out, or returned nothing usable.

    Deliberately NOT a subclass of any identity or transport error.
    """

    def __init__(self, message: str, *, provider: str = "", kind: str = "error") -> None:
        super().__init__(message)
        self.provider = provider
        #: one of: unavailable | timeout | auth | invalid_response | config
        self.kind = kind


@dataclass(frozen=True)
class Completion:
    """What the runtime got back. `text` is UNTRUSTED model output."""

    text: str
    provider: str
    model: str
    latency_ms: float

    def safe_dict(self) -> dict[str, Any]:
        """Metadata only — never the generated text, which may be confidential."""
        return {
            "provider": self.provider,
            "model": self.model,
            "latency_ms": round(self.latency_ms, 1),
            "chars": len(self.text),
        }


class ProviderAdapter:
    """Wraps any `LLMProvider` behind a small, stable runtime-facing surface."""

    def __init__(self, name: str, provider: Any, *, model: str = "") -> None:
        self.name = name
        self._provider = provider
        self.model = model or getattr(provider, "model", "") or "default"

    def __repr__(self) -> str:
        # Never expose the underlying client, which holds the API key.
        return f"<ProviderAdapter name={self.name} model={self.model}>"

    def generate(self, prompt: str, *, system: Optional[str] = None) -> Completion:
        import time

        started = time.perf_counter()
        try:
            result = self._provider.generate(prompt, system=system)
        except Exception as exc:
            raise ProviderFailure(_classify_message(exc), provider=self.name,
                                  kind=_classify_kind(exc)) from exc

        elapsed = (time.perf_counter() - started) * 1000.0
        text = getattr(result, "text", None)
        if not isinstance(text, str) or not text.strip():
            raise ProviderFailure("model returned an empty response",
                                  provider=self.name, kind="invalid_response")
        return Completion(text=text, provider=self.name,
                          model=getattr(result, "model", self.model) or self.model,
                          latency_ms=elapsed)

    def describe(self) -> dict[str, str]:
        return {"provider": self.name, "model": self.model}


def _classify_kind(exc: Exception) -> str:
    text = f"{type(exc).__name__}: {exc}".lower()
    if "timeout" in text or "timed out" in text:
        return "timeout"
    if "401" in text or "403" in text or "unauthor" in text or "api key" in text:
        return "auth"
    if "connect" in text or "unavailable" in text or "502" in text or "503" in text:
        return "unavailable"
    return "error"


def _classify_message(exc: Exception) -> str:
    """A safe summary. Provider errors can echo back the API key we sent."""
    return f"provider call failed ({type(exc).__name__})"


#: AEra's own .env does not use the canonical vendor variable names, and it
#: keeps two keys per vendor (a primary and a spare). The lab's settings layer
#: only knows the canonical single-key names, and that layer is deliberately
#: not modified from here. So this is the one place that translates, in order
#: of preference, from AEra's naming to the canonical one.
CREDENTIAL_ALIASES: dict[str, tuple[str, ...]] = {
    "DEEPSEEK_API_KEY": ("DEEPSEEK_API_KEY", "DEEPSEEK1_API_KEY", "DEEPSEEK2_API_KEY"),
    "XAI_API_KEY": ("XAI_API_KEY", "GROK_API_KEY", "GROK1_API_KEY", "GROK2_API_KEY"),
    "ANTHROPIC_API_KEY": ("ANTHROPIC_API_KEY", "CLAUDE_API_KEY",
                          "ANTHROPIC1_API_KEY", "CLAUDE1_API_KEY"),
}


def resolve_provider_credentials(env: Optional[dict] = None) -> list[str]:
    """Populate the canonical credential variables from AEra's aliases.

    Returns the list of canonical variable *names* that ended up set -- names
    only, never values, so the result is safe to log.

    This mutates only the current process's environment. It does not write to
    `.env`, and it never overwrites a canonical variable that is already set,
    so an operator can still override a specific provider explicitly.
    """
    target = os.environ if env is None else env
    resolved: list[str] = []
    for canonical, candidates in CREDENTIAL_ALIASES.items():
        if target.get(canonical, "").strip():
            resolved.append(canonical)
            continue
        for candidate in candidates:
            value = target.get(candidate, "").strip()
            if value:
                target[canonical] = value
                resolved.append(canonical)
                break
    return resolved


def build_adapter(name: str, *, model: Optional[str] = None) -> ProviderAdapter:
    """Construct a provider by name using the lab's registry and settings.

    Credentials come from the runtime's own environment. If a provider is not
    configured, this fails at startup with an actionable message rather than at
    the first inbound request.
    """
    key = (name or "").strip().lower()
    try:
        from src.config.settings import get_settings
        from src.providers.registry import ProviderConfigError, build_provider
    except ImportError as exc:  # pragma: no cover - environment problem
        raise ProviderFailure(f"provider layer unavailable: {exc}",
                              provider=key, kind="config") from exc

    resolve_provider_credentials()
    try:
        provider = build_provider(key, get_settings())
    except ProviderConfigError as exc:
        raise ProviderFailure(str(exc), provider=key, kind="config") from exc
    return ProviderAdapter(key, provider, model=model or "")
