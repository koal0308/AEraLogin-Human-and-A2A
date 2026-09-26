"""Anthropic Claude provider.

Anthropic uses a different wire format from the OpenAI-compatible backends:
`POST {base_url}/v1/messages`, header `x-api-key` (not a bearer), a mandatory
`anthropic-version`, a required `max_tokens`, and the system prompt as a
top-level field rather than a message role.

The Anthropic API key is never logged, never placed in an A2A payload and never
sent to AEraLogIn.
"""
from __future__ import annotations

from typing import Optional

import httpx

from .base import LLMError, LLMProvider, LLMResult
from .secret import Secret


class ClaudeProvider(LLMProvider):
    name = "claude"
    default_base_url = "https://api.anthropic.com"
    #: overridable via ANTHROPIC_MODEL -- never pin a model that may be retired
    default_model = "claude-sonnet-5"
    api_version = "2023-06-01"

    def __init__(self, api_key: str, *, base_url: Optional[str] = None,
                 model: Optional[str] = None, timeout: float = 120.0,
                 max_tokens: int = 8192, extended_thinking: bool = False,
                 client: Optional[httpx.Client] = None) -> None:
        if not api_key:
            raise LLMError("claude: ANTHROPIC_API_KEY is not configured")
        self.__api_key = Secret(api_key)
        self.base_url = (base_url or self.default_base_url).rstrip("/")
        self.model = model or self.default_model
        self.timeout = timeout
        self.max_tokens = max_tokens
        # Current Claude models emit an extended-thinking block by default.
        # On long review prompts that block can consume the ENTIRE token budget,
        # leaving no text block at all (observed live: stop_reason=max_tokens,
        # blocks=['thinking']). A test harness needs a deterministic answer, so
        # thinking is disabled by default and can be re-enabled explicitly.
        self.extended_thinking = extended_thinking
        self._client = client

    def __repr__(self) -> str:
        return f"<ClaudeProvider model={self.model} key=<redacted>>"

    __str__ = __repr__

    def generate(self, prompt: str, *, system: Optional[str] = None) -> LLMResult:
        body: dict = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            body["system"] = system
        if not self.extended_thinking:
            body["thinking"] = {"type": "disabled"}

        client = self._client or httpx.Client(timeout=self.timeout)
        try:
            r = client.post(
                f"{self.base_url}/v1/messages",
                headers={"x-api-key": self.__api_key.reveal(),
                         "anthropic-version": self.api_version,
                         "Content-Type": "application/json"},
                json=body,
            )
        except httpx.HTTPError as e:
            raise LLMError(f"claude transport error: {type(e).__name__}") from None
        finally:
            if self._client is None:
                client.close()

        if r.status_code != 200:
            raise LLMError(f"claude HTTP {r.status_code}: {r.text[:300]}")
        try:
            data = r.json()
            blocks = data["content"]
        except Exception:
            raise LLMError("claude: unexpected response shape") from None
        # Responses may begin with a `thinking` block; only `text` blocks carry
        # the answer. If the token budget is consumed before any text is
        # emitted, report WHY rather than a bare "empty response".
        text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
        if not text:
            kinds = [b.get("type") for b in blocks]
            stop = data.get("stop_reason")
            raise LLMError(
                f"claude: no text block (stop_reason={stop}, blocks={kinds}, "
                f"max_tokens={self.max_tokens})"
            )
        return LLMResult(text=text, model=self.model, provider=self.name)
