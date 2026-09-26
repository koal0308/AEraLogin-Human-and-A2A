"""Shared implementation for OpenAI-compatible chat APIs (DeepSeek, xAI/Grok).

Both expose `POST {base_url}/chat/completions` with a bearer token and the same
request/response shape, so the transport is factored out here. The API key is
held in a `Secret`, so it cannot leak through `repr`, `vars()`, f-strings,
logging or pytest assertion output.
"""
from __future__ import annotations

from typing import Optional

import httpx

from .base import LLMError, LLMProvider, LLMResult
from .secret import Secret


class OpenAICompatibleProvider(LLMProvider):
    """Base class. Subclasses only set `name` and a default base URL/model."""

    name = "openai-compatible"
    default_base_url = ""
    default_model = ""
    #: some backends require an explicit token budget
    max_tokens: Optional[int] = None

    def __init__(self, api_key: str, *, base_url: Optional[str] = None,
                 model: Optional[str] = None, timeout: float = 120.0,
                 client: Optional[httpx.Client] = None) -> None:
        if not api_key:
            raise LLMError(f"{self.name}: API key is not configured")
        self.__api_key = Secret(api_key)
        self.base_url = (base_url or self.default_base_url).rstrip("/")
        self.model = model or self.default_model
        self.timeout = timeout
        self._client = client

    def __repr__(self) -> str:
        return f"<{type(self).__name__} model={self.model} key=<redacted>>"

    __str__ = __repr__

    def _payload(self, prompt: str, system: Optional[str]) -> dict:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        body: dict = {"model": self.model, "messages": messages, "stream": False}
        if self.max_tokens:
            body["max_tokens"] = self.max_tokens
        return body

    def generate(self, prompt: str, *, system: Optional[str] = None) -> LLMResult:
        client = self._client or httpx.Client(timeout=self.timeout)
        try:
            r = client.post(
                f"{self.base_url}/chat/completions",
                headers={"Authorization": f"Bearer {self.__api_key.reveal()}",
                         "Content-Type": "application/json"},
                json=self._payload(prompt, system),
            )
        except httpx.HTTPError as e:
            # Transport failures (timeout, DNS, connection reset) are reported
            # WITHOUT echoing the request, so the key cannot leak.
            raise LLMError(f"{self.name} transport error: {type(e).__name__}") from None
        finally:
            if self._client is None:
                client.close()

        if r.status_code != 200:
            # Only the response body is echoed -- never the request headers.
            raise LLMError(f"{self.name} HTTP {r.status_code}: {r.text[:300]}")
        try:
            text = r.json()["choices"][0]["message"]["content"]
        except Exception:
            raise LLMError(f"{self.name}: unexpected response shape") from None
        if not isinstance(text, str):
            raise LLMError(f"{self.name}: unexpected content type") from None
        return LLMResult(text=text, model=self.model, provider=self.name)
