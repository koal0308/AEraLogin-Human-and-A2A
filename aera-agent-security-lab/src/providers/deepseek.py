"""DeepSeek provider (OpenAI-compatible chat API).

Behaviour is unchanged from the original security-lab implementation; the HTTP
transport is now shared with `GrokProvider` via `OpenAICompatibleProvider`.
The DeepSeek API key is never logged, never placed in an A2A payload and never
sent to AEraLogIn.
"""
from __future__ import annotations

from .openai_compatible import OpenAICompatibleProvider


class DeepSeekProvider(OpenAICompatibleProvider):
    name = "deepseek"
    default_base_url = "https://api.deepseek.com"
    default_model = "deepseek-chat"
