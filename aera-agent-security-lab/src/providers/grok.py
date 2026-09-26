"""xAI Grok provider (OpenAI-compatible chat API).

The xAI API key is never logged, never placed in an A2A payload and never sent
to AEraLogIn.
"""
from __future__ import annotations

from .openai_compatible import OpenAICompatibleProvider


class GrokProvider(OpenAICompatibleProvider):
    name = "grok"
    #: official xAI endpoint; overridable via XAI_BASE_URL
    default_base_url = "https://api.x.ai/v1"
    #: overridable via XAI_MODEL -- never pin a model that may be retired
    default_model = "grok-4.6"
