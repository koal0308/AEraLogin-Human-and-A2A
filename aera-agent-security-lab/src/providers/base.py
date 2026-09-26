"""LLM provider abstraction. The provider is a tool, NEVER an identity."""
from __future__ import annotations

import abc
from dataclasses import dataclass


@dataclass(frozen=True)
class LLMResult:
    text: str
    model: str
    provider: str


class LLMError(RuntimeError):
    pass


class LLMProvider(abc.ABC):
    """Contract for every model backend (DeepSeek today, OpenAI/Ollama later)."""

    name: str = "abstract"

    @abc.abstractmethod
    def generate(self, prompt: str, *, system: str | None = None) -> LLMResult:
        ...

    def __repr__(self) -> str:
        return f"<{type(self).__name__} name={self.name}>"
