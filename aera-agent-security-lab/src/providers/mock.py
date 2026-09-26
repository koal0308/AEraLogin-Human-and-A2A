"""Deterministic mock provider for offline phases (1-4)."""
from __future__ import annotations

from typing import Optional

from .base import LLMError, LLMProvider, LLMResult


class MockProvider(LLMProvider):
    name = "mock"

    def __init__(self, *, reply: str = "MOCK-ANSWER", fail: bool = False) -> None:
        self.reply = reply
        self.fail = fail
        self.calls: list[str] = []

    def generate(self, prompt: str, *, system: Optional[str] = None) -> LLMResult:
        self.calls.append(prompt)
        if self.fail:
            raise LLMError("mock provider failure")
        return LLMResult(text=f"{self.reply}: {prompt[:80]}", model="mock-1",
                         provider=self.name)
