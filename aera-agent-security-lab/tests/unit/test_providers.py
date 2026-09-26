"""PHASE 3 -- provider abstraction, mocked DeepSeek, and key-leak guards."""
from __future__ import annotations

import logging

import httpx
import pytest

from src.providers.base import LLMError, LLMProvider, LLMResult
from src.providers.deepseek import DeepSeekProvider
from src.providers.mock import MockProvider

SECRET = "sk-THIS-MUST-NEVER-APPEAR-ANYWHERE"


def test_mock_provider_generates():
    p = MockProvider(reply="R")
    r = p.generate("question")
    assert isinstance(r, LLMResult) and r.text.startswith("R:")
    assert p.calls == ["question"]


def test_mock_provider_error_path():
    with pytest.raises(LLMError):
        MockProvider(fail=True).generate("q")


def test_deepseek_requires_a_key():
    with pytest.raises(LLMError):
        DeepSeekProvider("")


def _client(capture: dict, *, status: int = 200, body: dict | None = None) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        capture["auth"] = request.headers.get("authorization")
        capture["url"] = str(request.url)
        capture["body"] = request.content.decode()
        return httpx.Response(status, json=body or {
            "choices": [{"message": {"content": "ANSWER"}}]})
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_deepseek_happy_path_uses_configured_model():
    cap: dict = {}
    p = DeepSeekProvider(SECRET, model="deepseek-chat", client=_client(cap))
    r = p.generate("hello", system="sys")
    assert r.text == "ANSWER" and r.provider == "deepseek" and r.model == "deepseek-chat"
    assert cap["auth"] == f"Bearer {SECRET}"
    assert "deepseek-chat" in cap["body"] and '"role":"system"' in cap["body"].replace(" ", "")


def test_deepseek_http_error_is_wrapped_and_key_free():
    cap: dict = {}
    p = DeepSeekProvider(SECRET, client=_client(cap, status=402, body={"error": "no credit"}))
    with pytest.raises(LLMError) as e:
        p.generate("hello")
    assert SECRET not in str(e.value)


def test_deepseek_unexpected_shape_is_wrapped():
    cap: dict = {}
    p = DeepSeekProvider(SECRET, client=_client(cap, body={"nope": 1}))
    with pytest.raises(LLMError):
        p.generate("hello")


def test_api_key_is_not_exposed_by_repr_str_or_attributes():
    p = DeepSeekProvider(SECRET)
    assert SECRET not in repr(p)
    assert SECRET not in str(p)
    assert SECRET not in str(vars(p))
    assert not hasattr(p, "api_key")


def test_api_key_never_reaches_the_log(caplog):
    cap: dict = {}
    p = DeepSeekProvider(SECRET, client=_client(cap))
    with caplog.at_level(logging.DEBUG):
        p.generate("hello")
    assert SECRET not in caplog.text


def test_provider_is_substitutable():
    assert isinstance(MockProvider(), LLMProvider)
    assert isinstance(DeepSeekProvider(SECRET), LLMProvider)
