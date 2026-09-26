"""MODEL-01 .. MODEL-09, MODEL-17 .. MODEL-20 -- multi-provider unit tests.

These run offline. The live hop tests (MODEL-10..16) are in
`tests/integration/test_network_live.py`; MODEL-21..23 are regression checks.
"""
from __future__ import annotations

import logging

import httpx
import pytest

from src.config.settings import Settings
from src.providers.base import LLMError, LLMProvider
from src.providers.claude import ClaudeProvider
from src.providers.deepseek import DeepSeekProvider
from src.providers.grok import GrokProvider
from src.providers.mock import MockProvider
from src.providers.registry import (
    PROVIDER_NAMES,
    ProviderConfigError,
    available_providers,
    build_provider,
)

XAI_KEY = "xai-CANARY-MUST-NOT-LEAK"
DS_KEY = "sk-DEEPSEEK-CANARY-MUST-NOT-LEAK"
ANTHROPIC_KEY = "sk-ant-CANARY-MUST-NOT-LEAK"
ALL_KEYS = (XAI_KEY, DS_KEY, ANTHROPIC_KEY)


def settings(**over) -> Settings:
    base = dict(
        aera_base_url="https://aeralogin.com",
        deepseek_api_key=DS_KEY, deepseek_base_url="", deepseek_model="",
        xai_api_key=XAI_KEY, xai_base_url="", xai_model="",
        anthropic_api_key=ANTHROPIC_KEY, anthropic_base_url="", anthropic_model="",
        provider="mock", http_timeout=60.0, provider_timeout=600.0,
    )
    base.update(over)
    return Settings(**base)


def openai_client(capture: dict, *, status=200, body=None) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        capture["auth"] = request.headers.get("authorization")
        capture["url"] = str(request.url)
        capture["body"] = request.content.decode()
        return httpx.Response(status, json=body if body is not None else {
            "choices": [{"message": {"content": "ANSWER"}}]})
    return httpx.Client(transport=httpx.MockTransport(handler))


def claude_client(capture: dict, *, status=200, body=None) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        capture["x-api-key"] = request.headers.get("x-api-key")
        capture["version"] = request.headers.get("anthropic-version")
        capture["url"] = str(request.url)
        capture["body"] = request.content.decode()
        return httpx.Response(status, json=body if body is not None else {
            "content": [{"type": "text", "text": "ANSWER"}], "stop_reason": "end_turn"})
    return httpx.Client(transport=httpx.MockTransport(handler))


# --- MODEL-01: Grok provider works ---------------------------------------- #
def test_model_01_grok_provider_works():
    cap: dict = {}
    p = GrokProvider(XAI_KEY, model="grok-4.6", client=openai_client(cap))
    r = p.generate("hello", system="sys")
    assert r.text == "ANSWER" and r.provider == "grok" and r.model == "grok-4.6"
    assert cap["url"] == "https://api.x.ai/v1/chat/completions"
    assert cap["auth"] == f"Bearer {XAI_KEY}"


# --- MODEL-02: DeepSeek provider works ------------------------------------ #
def test_model_02_deepseek_provider_works():
    cap: dict = {}
    p = DeepSeekProvider(DS_KEY, client=openai_client(cap))
    r = p.generate("hello")
    assert r.text == "ANSWER" and r.provider == "deepseek"
    assert cap["url"] == "https://api.deepseek.com/chat/completions"


# --- MODEL-03: Claude provider works -------------------------------------- #
def test_model_03_claude_provider_works():
    cap: dict = {}
    p = ClaudeProvider(ANTHROPIC_KEY, model="claude-sonnet-5", client=claude_client(cap))
    r = p.generate("hello", system="sys")
    assert r.text == "ANSWER" and r.provider == "claude"
    assert cap["url"] == "https://api.anthropic.com/v1/messages"
    assert cap["x-api-key"] == ANTHROPIC_KEY and cap["version"] == "2023-06-01"
    assert '"system"' in cap["body"]


def test_model_03b_claude_disables_extended_thinking_by_default():
    """Live finding: a long prompt consumed the whole budget in a `thinking`
    block, leaving no text. Deterministic harness => thinking disabled."""
    cap: dict = {}
    ClaudeProvider(ANTHROPIC_KEY, client=claude_client(cap)).generate("x")
    assert '"thinking"' in cap["body"] and '"disabled"' in cap["body"]

    cap2: dict = {}
    ClaudeProvider(ANTHROPIC_KEY, extended_thinking=True,
                   client=claude_client(cap2)).generate("x")
    assert '"thinking"' not in cap2["body"]


def test_model_03c_claude_reports_why_no_text_was_returned():
    cap: dict = {}
    p = ClaudeProvider(ANTHROPIC_KEY, client=claude_client(
        cap, body={"content": [{"type": "thinking", "thinking": "..."}],
                   "stop_reason": "max_tokens"}))
    with pytest.raises(LLMError) as e:
        p.generate("x")
    assert "max_tokens" in str(e.value) and "thinking" in str(e.value)


# --- MODEL-04/05/06: failure handling ------------------------------------- #
@pytest.mark.parametrize("status", [400, 401, 402, 429, 500])
@pytest.mark.parametrize("kind", ["grok", "deepseek", "claude"])
def test_model_04_05_06_http_failures_raise_llmerror(kind, status):
    cap: dict = {}
    if kind == "claude":
        p = ClaudeProvider(ANTHROPIC_KEY, client=claude_client(cap, status=status,
                                                               body={"error": "x"}))
    elif kind == "grok":
        p = GrokProvider(XAI_KEY, client=openai_client(cap, status=status,
                                                       body={"error": "x"}))
    else:
        p = DeepSeekProvider(DS_KEY, client=openai_client(cap, status=status,
                                                          body={"error": "x"}))
    with pytest.raises(LLMError) as e:
        p.generate("hello")
    assert str(status) in str(e.value)
    for k in ALL_KEYS:
        assert k not in str(e.value)


@pytest.mark.parametrize("kind", ["grok", "deepseek", "claude"])
def test_model_04_05_06_transport_failures_raise_llmerror(kind):
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timeout", request=request)
    client = httpx.Client(transport=httpx.MockTransport(boom))
    p = {"grok": GrokProvider(XAI_KEY, client=client),
         "deepseek": DeepSeekProvider(DS_KEY, client=client),
         "claude": ClaudeProvider(ANTHROPIC_KEY, client=client)}[kind]
    with pytest.raises(LLMError) as e:
        p.generate("hello")
    assert "ReadTimeout" in str(e.value)
    for k in ALL_KEYS:
        assert k not in str(e.value)


@pytest.mark.parametrize("kind", ["grok", "deepseek", "claude"])
def test_model_04_05_06_unexpected_shape_raises_llmerror(kind):
    cap: dict = {}
    if kind == "claude":
        p = ClaudeProvider(ANTHROPIC_KEY, client=claude_client(cap, body={"nope": 1}))
    elif kind == "grok":
        p = GrokProvider(XAI_KEY, client=openai_client(cap, body={"nope": 1}))
    else:
        p = DeepSeekProvider(DS_KEY, client=openai_client(cap, body={"nope": 1}))
    with pytest.raises(LLMError):
        p.generate("hello")


# --- registry -------------------------------------------------------------- #
def test_registry_builds_all_three_providers():
    s = settings()
    assert isinstance(build_provider("grok", s), GrokProvider)
    assert isinstance(build_provider("deepseek", s), DeepSeekProvider)
    assert isinstance(build_provider("claude", s), ClaudeProvider)
    assert isinstance(build_provider("mock", s), MockProvider)


@pytest.mark.parametrize("bad", ["openai", "", "gpt-4", "GROKK"])
def test_registry_rejects_unknown_provider_cleanly(bad):
    with pytest.raises(ProviderConfigError) as e:
        build_provider(bad, settings())
    assert "unknown provider" in str(e.value)


def test_registry_reports_missing_credentials_with_a_hint():
    with pytest.raises(ProviderConfigError) as e:
        build_provider("grok", settings(xai_api_key=""))
    assert "XAI_API_KEY" in str(e.value)


def test_registry_is_case_insensitive_and_trims():
    assert isinstance(build_provider("  Grok ", settings()), GrokProvider)


def test_available_providers_never_reveals_a_key():
    a = available_providers(settings())
    assert a == {"grok": True, "deepseek": True, "claude": True, "mock": True}
    assert not available_providers(settings(xai_api_key=""))["grok"]
    for k in ALL_KEYS:
        assert k not in str(a)


# --- MODEL-17: OpenAI is NOT required anywhere ---------------------------- #
def test_model_17_openai_is_not_required():
    assert "openai" not in PROVIDER_NAMES
    with pytest.raises(ProviderConfigError):
        build_provider("openai", settings())

    # The `openai` SDK must not be imported anywhere in the lab. "OpenAI-compatible"
    # describes a wire format and is explicitly allowed.
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parents[2]
    bad_import = re.compile(r"^\s*(?:import\s+openai|from\s+openai(?:\.|\s+import))")
    offenders = [
        f"{f.relative_to(root)}: {line.strip()}"
        for f in root.rglob("*.py")
        for line in f.read_text(encoding="utf-8").splitlines()
        if bad_import.match(line)
    ]
    assert not offenders, offenders

    for name in ("requirements.txt", "requirements-dev.txt", "pyproject.toml"):
        f = root / name
        if f.exists():
            assert "openai" not in f.read_text(encoding="utf-8").lower(), name


# --- MODEL-18/19/20: secret isolation ------------------------------------- #
@pytest.mark.parametrize("build,key", [
    (lambda c: GrokProvider(XAI_KEY, client=c), XAI_KEY),
    (lambda c: DeepSeekProvider(DS_KEY, client=c), DS_KEY),
])
def test_model_18_openai_style_key_not_exposed(build, key):
    p = build(None)
    assert key not in repr(p) and key not in str(p) and key not in str(vars(p))


def test_model_18_claude_key_not_exposed():
    p = ClaudeProvider(ANTHROPIC_KEY)
    assert ANTHROPIC_KEY not in repr(p)
    assert ANTHROPIC_KEY not in str(p)
    assert ANTHROPIC_KEY not in str(vars(p))


def test_model_18_settings_never_render_any_key():
    s = settings()
    for k in ALL_KEYS:
        assert k not in repr(s) and k not in str(s) and k not in str(s.redacted())


@pytest.mark.parametrize("kind", ["grok", "deepseek", "claude"])
def test_model_18_keys_never_reach_the_log(caplog, kind):
    cap: dict = {}
    p = {"grok": lambda: GrokProvider(XAI_KEY, client=openai_client(cap)),
         "deepseek": lambda: DeepSeekProvider(DS_KEY, client=openai_client(cap)),
         "claude": lambda: ClaudeProvider(ANTHROPIC_KEY, client=claude_client(cap))}[kind]()
    with caplog.at_level(logging.DEBUG):
        p.generate("hello")
    for k in ALL_KEYS:
        assert k not in caplog.text


@pytest.mark.parametrize("kind", ["grok", "deepseek", "claude"])
def test_model_18_key_is_sent_only_to_its_own_vendor(kind):
    """MODEL-18: no provider key is ever sent to AEra, and no key is sent to
    another vendor's endpoint."""
    cap: dict = {}
    if kind == "claude":
        ClaudeProvider(ANTHROPIC_KEY, client=claude_client(cap)).generate("x")
        assert "anthropic.com" in cap["url"]
        sent = cap["x-api-key"] + cap["body"]
        assert XAI_KEY not in sent and DS_KEY not in sent
    else:
        p = (GrokProvider(XAI_KEY, client=openai_client(cap)) if kind == "grok"
             else DeepSeekProvider(DS_KEY, client=openai_client(cap)))
        p.generate("x")
        assert "aeralogin.com" not in cap["url"]
        sent = cap["auth"] + cap["body"]
        assert ANTHROPIC_KEY not in sent
        if kind == "grok":
            assert DS_KEY not in sent
        else:
            assert XAI_KEY not in sent


@pytest.mark.parametrize("kind", ["grok", "deepseek", "claude"])
def test_model_19_20_no_jwt_or_private_key_is_sent_to_a_provider(kind):
    """MODEL-19 + MODEL-20: the prompt is the ONLY thing the provider sees."""
    cap: dict = {}
    fake_jwt = "eyJhbGciOiJIUzI1NiJ9.FAKE.SIGNATURE"
    fake_priv = "ed25519-private-key-material"
    if kind == "claude":
        p = ClaudeProvider(ANTHROPIC_KEY, client=claude_client(cap))
    elif kind == "grok":
        p = GrokProvider(XAI_KEY, client=openai_client(cap))
    else:
        p = DeepSeekProvider(DS_KEY, client=openai_client(cap))
    p.generate("analyse this", system="be brief")
    assert fake_jwt not in cap["body"] and fake_priv not in cap["body"]
    assert "Bearer eyJ" not in cap["body"]
    assert "agent_jwt" not in cap["body"] and "private" not in cap["body"].lower()


# --- provider substitutability -------------------------------------------- #
def test_all_providers_implement_the_same_abstraction():
    for p in (GrokProvider(XAI_KEY), DeepSeekProvider(DS_KEY),
              ClaudeProvider(ANTHROPIC_KEY), MockProvider()):
        assert isinstance(p, LLMProvider)
        assert callable(p.generate)


def test_models_are_configurable_and_not_hard_coded():
    s = settings(xai_model="grok-9", deepseek_model="deepseek-x",
                 anthropic_model="claude-future")
    assert build_provider("grok", s).model == "grok-9"
    assert build_provider("deepseek", s).model == "deepseek-x"
    assert build_provider("claude", s).model == "claude-future"


def test_base_urls_are_overridable():
    s = settings(xai_base_url="https://proxy.example/v1",
                 anthropic_base_url="https://proxy.example")
    assert build_provider("grok", s).base_url == "https://proxy.example/v1"
    assert build_provider("claude", s).base_url == "https://proxy.example"
