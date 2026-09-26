"""PHASE 1 -- configuration and secret-hygiene guards."""
from __future__ import annotations

from src.config.settings import Settings
from src.providers.secret import Secret

SECRET = "sk-CONFIG-LEAK-CANARY"


def _settings() -> Settings:
    return Settings(aera_base_url="https://aeralogin.com", deepseek_api_key=SECRET,
                    deepseek_base_url="https://api.deepseek.com",
                    deepseek_model="deepseek-chat", provider="mock", http_timeout=60.0)


def test_settings_repr_and_str_redact_the_key():
    s = _settings()
    assert SECRET not in repr(s)
    assert SECRET not in str(s)
    assert SECRET not in f"{s}"


def test_redacted_view_reports_presence_only():
    d = _settings().redacted()
    assert d["deepseek"]["api_key"] == "<present>"
    assert d["grok"]["api_key"] == "<absent>"
    assert d["claude"]["api_key"] == "<absent>"
    assert SECRET not in str(d)


def test_deepseek_available_flag():
    assert _settings().deepseek_available
    assert not Settings(aera_base_url="u", deepseek_api_key="",
                        deepseek_base_url="b",
                        deepseek_model="m").deepseek_available


def test_secret_wrapper_redacts_everywhere():
    s = Secret(SECRET)
    assert repr(s) == "<redacted>" and str(s) == "<redacted>" and f"{s}" == "<redacted>"
    assert SECRET not in str({"k": s})
    assert s.reveal() == SECRET and len(s) == len(SECRET) and bool(s)
