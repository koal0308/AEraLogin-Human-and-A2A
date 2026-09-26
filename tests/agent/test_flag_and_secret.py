"""Verify AGENT_LAYER_ENABLED semantics + secret isolation."""
from __future__ import annotations

import importlib
import os

import pytest


def test_flag_default_off(monkeypatch):
    monkeypatch.delenv("AGENT_LAYER_ENABLED", raising=False)
    import agent as _a
    importlib.reload(_a)
    assert _a.is_enabled() is False


def test_flag_on(monkeypatch):
    monkeypatch.setenv("AGENT_LAYER_ENABLED", "true")
    import agent as _a
    importlib.reload(_a)
    assert _a.is_enabled() is True


def test_secret_fail_fast_on_short(monkeypatch):
    monkeypatch.setenv("AGENT_JWT_SECRET", "short")
    from agent import tokens
    with pytest.raises(RuntimeError):
        tokens.get_secret()


def test_secret_fail_fast_on_collision(monkeypatch):
    monkeypatch.setenv("AGENT_JWT_SECRET", "x" * 64)
    monkeypatch.setenv("OAUTH_JWT_SECRET", "x" * 64)
    from agent import tokens
    with pytest.raises(RuntimeError):
        tokens.get_secret()
