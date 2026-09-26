"""Regression tests: authentication secrets must fail closed.

Guards the fix that removed the predictable fallbacks:
  - TOKEN_SECRET previously defaulted to a hardcoded production string
  - OAUTH_JWT_SECRET was previously derived from TOKEN_SECRET

None of these may ever come back. No secret values are printed.
"""
from __future__ import annotations

import pytest


def _loader(server_module):
    return server_module._require_auth_secret


def test_missing_secret_aborts(server_module, monkeypatch):
    monkeypatch.delenv("SOME_AUTH_SECRET", raising=False)
    with pytest.raises(RuntimeError) as exc:
        _loader(server_module)("SOME_AUTH_SECRET")
    msg = str(exc.value)
    assert "Missing required SOME_AUTH_SECRET" in msg


def test_known_placeholder_rejected(server_module, monkeypatch):
    for bad in ("aera-secret-key-change-in-production",
                "change-me-in-production", "changeme", "secret"):
        monkeypatch.setenv("SOME_AUTH_SECRET", bad)
        with pytest.raises(RuntimeError) as exc:
            _loader(server_module)("SOME_AUTH_SECRET")
        assert "Insecure" in str(exc.value)


def test_short_secret_rejected(server_module, monkeypatch):
    monkeypatch.setenv("SOME_AUTH_SECRET", "x" * 31)
    with pytest.raises(RuntimeError) as exc:
        _loader(server_module)("SOME_AUTH_SECRET")
    assert "at least" in str(exc.value)


def test_valid_secret_accepted(server_module, monkeypatch):
    monkeypatch.setenv("SOME_AUTH_SECRET", "y" * 48)
    assert _loader(server_module)("SOME_AUTH_SECRET") == "y" * 48


def test_error_messages_never_leak_the_value(server_module, monkeypatch):
    marker = "SUPER-SECRET-VALUE-" + "z" * 20
    monkeypatch.setenv("SOME_AUTH_SECRET", marker[:31])  # too short -> raises
    with pytest.raises(RuntimeError) as exc:
        _loader(server_module)("SOME_AUTH_SECRET")
    assert marker[:31] not in str(exc.value)


def test_no_hardcoded_fallback_in_source():
    """The removed defaults must not reappear anywhere in server.py."""
    with open("server.py", encoding="utf-8") as fh:
        src = fh.read()
    assert 'os.getenv("TOKEN_SECRET", "aera-secret-key-change-in-production")' not in src
    assert 'TOKEN_SECRET + "-oauth"' not in src
    assert 'TOKEN_SECRET = _require_auth_secret("TOKEN_SECRET")' in src
    assert 'OAUTH_JWT_SECRET = _require_auth_secret("OAUTH_JWT_SECRET")' in src


def test_three_secrets_are_independent(server_module):
    """TOKEN_SECRET, OAUTH_JWT_SECRET and AGENT_JWT_SECRET must all differ."""
    import os
    token = server_module.TOKEN_SECRET
    oauth = server_module.OAUTH_JWT_SECRET
    agent = os.getenv("AGENT_JWT_SECRET", "")
    assert token != oauth
    if agent:
        assert agent != token
        assert agent != oauth
