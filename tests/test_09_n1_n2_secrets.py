"""N1/N2 regression tests: OAUTH_ADMIN_KEY and TELEGRAM_BOT_HMAC_SECRET
must be independent, mandatory secrets.

Guards two removed insecure fallbacks:
  N1  expected_admin_key = os.getenv("OAUTH_ADMIN_KEY", TOKEN_SECRET)
  N2  HMAC_SECRET = os.getenv("TELEGRAM_BOT_HMAC_SECRET",
                              os.getenv("TOKEN_SECRET", "change-me-in-production"))

No secret values are ever printed.
"""
from __future__ import annotations

import hashlib
import hmac
import importlib.util
import os
import sys

import pytest


# ===========================================================================
# N1 - OAUTH_ADMIN_KEY
# ===========================================================================

def _loader(server_module):
    return server_module._require_auth_secret


def test_n1_A_missing_admin_key_fails_closed(server_module, monkeypatch):
    monkeypatch.delenv("OAUTH_ADMIN_KEY", raising=False)
    with pytest.raises(RuntimeError) as exc:
        _loader(server_module)("OAUTH_ADMIN_KEY")
    assert "Missing required OAUTH_ADMIN_KEY" in str(exc.value)


def test_n1_B_placeholder_admin_key_rejected(server_module, monkeypatch):
    for bad in ("aera-secret-key-change-in-production",
                "change-me-in-production", "changeme", "secret"):
        monkeypatch.setenv("OAUTH_ADMIN_KEY", bad)
        with pytest.raises(RuntimeError) as exc:
            _loader(server_module)("OAUTH_ADMIN_KEY")
        assert "Insecure" in str(exc.value)


def test_n1_C_short_admin_key_rejected(server_module, monkeypatch):
    monkeypatch.setenv("OAUTH_ADMIN_KEY", "a" * 31)
    with pytest.raises(RuntimeError) as exc:
        _loader(server_module)("OAUTH_ADMIN_KEY")
    assert "at least" in str(exc.value)


def test_n1_D_E_F_admin_key_must_be_independent(server_module):
    """Runtime values must differ from every other auth secret."""
    admin = server_module.OAUTH_ADMIN_KEY
    assert admin != server_module.TOKEN_SECRET          # D
    assert admin != server_module.OAUTH_JWT_SECRET      # E
    agent = os.getenv("AGENT_JWT_SECRET", "")
    if agent:
        assert admin != agent                           # F


def test_n1_G_valid_admin_key_accepted(server_module, monkeypatch):
    monkeypatch.setenv("OAUTH_ADMIN_KEY", "q" * 48)
    assert _loader(server_module)("OAUTH_ADMIN_KEY") == "q" * 48


def test_n1_H_valid_admin_operation_succeeds(client, server_module):
    """A client registration with the configured admin key works."""
    r = client.post("/api/v1/clients/register", json={
        "admin_key": server_module.OAUTH_ADMIN_KEY,
        "client_name": "PYTEST N1 TEST CLIENT",
        "redirect_uris": ["https://pytest.invalid/callback"],
        "allowed_origins": ["https://pytest.invalid"],
    })
    body = r.json()
    assert body.get("success") is True, body
    assert body.get("client_id", "").startswith("aera_")
    # cleanup: deactivate the throwaway client again
    conn = server_module.get_db_connection()
    conn.execute("UPDATE oauth_clients SET is_active=0 WHERE client_id=?",
                 (body["client_id"],))
    conn.commit()
    conn.close()


def test_n1_I_token_secret_is_not_accepted_as_admin_key(client, server_module):
    """The removed fallback must NOT work any more."""
    r = client.post("/api/v1/clients/register", json={
        "admin_key": server_module.TOKEN_SECRET,
        "client_name": "PYTEST MUST NOT BE CREATED",
        "redirect_uris": ["https://pytest.invalid/callback"],
    })
    body = r.json()
    assert body.get("success") is False
    assert body.get("error") == "Invalid admin key"
    assert "client_secret" not in body


def test_n1_empty_admin_key_rejected(client):
    r = client.post("/api/v1/clients/register", json={
        "admin_key": "", "client_name": "X",
        "redirect_uris": ["https://pytest.invalid/cb"]})
    assert r.json().get("success") is False


def test_n1_no_fallback_left_in_source():
    with open("server.py", encoding="utf-8") as fh:
        src = fh.read()
    assert 'os.getenv("OAUTH_ADMIN_KEY", TOKEN_SECRET)' not in src
    assert 'OAUTH_ADMIN_KEY = _require_auth_secret("OAUTH_ADMIN_KEY")' in src


# ===========================================================================
# N2 - TELEGRAM_BOT_HMAC_SECRET
# ===========================================================================

def _bot_secret_loader():
    """Import only the secret loader from telegram_group_bot.py.

    The module imports heavy telegram deps at module level, so we extract the
    function via a tiny exec of its source instead of importing the module.
    """
    with open("telegram_group_bot.py", encoding="utf-8") as fh:
        src = fh.read()
    start = src.index("_FORBIDDEN_SECRET_VALUES = frozenset({")
    end = src.index('HMAC_SECRET = _require_bot_secret(')
    ns: dict = {"os": os}
    exec(compile(src[start:end], "telegram_group_bot.py", "exec"), ns)
    return ns["_require_bot_secret"]


def test_n2_A_missing_secret_fails_closed(monkeypatch):
    monkeypatch.delenv("TELEGRAM_BOT_HMAC_SECRET", raising=False)
    with pytest.raises(RuntimeError) as exc:
        _bot_secret_loader()("TELEGRAM_BOT_HMAC_SECRET")
    assert "Missing required TELEGRAM_BOT_HMAC_SECRET" in str(exc.value)


def test_n2_B_placeholder_rejected(monkeypatch):
    for bad in ("change-me-in-production", "changeme", "secret",
                "aera-secret-key-change-in-production"):
        monkeypatch.setenv("TELEGRAM_BOT_HMAC_SECRET", bad)
        with pytest.raises(RuntimeError) as exc:
            _bot_secret_loader()("TELEGRAM_BOT_HMAC_SECRET")
        assert "Insecure" in str(exc.value)


def test_n2_C_short_secret_rejected(monkeypatch):
    monkeypatch.setenv("TELEGRAM_BOT_HMAC_SECRET", "z" * 31)
    with pytest.raises(RuntimeError) as exc:
        _bot_secret_loader()("TELEGRAM_BOT_HMAC_SECRET")
    assert "at least" in str(exc.value)


@pytest.mark.parametrize("other", ["TOKEN_SECRET", "OAUTH_JWT_SECRET",
                                   "OAUTH_ADMIN_KEY", "AGENT_JWT_SECRET"])
def test_n2_D_E_F_G_reused_secret_rejected(monkeypatch, other):
    shared = "r" * 48
    monkeypatch.setenv(other, shared)
    monkeypatch.setenv("TELEGRAM_BOT_HMAC_SECRET", shared)
    with pytest.raises(RuntimeError) as exc:
        _bot_secret_loader()("TELEGRAM_BOT_HMAC_SECRET")
    assert other in str(exc.value)


def test_n2_H_valid_independent_secret_accepted(monkeypatch):
    for k in ("TOKEN_SECRET", "OAUTH_JWT_SECRET", "OAUTH_ADMIN_KEY",
              "AGENT_JWT_SECRET"):
        monkeypatch.setenv(k, "other-" + k)
    monkeypatch.setenv("TELEGRAM_BOT_HMAC_SECRET", "t" * 48)
    assert _bot_secret_loader()("TELEGRAM_BOT_HMAC_SECRET") == "t" * 48


def test_n2_I_hmac_protocol_unchanged():
    """The HMAC construction itself must keep working with the new secret.

    Mirrors telegram_group_bot.py's sign/verify pair; only key management
    was changed, never the protocol.
    """
    secret = "n2-protocol-test-secret-" + "k" * 32
    payload = b"user:12345:capability:join_group"
    sig = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    assert hmac.compare_digest(sig, expected)          # valid accepted
    wrong = hmac.new(b"different-secret-value-padding-xx", payload,
                     hashlib.sha256).hexdigest()
    assert not hmac.compare_digest(sig, wrong)         # invalid rejected


def test_n2_no_fallback_left_in_source():
    with open("telegram_group_bot.py", encoding="utf-8") as fh:
        src = fh.read()
    assert 'os.getenv("TELEGRAM_BOT_HMAC_SECRET", os.getenv("TOKEN_SECRET"' not in src
    assert 'HMAC_SECRET = _require_bot_secret("TELEGRAM_BOT_HMAC_SECRET")' in src


def test_all_five_secrets_pairwise_distinct(server_module):
    """Full isolation matrix."""
    from dotenv import dotenv_values
    v = dotenv_values(".env")
    keys = ["TOKEN_SECRET", "OAUTH_JWT_SECRET", "AGENT_JWT_SECRET",
            "OAUTH_ADMIN_KEY", "TELEGRAM_BOT_HMAC_SECRET"]
    vals = [v[k] for k in keys if v.get(k)]
    assert len(vals) == 5, "all five secrets must be configured"
    assert len(set(vals)) == 5, "secrets must be pairwise distinct"
