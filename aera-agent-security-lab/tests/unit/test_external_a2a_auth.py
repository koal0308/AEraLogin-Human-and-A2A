"""Auth adapters, and the hard boundary that keeps AEra credentials at home."""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.external_a2a.auth import (  # noqa: E402
    ApiKeyAdapter,
    BearerTokenAdapter,
    NoAuthAdapter,
    describe_required_auth,
    select_adapter,
)
from src.external_a2a.card import parse_agent_card  # noqa: E402
from src.external_a2a.errors import A2AAuthError  # noqa: E402

BASE = {
    "name": "Test Agent",
    "description": "d",
    "version": "1.0.0",
    "protocolVersion": "0.3.0",
    "url": "https://example.test/a2a",
    "preferredTransport": "JSONRPC",
}


def card(**overrides):
    return parse_agent_card(dict(BASE, **overrides))


def _b64(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


def fake_aera_jwt(aud: str = "aera-agent-api") -> str:
    """Structurally a JWT, exactly what the AEra identity layer hands out."""
    return ".".join([
        _b64({"alg": "HS256", "typ": "JWT"}),
        _b64({"sub": "did:aera:agent:abc", "aud": aud}),
        "c2lnbmF0dXJl",
    ])


# -- adapter behaviour -------------------------------------------------------
def test_no_auth_adapter_sends_no_headers():
    a = NoAuthAdapter()
    assert a.headers() == {}
    assert a.describe() == "none"


def test_bearer_adapter_sets_authorization_header():
    a = BearerTokenAdapter("external-opaque-token-123")
    assert a.headers() == {"Authorization": "Bearer external-opaque-token-123"}


def test_api_key_adapter_uses_named_header():
    a = ApiKeyAdapter("secret-key", header_name="X-Custom-Key")
    assert a.headers() == {"X-Custom-Key": "secret-key"}


def test_empty_credentials_are_rejected():
    with pytest.raises(A2AAuthError):
        BearerTokenAdapter("")
    with pytest.raises(A2AAuthError):
        BearerTokenAdapter("   ")
    with pytest.raises(A2AAuthError):
        ApiKeyAdapter("")


def test_header_injection_is_rejected():
    with pytest.raises(A2AAuthError):
        ApiKeyAdapter("k", header_name="X-Bad\r\nInjected: 1")


def test_adapters_never_leak_the_secret_via_repr():
    for a in (BearerTokenAdapter("super-secret-token"),
              ApiKeyAdapter("super-secret-key")):
        assert "super-secret" not in repr(a)
        assert "super-secret" not in str(a)


# -- the AEra boundary -------------------------------------------------------
def test_aera_jwt_is_never_accepted_as_an_external_bearer_token():
    with pytest.raises(A2AAuthError):
        BearerTokenAdapter(fake_aera_jwt("aera-agent-api"))


def test_aera_relay_jwt_is_never_accepted():
    with pytest.raises(A2AAuthError):
        BearerTokenAdapter(fake_aera_jwt("aera-agent-relay"))


def test_aera_jwt_is_never_accepted_as_an_api_key():
    with pytest.raises(A2AAuthError):
        ApiKeyAdapter(fake_aera_jwt())


def test_credentials_naming_aera_are_rejected():
    for bad in ("aera-agent-api-token", "token-for-aeralogin.com", "x-aera-agent-relay-y"):
        with pytest.raises(A2AAuthError):
            BearerTokenAdapter(bad)


def test_ed25519_private_key_is_never_accepted_as_a_credential():
    pem = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA==\n-----END PRIVATE KEY-----"
    with pytest.raises(A2AAuthError):
        BearerTokenAdapter(pem)


def test_owner_wallet_private_key_is_never_accepted_as_a_credential():
    with pytest.raises(A2AAuthError):
        BearerTokenAdapter("0x" + "ab" * 32)


def test_jwt_secret_is_never_accepted_as_a_credential():
    with pytest.raises(A2AAuthError):
        ApiKeyAdapter("AGENT_JWT_SECRET=hunter2")


def test_adapter_cannot_be_built_from_an_aera_identity_client():
    """select_adapter takes explicit credentials only -- no AEra handle."""
    import inspect
    params = set(inspect.signature(select_adapter).parameters)
    assert params == {"card", "bearer_token", "api_key", "api_key_header"}


# -- selection ---------------------------------------------------------------
def test_open_endpoint_selects_no_auth():
    assert isinstance(select_adapter(card()), NoAuthAdapter)


def test_explicit_bearer_token_wins():
    a = select_adapter(card(), bearer_token="ext-token")
    assert isinstance(a, BearerTokenAdapter)


def test_required_auth_without_credentials_fails_loudly():
    c = card(security=[{"apiKey": []}])
    with pytest.raises(A2AAuthError) as exc:
        select_adapter(c)
    assert "requires authentication" in str(exc.value)


def test_api_key_header_is_read_from_the_card_v03_scheme():
    c = card(securitySchemes={"k": {"type": "apiKey", "in": "header", "name": "X-Beacon-Key"}})
    a = select_adapter(c, api_key="ext-key")
    assert "X-Beacon-Key" in a.headers()


def test_api_key_header_is_read_from_the_card_v10_scheme():
    c = card(securitySchemes={
        "k": {"apiKeySecurityScheme": {"location": "header", "name": "X-V1-Key"}}})
    a = select_adapter(c, api_key="ext-key")
    assert "X-V1-Key" in a.headers()


def test_describe_required_auth_is_honest():
    assert "none" in describe_required_auth(card())
    assert "apiKey" in describe_required_auth(card(security=[{"apiKey": []}]))
