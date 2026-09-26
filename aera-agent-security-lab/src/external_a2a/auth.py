"""A2AAuthAdapter -- the boundary between AEra identity and external transport auth.

The single most important rule in this file:

    An AEra Agent JWT is a credential for AEra services. It is NEVER sent to a
    third party merely because that third party expects a bearer token.

So no adapter here can be constructed from an `AeraIdentityClient`. Credentials
must be passed in explicitly by the operator, and `NoAuthAdapter` is the default.
A defensive check also refuses any credential that merely looks like an AEra
token, so a copy-paste mistake fails loudly instead of leaking.

Only the mechanisms actually needed for the first interoperability test are
implemented: none, bearer, and API key. OAuth 2.0 and mTLS are deliberately NOT
built yet (see docs/external-a2a.md, "Not implemented").
"""
from __future__ import annotations

from typing import Any, Optional

from .card import AgentCard
from .errors import A2AAuthError

#: Audiences AEra mints tokens for. A credential carrying one of these is an
#: AEra-internal token and must never leave for a third party.
AERA_TOKEN_MARKERS = ("aera-agent-api", "aera-agent-relay", "aeralogin.com")

#: Shapes that indicate raw key material rather than a bearer credential. A
#: private key must never be transmitted anywhere, to anyone, for any reason.
KEY_MATERIAL_MARKERS = (
    "-----begin",
    "private key",
    "agent_jwt_secret",
)


def _reject_aera_credential(secret: str) -> None:
    """Refuse anything that smells like an AEra-issued token or key material."""
    if not secret:
        return
    if secret.count(".") == 2 and secret.startswith("eyJ"):
        raise A2AAuthError(
            "refusing to send what looks like a JWT minted by AEra to an external "
            "agent; external credentials must be issued by the external provider"
        )
    low = secret.lower()
    for marker in KEY_MATERIAL_MARKERS:
        if marker in low:
            raise A2AAuthError(
                "refusing to send what looks like private key material to an "
                "external agent; a private key is never a transport credential"
            )
    #: A 0x-prefixed 32-byte hex blob is an EOA private key, not a token.
    if low.startswith("0x") and len(low) == 66:
        try:
            int(low, 16)
        except ValueError:
            pass
        else:
            raise A2AAuthError(
                "refusing to send what looks like a 32-byte private key to an "
                "external agent"
            )
    for marker in AERA_TOKEN_MARKERS:
        if marker in low:
            raise A2AAuthError(
                f"refusing to send a credential containing the AEra marker {marker!r} "
                "to an external agent"
            )


class A2AAuthAdapter:
    """Turns whatever the external agent requires into request headers."""

    #: Stable name for audit records.
    scheme = "none"

    def headers(self) -> dict[str, str]:
        raise NotImplementedError

    def describe(self) -> str:
        return self.scheme

    def __repr__(self) -> str:  # never leak a secret through logs or tracebacks
        return f"<{type(self).__name__} scheme={self.scheme}>"

    __str__ = __repr__


class NoAuthAdapter(A2AAuthAdapter):
    """The external agent's A2A endpoint is open. The common public case."""

    scheme = "none"

    def headers(self) -> dict[str, str]:
        return {}


class BearerTokenAdapter(A2AAuthAdapter):
    """`Authorization: Bearer <token>` with a token issued by the EXTERNAL provider."""

    scheme = "bearer"

    def __init__(self, token: str) -> None:
        token = (token or "").strip()
        if not token:
            raise A2AAuthError("bearer authentication selected but no token was supplied")
        _reject_aera_credential(token)
        self._token = token

    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}"}


class ApiKeyAdapter(A2AAuthAdapter):
    """API key in a header, as described by an `apiKeySecurityScheme`."""

    scheme = "apiKey"

    def __init__(self, key: str, *, header_name: str = "X-API-Key") -> None:
        key = (key or "").strip()
        if not key:
            raise A2AAuthError("API-key authentication selected but no key was supplied")
        _reject_aera_credential(key)
        if not header_name or any(c in header_name for c in "\r\n: "):
            raise A2AAuthError(f"invalid API key header name: {header_name!r}")
        self._key = key
        self._header = header_name

    def headers(self) -> dict[str, str]:
        return {self._header: self._key}


def describe_required_auth(card: AgentCard) -> str:
    """Human-readable summary of what the card says it wants."""
    if not card.requires_authentication:
        return "none (no security requirements declared)"
    names: list[str] = []
    for req in card.security_requirements:
        if isinstance(req, dict):
            schemes = req.get("schemes")
            names.extend(schemes.keys() if isinstance(schemes, dict) else req.keys())
    detail = ", ".join(sorted(set(names))) or "<unnamed>"
    return f"required: {detail}"


def select_adapter(
    card: AgentCard,
    *,
    bearer_token: Optional[str] = None,
    api_key: Optional[str] = None,
    api_key_header: Optional[str] = None,
) -> A2AAuthAdapter:
    """Pick an adapter from the card plus explicitly supplied credentials.

    Never invents a credential and never reaches into AEra for one.
    """
    if bearer_token:
        return BearerTokenAdapter(bearer_token)
    if api_key:
        return ApiKeyAdapter(api_key, header_name=api_key_header or _api_key_header(card))
    if card.requires_authentication:
        raise A2AAuthError(
            f"external agent {card.name!r} requires authentication "
            f"({describe_required_auth(card)}) but no credentials were supplied",
            scheme=describe_required_auth(card),
        )
    return NoAuthAdapter()


def _api_key_header(card: AgentCard) -> str:
    """Read the header name out of the first apiKey scheme, else a sane default."""
    for scheme in card.security_schemes.values():
        if not isinstance(scheme, dict):
            continue
        # v1.0 nests under a discriminator; v0.3 uses a flat "type" field.
        inner = scheme.get("apiKeySecurityScheme")
        if isinstance(inner, dict) and str(inner.get("location", "")).lower() == "header":
            name = inner.get("name")
            if isinstance(name, str) and name:
                return name
        if str(scheme.get("type", "")).lower() == "apikey" and \
                str(scheme.get("in", "")).lower() == "header":
            name = scheme.get("name")
            if isinstance(name, str) and name:
                return name
    return "X-API-Key"
