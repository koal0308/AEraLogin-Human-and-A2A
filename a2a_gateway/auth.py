"""Inbound transport authentication.

The gateway accepts opaque bearer credentials issued by AEra to external peers
(`a2a_gateway/credentials.py`). Whether one is *required* is an operator
decision -- see `AERA_A2A_AUTH_POLICY`. The default remains `optional`, so an
anonymous caller is still served exactly as before; presenting a valid
credential is what upgrades a caller from anonymous to authenticated.

The critical rule enforced here, unchanged from the previous phase:

    Presenting an AEra Agent JWT to this gateway grants NOTHING.

The inbound gateway is a LEVEL 3 boundary. AEra agent tokens belong to LEVEL 2
and are verified by `agent/tokens.py` on `/api/agents/*`, not here. Treating an
AEra JWT as an external transport credential would collapse two trust levels
into one, so it is explicitly refused -- and refused *before* any credential
lookup, so the two paths can never be confused.

Authentication answers "who is this". It does not answer "what may they do";
that is `authorize_request()` in `credentials.py`, called later, separately.
"""
from __future__ import annotations

import os
from typing import Optional

from . import credentials as _cred
from .constants import (
    AUTH_POLICY_REQUIRED,
    DEFAULT_AUTH_POLICY,
)
from .peer import (
    AUTH_API_KEY,
    AUTH_BEARER,
    AUTH_NONE,
    STATUS_ANONYMOUS,
    STATUS_FAILED,
    ExternalPeerIdentity,
    anonymous_peer,
    authenticated_peer,
)

#: Header an API-key scheme would use, if one were ever declared in the card.
API_KEY_HEADER = "x-api-key"


class InboundAuthError(Exception):
    """The credential presented is malformed. Distinct from 'not authorised'."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def auth_policy() -> str:
    """Read the inbound policy. Anything unrecognised means `optional`.

    Failing *open* on a typo is the right choice here and only here: the
    alternative would be that a misspelling in `.env` silently locks out every
    existing anonymous peer, which is an availability incident caused by a
    configuration error rather than a security decision. The security-relevant
    direction -- enabling `required` -- must be spelled correctly to take
    effect, and is verified by the live probe.
    """
    value = (os.getenv("AERA_A2A_AUTH_POLICY", "") or "").strip().lower()
    return AUTH_POLICY_REQUIRED if value == AUTH_POLICY_REQUIRED else DEFAULT_AUTH_POLICY


def authentication_required() -> bool:
    return auth_policy() == AUTH_POLICY_REQUIRED


def _looks_like_a_jwt(token: str) -> bool:
    return token.count(".") == 2 and token.startswith("eyJ")


def authenticate_request(headers, *, claimed_agent_id: Optional[str] = None,
                         conn=None, conn_factory=None) -> ExternalPeerIdentity:
    """Turn transport headers into an ExternalPeerIdentity.

    Raises InboundAuthError when a credential is present but malformed or
    invalid, and -- under `AERA_A2A_AUTH_POLICY=required` -- when none is
    present at all. Silently ignoring a bad credential would hide caller bugs
    and let an attacker probe for parser differences.

    The credential store is reached through `conn_factory`, which is called
    ONLY once a syntactically valid, non-JWT bearer credential has actually
    been presented. Every rejection above that point -- no header, wrong
    scheme, a JWT, a malformed credential -- happens without opening a
    database connection, so a flood of junk costs no I/O. `conn` is accepted
    as well for direct unit testing.
    """
    raw = _get(headers, "authorization")
    api_key = _get(headers, API_KEY_HEADER)

    if raw is None and api_key is None:
        if authentication_required():
            raise InboundAuthError(
                "this gateway requires an external peer credential")
        return anonymous_peer(claimed_agent_id)

    if api_key is not None and raw is None:
        if not api_key.strip():
            raise InboundAuthError("empty API key")
        # No API-key store exists. A key buys no privilege, and under a
        # `required` policy it is not a substitute for a bearer credential.
        if authentication_required():
            raise InboundAuthError(
                "this gateway requires an external peer credential")
        return ExternalPeerIdentity(
            external_agent_id=claimed_agent_id,
            authentication_method=AUTH_API_KEY,
            authentication_status=STATUS_ANONYMOUS,
            authenticated_principal=None,
        )

    assert raw is not None
    value = raw.strip()
    if not value:
        raise InboundAuthError("empty Authorization header")

    parts = value.split(None, 1)
    if len(parts) != 2:
        raise InboundAuthError("malformed Authorization header")

    scheme, credential = parts[0].lower(), parts[1].strip()
    if not credential:
        raise InboundAuthError("malformed Authorization header: empty credential")

    if scheme != "bearer":
        raise InboundAuthError(f"unsupported Authorization scheme: {parts[0][:32]!r}")

    if _looks_like_a_jwt(credential):
        # An AEra Agent JWT (or anything shaped like one) is not an external
        # transport credential. Refusing loudly is safer than ignoring it,
        # because a caller doing this has misunderstood the trust boundary.
        # Checked before the credential store so that no AEra token ever
        # reaches a lookup path.
        raise InboundAuthError(
            "a JWT is not accepted as an external transport credential on the "
            "A2A gateway; AEra agent tokens are not external identities"
        )

    if conn is None and conn_factory is None:
        # No store available. Fail closed: an unverifiable credential is not a
        # valid one, and under `required` there is nothing to fall back to.
        if authentication_required():
            raise InboundAuthError(_cred.OPAQUE_AUTH_FAILURE)
        return ExternalPeerIdentity(
            external_agent_id=claimed_agent_id,
            authentication_method=AUTH_BEARER,
            authentication_status=STATUS_ANONYMOUS,
            authenticated_principal=None,
        )

    owned = conn is None
    if owned:
        try:
            conn = conn_factory()
        except Exception:  # noqa: BLE001 - a broken store must not grant access
            raise InboundAuthError(_cred.OPAQUE_AUTH_FAILURE) from None
    try:
        try:
            record = _cred.verify_credential(conn, credential)
        except _cred.CredentialError as exc:
            # One wording for every failure mode -- unknown, revoked, expired
            # and wrong-secret are indistinguishable from outside, so the
            # endpoint cannot be used to enumerate valid credential ids.
            raise InboundAuthError(exc.message) from None
        except Exception:  # noqa: BLE001 - a broken store must not grant access
            raise InboundAuthError(_cred.OPAQUE_AUTH_FAILURE) from None

        _cred.touch(conn, record.cred_id)
        if owned:
            try:
                conn.commit()
            except Exception:  # noqa: BLE001 - telemetry only
                pass
        return authenticated_peer(record, claimed_id=claimed_agent_id)
    finally:
        if owned and conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass


def failed_peer(method: str = AUTH_NONE) -> ExternalPeerIdentity:
    return ExternalPeerIdentity(
        authentication_method=method,
        authentication_status=STATUS_FAILED,
        authenticated_principal=None,
    )


def _get(headers, name: str) -> Optional[str]:
    try:
        return headers.get(name)
    except AttributeError:  # pragma: no cover - defensive
        return None
