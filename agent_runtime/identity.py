"""The runtime's AEra identity: authenticate, hold a JWT, notice revocation.

This uses the EXISTING Agent Identity API exactly as specified. It defines no
new token type, changes no claim, and never sees `AGENT_JWT_SECRET` — AEra
signs the JWT, the runtime merely receives and presents it.

WHY THIS IS NOT `AeraIdentityClient`
------------------------------------
The lab's `AeraIdentityClient` generates a *disposable owner EOA* and a fresh
in-memory key in its constructor. That is exactly right for a test harness and
exactly wrong for a product runtime, which must:

  * load a persistent key from disk rather than invent one per process,
  * never contain an owner wallet key at all,
  * survive JWT expiry without the caller thinking about it.

Copying the harness into product code would have quietly shipped a disposable
owner wallet inside the runtime. The canonical-JSON and signing primitives are
still reused from production `agent/`, so no signature logic is duplicated.

JWT HANDLING
------------
Tokens are kept in memory only and are never written to disk. A restart
re-authenticates; that costs one round trip and removes a class of leaks
entirely. Tokens are refreshed before expiry rather than after a failure, so a
long-running conversation does not fail on a boundary.
"""
from __future__ import annotations

import threading
import time
from typing import Any, Optional

import httpx

from agent.constants import (
    AGENT_AUTH_KEYS,
    AUD_AGENT_API,
    AUD_AGENT_RELAY,
    PROTO_AGENT_AUTH,
    PROTOCOL_VERSION,
)
from agent.crypto import b64u_encode, canonical_json

from .keystore import LocalKeyStore

#: Refresh this many seconds before the token actually expires.
REFRESH_MARGIN_SECONDS = 60


class IdentityError(Exception):
    """Authentication against AEra failed for a recoverable reason."""


class RevokedError(IdentityError):
    """AEra reports this agent or key as revoked. Not recoverable locally."""


#: `agent_error` values that mean "stop trying"; anything else may be transient.
_REVOKED_MARKERS = frozenset({
    "agent_revoked", "agent_not_found", "key_revoked", "key_not_found",
    "agent_inactive",
})


class RuntimeIdentity:
    """Holds the agent's AEra identity and its short-lived tokens."""

    def __init__(self, *, base_url: str, agent_id: str, key_id: str,
                 keystore: LocalKeyStore, timeout: float = 30.0,
                 http: Optional[httpx.Client] = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.agent_id = agent_id
        self.key_id = key_id
        self.keystore = keystore
        self._http = http or httpx.Client(base_url=self.base_url, timeout=timeout)
        self._tokens: dict[str, tuple[str, int]] = {}
        self._lock = threading.Lock()

    def __repr__(self) -> str:
        # No token, no key. This object ends up in log context.
        return f"<RuntimeIdentity agent_id={self.agent_id} key_id={self.key_id}>"

    @property
    def public_key(self) -> str:
        return self.keystore.public_key

    # -- authentication ------------------------------------------------------
    def authenticate(self, *, aud: str = AUD_AGENT_API) -> str:
        """Full challenge/response against AEra. Returns the Agent JWT."""
        challenge = self._post(f"/api/agents/{self.agent_id}/challenge",
                               {"key_id": self.key_id, "aud": aud})

        payload = {
            "protocol": PROTO_AGENT_AUTH,
            "version": PROTOCOL_VERSION,
            "agent_id": self.agent_id,
            "key_id": self.key_id,
            "challenge_id": challenge["challenge_id"],
            "challenge": challenge["challenge"],
            "aud": aud,
            "issued_at": challenge["issued_at"],
            "expires_at": challenge["expires_at"],
        }
        # The private key is used here and only here.
        signature = b64u_encode(
            self.keystore.sign(canonical_json(payload, AGENT_AUTH_KEYS)))

        data = self._post(f"/api/agents/{self.agent_id}/authenticate", {
            "challenge_id": challenge["challenge_id"],
            "key_id": self.key_id,
            "aud": aud,
            "signature": signature,
        })
        with self._lock:
            self._tokens[aud] = (data["token"], int(data["expires_at"]))
        return data["token"]

    def token(self, *, aud: str = AUD_AGENT_API) -> str:
        """A valid token, refreshed ahead of expiry rather than after failure."""
        with self._lock:
            cached = self._tokens.get(aud)
            if cached and cached[1] - REFRESH_MARGIN_SECONDS > int(time.time()):
                return cached[0]
        return self.authenticate(aud=aud)

    def auth_header(self, *, aud: str = AUD_AGENT_API) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token(aud=aud)}"}

    def relay_header(self) -> dict[str, str]:
        return self.auth_header(aud=AUD_AGENT_RELAY)

    def forget_tokens(self) -> None:
        with self._lock:
            self._tokens.clear()

    # -- revocation ----------------------------------------------------------
    def check_liveness(self) -> bool:
        """Re-authenticate to find out whether AEra still accepts this agent.

        Revocation is detected by AEra refusing us, which is the authoritative
        answer. The runtime never decides for itself that it is still valid.
        """
        self.forget_tokens()
        self.authenticate()
        return True

    # -- transport -----------------------------------------------------------
    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        try:
            response = self._http.post(path, json=body)
        except httpx.HTTPError as exc:
            raise IdentityError(f"cannot reach AEra: {type(exc).__name__}") from exc

        if response.status_code == 200:
            return response.json()

        marker = _agent_error(response)
        if marker in _REVOKED_MARKERS or response.status_code in (401, 403):
            raise RevokedError(
                f"AEra refused this identity (HTTP {response.status_code}"
                f"{', ' + marker if marker else ''})")
        raise IdentityError(f"AEra returned HTTP {response.status_code}"
                            f"{', ' + marker if marker else ''}")

    def close(self) -> None:
        self._http.close()


def _agent_error(response: httpx.Response) -> Optional[str]:
    try:
        body = response.json()
    except ValueError:
        return None
    detail = body.get("detail", body) if isinstance(body, dict) else None
    if isinstance(detail, dict):
        value = detail.get("agent_error")
        return value if isinstance(value, str) else None
    return None
