"""Error taxonomy for external A2A.

The brief requires that four failure classes stay clearly distinguishable:

    A2ANetworkError   transport / SSRF / timeout / size   -- our side or the wire
    A2AAuthError      credentials missing, rejected       -- the EXTERNAL agent's auth
    A2AProtocolError  malformed card / malformed response -- the EXTERNAL agent's protocol
    A2ARemoteError    a well-formed A2A error response    -- the EXTERNAL agent's business logic

None of these are AEra identity failures. AEra identity problems surface as
`AeraError` from `src.identity.aera_client` and are never re-raised as one of
these, so an operator can always tell "our identity broke" from "their agent
broke".
"""
from __future__ import annotations

from typing import Any, Optional


class A2AError(Exception):
    """Base class for every external-A2A failure."""

    category = "external"

    def __init__(self, message: str, *, detail: Any = None) -> None:
        super().__init__(message)
        self.detail = detail


class A2ANetworkError(A2AError):
    """Transport-level failure: DNS, TLS, timeout, size limit, SSRF refusal."""

    category = "network"


class A2AAuthError(A2AError):
    """The external agent refused our credentials, or we have none to offer."""

    category = "auth"

    def __init__(self, message: str, *, detail: Any = None,
                 status: Optional[int] = None, scheme: Optional[str] = None) -> None:
        super().__init__(message, detail=detail)
        self.status = status
        self.scheme = scheme


class A2AProtocolError(A2AError):
    """The external agent's Agent Card or response does not conform to A2A."""

    category = "protocol"


class A2ARemoteError(A2AError):
    """The external agent returned a valid A2A/JSON-RPC error object."""

    category = "remote"

    def __init__(self, message: str, *, code: Any = None, detail: Any = None) -> None:
        super().__init__(message, detail=detail)
        self.code = code


class SSRFBlocked(A2ANetworkError):
    """The requested URL resolves somewhere we refuse to send traffic."""

    category = "ssrf_blocked"
