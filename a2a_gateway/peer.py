"""The external peer boundary (LEVEL 3).

An `ExternalPeerIdentity` describes who is talking to us from the outside. It is
deliberately *not* an AEra identity and cannot be converted into one here.

This type exists so that a future trust/identity-mapping layer has a defined
seam to attach to. Building that layer is explicitly out of scope for this
phase; what matters now is that the seam is honest:

    auth=none  ->  authenticated_principal is None

An unauthenticated peer is an UNAUTHENTICATED EXTERNAL PEER, not an AEra agent.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

#: Authentication outcomes. "none" means no credential was *required*;
#: "anonymous" means we know nothing about who called.
AUTH_NONE = "none"
AUTH_BEARER = "bearer"
AUTH_API_KEY = "apiKey"

STATUS_ANONYMOUS = "anonymous"
STATUS_AUTHENTICATED = "authenticated"
STATUS_FAILED = "failed"


@dataclass(frozen=True)
class ExternalPeerIdentity:
    """Who the external caller claims/proves to be. Claims are NOT facts."""

    #: Always "external_a2a" for this gateway -- the provenance of the identity.
    source: str = "external_a2a"

    #: Whatever the peer *claimed* about itself. Untrusted, informational only.
    external_agent_id: Optional[str] = None

    #: Which transport auth method was used.
    authentication_method: str = AUTH_NONE

    #: anonymous | authenticated | failed
    authentication_status: str = STATUS_ANONYMOUS

    #: Only ever set when a credential was actually verified. For auth=none
    #: this MUST stay None -- that is the whole point of the distinction.
    authenticated_principal: Optional[str] = None

    #: AEra-minted identity of the external peer. Set only after a credential
    #: was verified. Never taken from the request -- a caller cannot name itself.
    peer_id: Optional[str] = None

    #: Which credential proved it. Safe to log: it is a public handle, not the
    #: secret. Needed so an audit trail can point at a specific credential when
    #: one has to be revoked.
    credential_id: Optional[str] = None

    #: The credential's scope restrictions, carried forward for authorisation.
    #: Empty tuple means "unrestricted at this dimension".
    scoped_agents: tuple = ()
    scoped_skills: tuple = ()

    @property
    def is_authenticated(self) -> bool:
        return (
            self.authentication_status == STATUS_AUTHENTICATED
            and self.authenticated_principal is not None
        )

    @property
    def is_trusted_aera_agent(self) -> bool:
        """Always False. An external peer is never an AEra agent.

        Kept as an explicit property so that any future code which *wants* to
        make that leap has to delete this method deliberately rather than do it
        by accident.
        """
        return False

    def audit_label(self) -> str:
        """A short, non-sensitive identifier for logs."""
        if self.authenticated_principal:
            return f"{self.source}:{self.authenticated_principal}"
        if self.external_agent_id:
            return f"{self.source}:claimed:{self.external_agent_id}"
        return f"{self.source}:anonymous"

    def to_audit_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "external_agent_id": self.external_agent_id,
            "authentication_method": self.authentication_method,
            "authentication_status": self.authentication_status,
            "authenticated_principal": self.authenticated_principal,
            "peer_id": self.peer_id,
            "credential_id": self.credential_id,
        }

    def __repr__(self) -> str:  # never let a credential reach a log
        return (f"<ExternalPeerIdentity {self.audit_label()} "
                f"method={self.authentication_method} "
                f"status={self.authentication_status}>")


def anonymous_peer(claimed_id: Optional[str] = None) -> ExternalPeerIdentity:
    """The auth=none case: we accept the call, we do not believe the caller."""
    return ExternalPeerIdentity(
        external_agent_id=claimed_id,
        authentication_method=AUTH_NONE,
        authentication_status=STATUS_ANONYMOUS,
        authenticated_principal=None,
    )


def authenticated_peer(record, *, claimed_id: Optional[str] = None,
                       method: str = AUTH_BEARER) -> ExternalPeerIdentity:
    """Build a peer identity from a *verified* credential record.

    The only constructor that may set STATUS_AUTHENTICATED. It takes a
    `CredentialRecord`, which can only be produced by `verify_credential`, so
    there is no path to an authenticated peer that skipped verification.

    `claimed_id` is still recorded, and still untrusted -- proving you are
    peer_abc123 does not make your claim to be "Sanctum Beacon" true.
    """
    return ExternalPeerIdentity(
        external_agent_id=claimed_id,
        authentication_method=method,
        authentication_status=STATUS_AUTHENTICATED,
        authenticated_principal=record.peer_id,
        peer_id=record.peer_id,
        credential_id=record.cred_id,
        scoped_agents=tuple(record.scoped_agents),
        scoped_skills=tuple(record.scoped_skills),
    )
