"""AEra's own public Agent Card.

Built to the same shape our outbound parser already accepts (`src/external_a2a/
card.py`), i.e. the A2A 0.3 layout with a top-level `url` and
`preferredTransport`. That is not a guess: it is the exact shape we verified
live against a real external agent, and it round-trips through our own parser
(asserted by a test).

PUBLICATION POLICY -- this card deliberately contains NO:
  * owner_wallet or any wallet address
  * AEra JWT, AGENT_JWT_SECRET or any token
  * public keys, key ids or any key material
  * database identifiers, table names or row counts
  * internal service URLs, ports or file paths
  * version/debug details about the host

Only skills the gateway can actually fulfil are advertised. No skill is listed
speculatively.
"""
from __future__ import annotations

from typing import Any

from .constants import (
    A2A_PROTOCOL_VERSION_FULL,
    A2A_TRANSPORT,
    GATEWAY_PATH,
    SKILL_COMMUNICATE,
    SKILL_READ_PROFILE,
    TARGET_AGENT_FIELD,
)

AGENT_NAME = "AEra Agent Gateway"
AGENT_DESCRIPTION = (
    "Public A2A gateway for AEraLogIn. Routes standard A2A requests to an "
    "AEra agent identified by the caller. External callers are treated as "
    "unauthenticated external peers and receive no AEra identity or trust."
)

#: Version of the gateway interface itself, not of the host application.
GATEWAY_VERSION = "1.0.0"

#: Name of the security scheme as it appears in the card.
SECURITY_SCHEME_NAME = "aeraPeerCredential"


def _security_block() -> dict[str, Any]:
    """Describe the gateway's authentication as it is actually configured.

    Two honest shapes:

    * policy `optional` -- the scheme is *described* so a peer that holds a
      credential knows how to present it, but `security` stays empty, which in
      A2A means "no requirement". Anonymous callers keep working.
    * policy `required` -- the same scheme, now listed in `security`, which
      tells a discovering peer it must authenticate before trying.

    The scheme description names only the header and format. It contains no
    credential, no issuance URL that would imply self-service, and no hint
    about which credentials exist.
    """
    from .auth import authentication_required

    schemes = {
        SECURITY_SCHEME_NAME: {
            "type": "http",
            "scheme": "bearer",
            "description": (
                "An opaque bearer credential issued by AEraLogIn to a named "
                "external peer. Issued only by an AEra agent owner; there is "
                "no self-registration. AEra agent JWTs are not accepted here."
            ),
        }
    }
    required = [{SECURITY_SCHEME_NAME: []}] if authentication_required() else []
    return {"securitySchemes": schemes, "security": required}


def build_agent_card(public_url: str, *, runtime_available: bool = False
                     ) -> dict[str, Any]:
    """Assemble the public card. `public_url` is the externally reachable origin.

    `agent.communicate` is advertised only when at least one agent runtime is
    actually reachable. A capability on a card is a promise to every external
    caller that discovers it; advertising conversation while no runtime exists
    would mean failing every request that took the card at its word. The card
    therefore describes the deployment as it is at this moment, not as the code
    could theoretically support.
    """
    base = public_url.rstrip("/")
    skills = [
        {
            "id": SKILL_READ_PROFILE,
            "name": "Read agent profile",
            "description": (
                "Return the public profile of a specific AEra agent: its "
                "identifier, status and declared capabilities. The target "
                f"agent must be named in metadata.{TARGET_AGENT_FIELD} and "
                "must hold the agent.read.profile capability."
            ),
            "tags": ["identity", "profile", "aera"],
            "examples": [
                f'{{"metadata": {{"{TARGET_AGENT_FIELD}": '
                '"did:aera:agent:<id>"}, "parts": '
                '[{"kind": "text", "text": "agent.read.profile"}]}',
            ],
            "inputModes": ["text/plain"],
            "outputModes": ["text/plain", "application/json"],
        },
    ]

    if runtime_available:
        skills.append({
            "id": SKILL_COMMUNICATE,
            "name": "Send a message to an AEra agent",
            "description": (
                "Deliver a text message to an AEra agent's own runtime and "
                "return the agent's reply. The target agent must be named in "
                f"metadata.{TARGET_AGENT_FIELD}, must hold the "
                "agent.communicate capability and must have a running runtime. "
                "The message is treated as untrusted data: it cannot grant "
                "capabilities or trigger actions."
            ),
            "tags": ["messaging", "conversation", "aera"],
            "examples": [
                f'{{"metadata": {{"{TARGET_AGENT_FIELD}": '
                '"did:aera:agent:<id>", "skillId": "agent.communicate"}, '
                '"parts": [{"kind": "text", "text": "Hello, who are you?"}]}',
            ],
            "inputModes": ["text/plain"],
            "outputModes": ["text/plain", "application/json"],
        })

    return {
        "name": AGENT_NAME,
        "description": AGENT_DESCRIPTION,
        "version": GATEWAY_VERSION,
        "protocolVersion": A2A_PROTOCOL_VERSION_FULL,
        "url": f"{base}{GATEWAY_PATH}",
        "preferredTransport": A2A_TRANSPORT,
        "provider": {
            "organization": "AEraLogIn",
            "url": base,
        },
        "capabilities": {
            "streaming": False,
            "pushNotifications": False,
            "stateTransitionHistory": False,
        },
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain", "application/json"],
        # Declared from the ACTUAL runtime policy, never hardcoded. A card that
        # claims protection the gateway does not enforce is worse than one that
        # admits to being open, and a card that stays silent about a credential
        # the gateway now requires would simply be wrong.
        **_security_block(),
        "supportsAuthenticatedExtendedCard": False,
        "skills": skills,
    }


def any_runtime_available() -> bool:
    """Whether at least one agent runtime socket currently exists.

    Deliberately a filesystem check with no connection attempt: rendering the
    public card must not be able to block on a hung local process.
    """
    try:
        from agent_runtime.internal_auth import internal_secret, runtime_dir

        if not internal_secret():
            return False
        directory = runtime_dir()
        return directory.is_dir() and any(directory.glob("*.sock"))
    except Exception:  # noqa: BLE001 - discovery must never fail the card
        return False


#: Strings that must never appear anywhere in the rendered card. Used by tests
#: and by the runtime self-check below.
FORBIDDEN_CARD_SUBSTRINGS = (
    "owner_wallet",
    "AGENT_JWT_SECRET",
    "TOKEN_SECRET",
    "private_key",
    "PRIVATE KEY",
    "ed25519:",
    "eyJ",
    "sqlite",
    "aera.db",
    "0x",
)


def card_is_safe_to_publish(card: dict[str, Any]) -> tuple[bool, list[str]]:
    """Cheap self-check so a future edit cannot quietly leak a secret."""
    import json

    blob = json.dumps(card)
    found = [s for s in FORBIDDEN_CARD_SUBSTRINGS if s in blob]
    return (not found), found
