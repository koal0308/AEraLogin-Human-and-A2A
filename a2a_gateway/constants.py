"""Constants for the inbound A2A gateway.

Protocol version and transport are deliberately fixed to the exact combination
that was already proven to work live against a real external agent
(Sanctum Beacon, A2A 0.3 over JSON-RPC). Nothing speculative is advertised.
"""
from __future__ import annotations

# --- protocol ---------------------------------------------------------------
#: The A2A version family this gateway speaks. Matches the version our outbound
#: client was interoperability-tested with.
A2A_PROTOCOL_VERSION = "0.3"
A2A_PROTOCOL_VERSION_FULL = "0.3.0"

#: The only transport implemented. No gRPC, no HTTP+JSON.
A2A_TRANSPORT = "JSONRPC"

#: JSON-RPC methods we accept. Anything else is rejected, never guessed.
METHOD_MESSAGE_SEND = "message/send"
SUPPORTED_METHODS = frozenset({METHOD_MESSAGE_SEND})

#: Methods that exist in the specification but are deliberately NOT implemented.
#: Listed so we can return "unsupported operation" instead of "method unknown".
KNOWN_UNIMPLEMENTED_METHODS = frozenset({
    "message/stream", "tasks/get", "tasks/cancel", "tasks/resubscribe",
    "tasks/pushNotificationConfig/set", "tasks/pushNotificationConfig/get",
    "agent/getAuthenticatedExtendedCard",
})

# --- routes -----------------------------------------------------------------
WELL_KNOWN_PATH = "/.well-known/agent-card.json"
GATEWAY_PATH = "/api/a2a"

# --- JSON-RPC error codes ---------------------------------------------------
ERR_PARSE = -32700
ERR_INVALID_REQUEST = -32600
ERR_METHOD_NOT_FOUND = -32601
ERR_INVALID_PARAMS = -32602
ERR_INTERNAL = -32603
# A2A-specific range
ERR_TASK_NOT_FOUND = -32001
ERR_UNSUPPORTED_OPERATION = -32004
ERR_CONTENT_TYPE_NOT_SUPPORTED = -32005
ERR_VERSION_NOT_SUPPORTED = -32009

# The A2A specification defines no rate-limit error, so we use the
# implementation-defined server range (-32000..-32099). The authoritative signal
# is the HTTP 429 + Retry-After; this code exists so that a client which only
# reads the JSON-RPC body still gets a structured, machine-readable reason.
ERR_RATE_LIMITED = -32010
RATE_LIMIT_MESSAGE = "rate limit exceeded: too many requests, retry later"

# --- limits (inbound requests are hostile until proven otherwise) -----------
MAX_REQUEST_BYTES = 64 * 1024
MAX_PARTS = 16
MAX_TEXT_LEN = 8_000
MAX_ID_LEN = 200
MAX_METADATA_KEYS = 20

#: How long an inbound message id is remembered for duplicate detection.
REPLAY_TTL_SECONDS = 10 * 60

#: Maximum accepted clock skew / age for a supplied timestamp.
MAX_REQUEST_AGE_SECONDS = 5 * 60
MAX_CLOCK_SKEW_SECONDS = 60

# --- routing ----------------------------------------------------------------
#: Where an external caller names the AEra agent it wants to reach.
TARGET_AGENT_FIELD = "aera_target_agent"

#: Skills this gateway can actually fulfil. Each maps 1:1 onto an EXISTING AEra
#: capability -- no skill is invented for the sake of the card.
SKILL_READ_PROFILE = "agent.read.profile"

#: Inbound conversation, delivered to the agent's own runtime process.
#: Advertised on the public Agent Card ONLY for agents that genuinely have a
#: reachable runtime (see `card.build_agent_card`), because a capability nobody
#: can serve is a promise we would be breaking on every call.
SKILL_COMMUNICATE = "agent.communicate"

SUPPORTED_SKILLS = frozenset({SKILL_READ_PROFILE, SKILL_COMMUNICATE})

#: skill id -> AEra capability the target agent must actually hold.
SKILL_TO_CAPABILITY = {
    SKILL_READ_PROFILE: "agent.read.profile",
    SKILL_COMMUNICATE: "agent.communicate",
}

# --- external peer credentials (LEVEL 3) ------------------------------------
#: Audience of an external peer credential.
#:
#: This value is deliberately NOT a member of `agent.constants.AUDIENCE_ALLOWLIST`.
#: An AEra Agent JWT and an external peer credential are different kinds of
#: thing held by different principals, and neither may ever be accepted where
#: the other is expected. Keeping the audiences disjoint makes that structural
#: rather than a matter of remembering to check.
CREDENTIAL_AUDIENCE = "aera-a2a-gateway"

#: Same issuer string as the Agent Identity Layer -- both are issued by AEra --
#: but paired with a different audience, which is what separates them.
CREDENTIAL_ISSUER = "aeralogin.com"

#: Prefix of every credential we mint. Also what makes a leaked credential
#: greppable in a log aggregator or a public repository.
CREDENTIAL_PREFIX = "aera_a2a_"

#: Default lifetime. Long enough to be operable, short enough that a credential
#: forgotten in a config file eventually stops working.
DEFAULT_CREDENTIAL_TTL_DAYS = 90

#: Inbound authentication policy.
#:   optional -- anonymous callers are still served (current public behaviour)
#:   required -- every inbound request must present a valid credential
#:
#: The default is `optional` because flipping it is a breaking change for every
#: existing anonymous peer, and that must be a deliberate operator decision,
#: not a side effect of deploying this phase.
AUTH_POLICY_OPTIONAL = "optional"
AUTH_POLICY_REQUIRED = "required"
DEFAULT_AUTH_POLICY = AUTH_POLICY_OPTIONAL

#: Authentication is required but absent or invalid.
ERR_UNAUTHENTICATED = -32011
#: Authenticated successfully, but not permitted for this target or skill.
ERR_FORBIDDEN = -32012
