"""Spec constants (v1.2) – protocol vocabularies, allowlists, TTLs, capabilities."""
from __future__ import annotations

# --- Protocol domain separators (§7.4) ---
PROTO_AGENT_AUTH = "aera-agent-auth"
PROTO_AGENT_MESSAGE = "aera-agent-message"
PROTO_OWNER_CHALLENGE = "aera-owner-challenge"
PROTOCOL_VERSION = "1"

# --- Audience allowlist (§9.6) ---
AUD_AGENT_API = "aera-agent-api"
AUD_AGENT_RELAY = "aera-agent-relay"
AUDIENCE_ALLOWLIST = frozenset({AUD_AGENT_API, AUD_AGENT_RELAY})

# --- Owner operations (§6a.3) ---
OWNER_OPS = frozenset({
    "register", "key_add", "key_rotate", "key_revoke",
    "agent_revoke", "capabilities",
})

# --- TTLs ---
AGENT_CHALLENGE_TTL_SECONDS = 60
OWNER_CHALLENGE_TTL_SECONDS = 120
AGENT_JWT_TTL_SECONDS = 15 * 60
MESSAGE_TTL_SECONDS = 5 * 60
JTI_RETENTION_SECONDS = 30 * 24 * 3600  # exp + 30d

# --- Capabilities (§12.1) ---
CAP_AUTHENTICATE = "agent.authenticate"
CAP_READ_PROFILE = "agent.read.profile"
CAP_COMMUNICATE = "agent.communicate"
CAP_INTERACTION_RECORD = "agent.interaction.record"
CAPABILITY_ALLOWLIST = frozenset({
    CAP_AUTHENTICATE, CAP_READ_PROFILE, CAP_COMMUNICATE, CAP_INTERACTION_RECORD,
})
DEFAULT_CAPABILITIES = (CAP_AUTHENTICATE, CAP_READ_PROFILE, CAP_COMMUNICATE)

# --- Key limits (§5.3) ---
MAX_ACTIVE_KEYS_PER_AGENT = 5

# --- JWT ---
JWT_ISSUER = "aeralogin.com"
JWT_ALG = "HS256"
JWT_TYP = "agent"

# --- Canonical payload allowed-keys per protocol ---
AGENT_AUTH_KEYS = frozenset({
    "protocol", "version", "agent_id", "key_id",
    "challenge_id", "challenge", "aud", "issued_at", "expires_at",
})
AGENT_MESSAGE_KEYS = frozenset({
    "protocol", "version", "message_id",
    "sender_agent_id", "sender_key_id", "receiver_agent_id",
    "issued_at", "expires_at", "content_hash",
})
OWNER_CHALLENGE_KEYS = frozenset({
    "protocol", "version", "owner_wallet", "agent_id", "operation",
    "challenge_id", "challenge", "expires_at", "domain",
})

OWNER_DOMAIN = "aeralogin.com"

# --- Agent enrollment / runtime pairing ---
# The runtime proves possession of the private key it is enrolling by signing
# this payload. Separate protocol string => a PoP signature can never be
# replayed as an auth or message signature, and vice versa.
PROTO_AGENT_ENROLL = "aera-agent-enroll"
AGENT_ENROLL_KEYS = frozenset({
    "protocol", "version", "enrollment_id", "public_key", "domain",
})
ENROLLMENT_TTL_SECONDS = 15 * 60
MAX_OPEN_ENROLLMENTS_PER_OWNER = 5
#: Prefix of the owner-challenge agent_id that binds a `register` signature to
#: exactly one enrollment. Such a challenge can never be consumed by the plain
#: /register endpoint (which requires agent_id NULL) and vice versa.
ENROLLMENT_CHALLENGE_PREFIX = "enrollment:"
