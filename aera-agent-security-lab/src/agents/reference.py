"""Reference material handed to the agents as the basis for their analysis.

Every statement below was verified against the deployed implementation during
the API-discovery and security-lab phases (see
`docs/AEra-agent-api-discovery.md` and `docs/AEra-agent-security-test-report.md`).

Providing verified facts is what lets the models produce a grounded analysis
instead of refusing to speculate about an unknown system.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

AERA_REFERENCE = """\
AEra Agent Identity Layer -- verified facts from the deployed implementation
(https://aeralogin.com, FastAPI router prefix /api/agents, 14 endpoints).

IDENTITY
- agent_id format: did:aera:agent:<32 hex>; key_id: aera-key-<24 hex>.
- Agent keys are Ed25519, encoded "ed25519:<base64url-nopad(32B)>".
- Max 5 active keys per agent. Keys can be added, rotated and revoked.

OWNER AUTHORISATION (lifecycle: register, key_add, key_rotate, key_revoke,
agent_revoke, capabilities)
- POST /api/agents/owner-challenge issues a single-use challenge (TTL 120 s)
  bound to (owner_wallet, operation, agent_id).
- The owner signs canonical JSON over
  {protocol=aera-owner-challenge, version=1, owner_wallet, agent_id, operation,
   challenge_id, challenge, expires_at, domain=aeralogin.com}
  using EIP-191 personal_sign (EIP-1271 supported for contract wallets).
- Consumption is atomic: UPDATE ... WHERE consumed_at IS NULL with a
  rowcount != 1 guard.

AGENT AUTHENTICATION
- POST /api/agents/{agent_id}/challenge issues a single-use challenge (TTL 60 s)
  bound to (agent_id, key_id, aud).
- The agent signs canonical JSON over
  {protocol=aera-agent-auth, version=1, agent_id, key_id, challenge_id,
   challenge, aud, issued_at, expires_at} with Ed25519.
- POST /api/agents/{agent_id}/authenticate validates in this order:
  challenge unconsumed+unexpired -> agent_id match -> key_id match ->
  aud match -> agent active -> key active -> signature -> atomic consumption.
  The JWT is issued only after the commit.

AGENT JWT
- HS256 with AGENT_JWT_SECRET (server-side only, >=32 chars, must differ from
  OAUTH_JWT_SECRET and TOKEN_SECRET, fail-fast on default values).
- Claims: iss=aeralogin.com, sub=agent_id, aud, iat, exp (iat+900), jti,
  typ=agent, key_id, owner_wallet (lowercase), capabilities (sorted).
- Two audiences: aera-agent-api and aera-agent-relay. They are NOT
  interchangeable.
- Every jti is persisted in table agent_jti together with its aud.
- Verification: HMAC -> required claims -> typ -> jti known -> jti active ->
  DB agent_id matches sub -> DB key_id matches -> DB aud matches JWT aud
  (audience-pivot defence) -> agent active -> key active -> owner_wallet
  matches -> JWT capabilities are a subset of server capabilities.

A2A RELAY
- POST /api/agents/messages requires a JWT with aud=aera-agent-relay and the
  capability agent.communicate.
- The signed payload must contain EXACTLY these keys:
  {protocol=aera-agent-message, version=1, message_id, sender_agent_id,
   sender_key_id, receiver_agent_id, issued_at, expires_at, content_hash}.
- content_hash = "sha256:" + base64url-nopad(sha256(content)).
- Checks: exact key set -> payload.sender_agent_id == jwt.sub
  (sender_jwt_mismatch) -> expires_at in the future (expired_message, TTL 300 s)
  -> canonical JSON -> sender agent active -> receiver agent active ->
  sender key active -> Ed25519 signature -> INSERT into agent_message_ids with
  primary key (receiver_agent_id, message_id), a duplicate raising
  message_replay.
- The JWT and the Ed25519 payload signature are verified INDEPENDENTLY.

CANONICAL JSON (restricted profile)
- Keys must match ^[A-Za-z_][A-Za-z0-9_]*$ and belong to a per-protocol
  allowlist; unknown keys raise an error.
- Keys sorted by UTF-16 code point; values limited to str (NFC-normalised),
  int (|v| <= 2^53-1), bool, or a flat list thereof. No null, no floats, no
  nested objects.

KNOWN LIMITATION M-01 (important)
- POST /api/agents/messages VERIFIES and NOTARISES the message envelope. It
  does NOT transport, deliver or store the message content. MessageRequest has
  an optional "content" field that is never read and never persisted, and there
  is no inbox, polling or push endpoint.
- Consequence: content must travel out-of-band, and the receiving agent must
  independently recompute content_hash from the bytes it actually received and
  verify the Ed25519 signature locally. An attack that swaps the content while
  leaving the envelope and signature intact is invisible to AEra by
  construction.

MEASURED SECURITY RESULTS (live against production)
- 14 of 14 attack scenarios blocked: replay, content tampering, content_hash
  manipulation, sender spoofing, key-id spoofing, JWT/sender mismatch, receiver
  manipulation, expired message, 10 invalid-JWT variants, cross-audience JWT,
  5 JWT claim mutations, forged response, response replay, and 10 signed-field
  mutations.
- 12 were rejected by AEra itself; 2 (content tampering, and the delivery half
  of a forged response) can only be caught by receiver-side verification,
  because of M-01.
- Revocation cascades: revoking an agent revokes its keys and all active JTIs;
  previously issued JWTs then return 401.

OPEN ITEMS RECORDED DURING HARDENING
- No public token-revocation endpoint for OAuth clients; no lifecycle garbage
  collection for expired JTI rows.
- Legacy OAuth code used sha256(data+secret) rather than HMAC in one place, and
  client secrets are stored as unsalted SHA-256.
- Historical process logs may still contain JWT prefixes (fixed going forward).
"""


def load_context(path: Optional[str] = None, *, max_chars: int = 12000) -> str:
    """Return reference material, optionally overridden by a file."""
    if path:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
        return text[:max_chars]
    return AERA_REFERENCE
