# AEraLogIn Agent Identity Layer

Additive subsystem on top of AEraLogIn. Fully deactivatable via
`AGENT_LAYER_ENABLED=false` (default). Never touches OAuth / Wallet / NFT /
Resonance Score logic.

## Architecture

```
Owner Wallet (EOA / EIP-1271)
     │  (2)  personal_sign over restricted canonical JSON
     ▼
POST /api/agents/owner-challenge  ──┐
POST /api/agents/register           │  operations: register, key_add,
POST /api/agents/{id}/keys          │  key_rotate, key_revoke,
POST /api/agents/{id}/keys/rotate   │  agent_revoke, capabilities
DELETE /api/agents/{id}/keys/{kid}  │
DELETE /api/agents/{id}             │
PATCH /api/agents/{id}/capabilities─┘

Agent Process (holds Ed25519 private key, never sent to server)
     │
     ▼
POST /api/agents/{id}/challenge      (60 s, single-use, bound to agent+key+aud)
POST /api/agents/{id}/authenticate   → returns Agent JWT (HS256, 15 min)
POST /api/agents/tokens/revoke       (self-revoke or owner)
POST /api/agents/verify-jwt
POST /api/agents/messages            (JWT ∧ Ed25519 message signature)
POST /api/agents/interactions        (JWT + capability + Ed25519)
GET  /api/agents/{id}                (public metadata)
```

## Security Model (Spec v1.2)

| Aspect | Guarantee |
|---|---|
| Owner binding | Owner Challenge (persistent, 120 s, single-use, bound to `(owner, op, agent)`) + EIP-191 / EIP-1271 signature over canonical JSON. |
| Agent authentication | Agent Challenge (60 s, single-use, bound to `(agent_id, key_id, aud)`) + Ed25519. |
| Audience | Server-side allowlist: `aera-agent-api`, `aera-agent-relay`. Fixed per endpoint. |
| JWT | HS256, `AGENT_JWT_SECRET` ≠ `OAUTH_JWT_SECRET`. Strict `require=[exp,iat,sub,jti,aud,iss]`. `typ=agent` enforced. |
| JWT lifecycle | `agent_jti` register – verifier reads status, does NOT single-use. Reusable within `exp`. Revocation cascades on key/agent revoke. |
| Message auth | Independent Ed25519 signature over canonical message payload. JWT alone never authenticates a message. |
| Replay protection | Layer-per-layer stores: `agent_challenges`, `owner_challenges`, `agent_jti`, `agent_message_ids` – disjoint. |
| Canonical JSON | Restricted profile: fixed ASCII keys, no floats, no nulls in required fields, NFC UTF-8, codepoint-sorted keys. Python ↔ Node byte-identity verified by T-31. |

## Key Management

* Ed25519 via `cryptography` (already present, no new dependency).
* Public key encoded as `ed25519:<base64url-nopad(32B)>`.
* Signatures encoded as `base64url-nopad(64B)`.
* Max 5 active keys per agent. Rotation = INSERT new + revoke old + cascade JWT revocation, all in one SQLite `BEGIN IMMEDIATE`.
* Agent revocation cascades to all keys and all active JWTs.

## Capabilities (Spec §12.1)

`agent.authenticate`, `agent.read.profile`, `agent.communicate`,
`agent.interaction.record`. Server-issued only. JWT capabilities MUST be a
subset of server-recorded capabilities.

## Configuration

```env
AGENT_LAYER_ENABLED=false     # master switch (default off)
AGENT_JWT_SECRET=<>=32 bytes> # required if AGENT_LAYER_ENABLED=true
                              # MUST differ from OAUTH_JWT_SECRET and TOKEN_SECRET
```

Generate secret:
```
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

## Local Test Guide

```
export AGENT_LAYER_ENABLED=true
export AGENT_JWT_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
venv/bin/python -m pytest tests/agent -q
```

E2E flow: `tests/agent/test_e2e.py::test_e2e_full_flow` performs Owner →
Register A + B → Auth A/B → Message A→B → Interaction → Audit assertions →
replay rejection.

## Phase-2 – NOT implemented

* Per-request PoP nonces (`agent_pop_nonces`) – documented in Spec §9.5 as roadmap only.
* On-chain agent registry / Ed25519 precompile.
* Direct P2P agent-to-agent transport.
* Server-side EdDSA JWKS.
* Capability delegation between agents.
