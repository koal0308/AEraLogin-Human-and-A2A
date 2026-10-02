# AEraLogIn Agent Identity Layer

Core security subsystem of the A2A-first AEraLogIn architecture. It is additive to the broader trust core and remains independently disableable via `AGENT_LAYER_ENABLED=false` (default).

The Agent Identity Layer establishes the relationship between:

```text
Human Owner
    ↓
Agent Identity
    ↓
Runtime Identity
    ↓
Authorized Agent / A2A Execution
```

It does not replace A2A and it does not treat human authentication as runtime authentication.

## Position in the A2A-first architecture

The Agent Identity Layer provides agent-side identity and lifecycle primitives consumed by runtime authorization and the A2A gateway.

```text
Human Identity
   = ownership / governance

Agent Identity
   = software actor identity

Runtime Identity
   = execution identity

External Peer Credential
   = inbound A2A peer identity

Authorization
   = permission to act
```

The runtime is the execution boundary. Its private Ed25519 key remains local to the runtime; AEra verifies the corresponding registered public key when runtime-authenticated output is required.

## Architecture

```text
Owner Wallet / Human Session
     │
     │ owner authorization
     ▼
Agent lifecycle API
     │
     ├── register / key_add / key_rotate / key_revoke
     ├── agent_revoke
     └── capability changes

Agent Runtime
     │
     │ holds Ed25519 private key locally
     ▼
Agent challenge → Ed25519 → Agent JWT
     │
     ├── signed agent messages
     ├── capability checks
     └── runtime authentication
     │
     ▼
A2A Gateway
     │
     └── verifies active runtime key
```

## Security Model

The implementation intentionally keeps the following proofs separate:

| Proof | Establishes | Does not establish |
|---|---|---|
| Human owner authorization | lifecycle authority | runtime execution |
| Agent JWT | authenticated agent API principal | external peer identity |
| Agent message signature | message authenticity | physical/business effect |
| Runtime Ed25519 signature | output attributed to registered runtime key | downstream effect by itself |
| A2A peer credential | external peer identity | unrestricted access |
| Capability check | permission for a defined operation | proof that the operation succeeded |

## Agent Authentication

The owner authorizes lifecycle operations such as:

- agent registration,
- key add/rotate/revoke,
- agent revoke,
- capability changes.

Agent authentication uses:

1. a short-lived, single-use agent challenge,
2. an Ed25519 signature,
3. a server-issued Agent JWT.

The Agent JWT is audience-restricted and independently revocable.

Message-level authentication remains separate: an Agent JWT alone is not accepted as proof of a signed agent message.

## Runtime Enrollment and Key Ownership

The recommended path is:

```text
Owner creates enrollment
        ↓
short-lived single-use enrollment code
        ↓
runtime generates Ed25519 key locally
        ↓
runtime proves possession of the new key
        ↓
owner approves enrollment
        ↓
agent_id + key_id created
```

Important invariant:

> **The runtime private key never leaves the runtime.**

AEra receives the public key and proof-of-possession material.

The owner wallet/private key never enters the runtime.

Enrollment prevents reuse of a public key already registered to another active agent and uses transactional state transitions to keep claim and completion single-use.

## Runtime Lifecycle

The runtime authenticates, opens the host-local gateway channel and responds to A2A work with an Ed25519-signed response.

The gateway accepts the response only when:

- the signing key is active,
- the key belongs to the target agent,
- the returned `agent_id` matches the request,
- the returned `request_id` matches the request.

Revocation therefore reaches the execution boundary rather than stopping at account administration.

## Capabilities

Current server-issued agent capabilities include:

- `agent.authenticate`
- `agent.read.profile`
- `agent.communicate`
- `agent.interaction.record`

The roadmap extends this toward explicit runtime-scoped, resource-level and tool-level authorization.

## Enrollment Security Properties

| Property | Current implementation |
|---|---|
| Code | single-use, short-lived enrollment secret |
| Secret storage | hashed; not logged |
| Runtime key | generated locally |
| Proof of possession | Ed25519 signature bound to enrollment |
| Owner binding | owner-controlled completion |
| Replay | transactional state transitions |
| Key uniqueness | active public key cannot be registered twice |
| Rate limits | applied to enrollment operations |

## Revocation and Recovery

Key and agent revocation cascade into dependent Agent JWT state and runtime verification.

Supported recovery includes adding a new key to an existing agent and revoking the lost key.

Re-enrollment creates a new agent identity.

Not yet implemented:

- pairing-based recovery,
- pairing-based key rotation for an existing agent.

## Security Boundary

**PRIVATE KEY NEVER LEAVES THE RUNTIME.**

AEra never receives a runtime private key, seed, mnemonic or decrypted key material.

Human ownership credentials remain outside the runtime.

## Verification

The repository includes unit, negative-proof and end-to-end tooling for the Agent Identity and runtime paths. Specific historical test counts should be treated as verification records for the corresponding test run, not as permanent CI status.

## Configuration

```env
AGENT_LAYER_ENABLED=false
AGENT_JWT_SECRET=<>=32 bytes
```

When enabled, `AGENT_JWT_SECRET` must be distinct from other application secrets such as `OAUTH_JWT_SECRET` and `TOKEN_SECRET`.

## Future Work

- formal Agent Identity specification,
- formal capability vocabulary,
- runtime-scoped authorization,
- resource/tool-level permissions,
- explicit deny semantics,
- signed action receipts,
- delegation,
- stronger provenance verification,
- optional DID adapters,
- packaged runtime distribution,
- pairing-based key lifecycle,
- optional WebAuthn for human ownership.
