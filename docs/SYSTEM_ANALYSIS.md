# AEraLogIn System Analysis
## Current A2A-First Implementation

**Analysis baseline:** `main` after the A2A-first reorientation, October 2026  
**Repository:** `koal0308/AEraLogin-Human-and-A2A`

---

## 1. Purpose

This document describes the current implementation as it exists after the project's architectural reorientation.

The repository is now best understood as a system centered on:

```text
Agent → Runtime → Authorization → A2A → Execution → Evidence
```

Human identity remains an ownership and governance subsystem.

---

## 2. System Boundaries

The implementation contains several deliberately separate trust domains:

| Domain | Principal | Main proof / credential | Boundary |
|---|---|---|---|
| Human ownership | Human owner | dashboard session / owner signature | owner-controlled lifecycle |
| Agent identity | AEra Agent | Agent JWT + Ed25519 identity | agent API |
| Runtime execution | Agent Runtime | locally held Ed25519 key | runtime execution boundary |
| External A2A | External peer | opaque peer credential | inbound `/api/a2a` |
| Gateway ↔ runtime | Local gateway channel | internal shared secret | host-local transport |

These credentials are not interchangeable.

A dashboard JWT is not an Agent credential.

An Agent JWT is not an external A2A peer credential.

An external peer credential is not proof that a runtime executed an action.

A runtime key is not a human ownership credential.

---

## 3. High-Level Data Flow

```text
Human / Owner
    |
    | create / enroll / authorize
    v
Agent Identity
    |
    | runtime enrollment
    v
Runtime Identity
    |
    | active key
    v
Runtime Authorization
    |
    | A2A gateway
    v
External Peer / A2A Request
    |
    v
Target Agent
    |
    v
Local Runtime
    |
    | signed response
    v
Gateway verification
    |
    v
A2A Response
    |
    v
Evidence / Audit
```

---

## 4. Agent Identity Layer

The Agent Identity subsystem is an additive security layer.

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

The implementation therefore distinguishes:

```text
JWT authentication
        ≠
message signature
        ≠
runtime execution proof
```

---

## 5. Runtime Enrollment and Key Ownership

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

---

## 6. Runtime Authentication and Execution Boundary

At runtime startup the runtime authenticates and establishes its host-local gateway channel.

During A2A execution:

1. the gateway accepts and authenticates the incoming request,
2. the gateway identifies the target agent,
3. the request is delivered to the target runtime over the configured local channel,
4. the runtime processes the request,
5. the runtime signs its response using the locally held Ed25519 key,
6. the gateway checks that the key is active and belongs to the requested agent,
7. the gateway checks the returned `agent_id` and `request_id`,
8. only a valid response is accepted.

This is the central runtime-authenticity mechanism.

The important distinction is:

> A signed runtime response establishes runtime-attributed output. It is not by itself proof of every downstream physical or business effect.

---

## 7. A2A Gateway

The public A2A surface includes:

- `GET /.well-known/agent-card.json`
- `POST /api/a2a`

The gateway is responsible for the inbound trust sequence.

Conceptually:

```text
A2A request
    ↓
Credential parsing
    ↓
Peer authentication
    ↓
Peer authorization
    ↓
Rate limiting
    ↓
Replay protection
    ↓
Target agent checks
    ↓
Runtime delivery
    ↓
Signed runtime response
    ↓
Signature + request binding verification
    ↓
A2A response
```

The gateway is therefore not just a transport proxy. It is the enforcement boundary between external A2A requests and local runtime execution.

---

## 8. External Peer Credentials

The external peer system uses an opaque credential format:

```text
aera_a2a_<cred_id>_<secret>
```

The server stores only a SHA-256 hash of the secret.

Current properties include:

- owner-authorized issuance,
- stable AEra-minted `peer_id`,
- scope by agent and skill,
- expiration,
- immediate revocation,
- rotation without requiring downtime,
- opaque authentication failures,
- per-credential rate limiting,
- replay protection at the A2A request level.

The trust sequence is explicitly split:

```text
authenticate peer
      ↓
authorize peer for target / skill
      ↓
deliver to runtime
```

A valid credential is never treated as unrestricted access.

---

## 9. Authentication Policy

The A2A peer authentication policy supports:

```
AERA_A2A_AUTH_POLICY=optional|required
```

In `optional` mode:

- no credential → anonymous request may proceed,
- valid credential → authenticated peer,
- invalid credential → authentication failure.

In `required` mode:

- no credential → rejected,
- valid credential → authenticated peer,
- invalid credential → rejected.

The Agent Card reflects the active authentication policy.

This keeps protocol interoperability explicit instead of assuming that every external peer already understands AEra-specific credentials.

---

## 10. Authorization Model

Authorization is layered rather than inferred from identity.

Current layers include:

### Agent-level authorization
Server-recorded agent capabilities and lifecycle state.

### Peer-level authorization
Scoped external peer credentials.

### Runtime-level enforcement
Only an active registered runtime key may produce an accepted runtime response for the target agent.

### Revocation
Agent and runtime key revocation propagate into the verification path.

The next authorization layer should formalize:

- runtime-scoped capabilities,
- resource-level permissions,
- tool-level permissions,
- explicit deny rules,
- time-bounded permissions,
- formal delegation.

---

## 11. Replay and Rate Limiting

Replay protection exists at multiple trust layers rather than through a single global mechanism.

The agent subsystem uses separate stores for:

- owner challenges,
- agent challenges,
- Agent JWT lifecycle,
- signed agent messages.

The A2A subsystem uses request identifiers and inbound request tracking.

Rate limiting includes global, source/network, target-agent and authenticated peer dimensions.

This separation is important because a replay-safe authentication mechanism does not automatically make the application message itself replay-safe.

---

## 12. Revocation

Revocation is an active security mechanism.

Agent/key revocation affects:

- future Agent JWT authentication,
- runtime liveness,
- A2A target delivery,
- runtime response signature acceptance.

External peer credential revocation is intentionally separate.

Revoking a peer credential does not revoke an agent.

Revoking an agent does not implicitly revoke an unrelated peer credential.

This preserves clean trust-domain boundaries.

---

## 13. Evidence and Logging

The current implementation already produces security-relevant evidence in the end-to-end path.

Evidence should be treated as a record of what the system observed or verified.

It should not be interpreted as authorization itself.

Sensitive material must not be logged, including:

- plaintext peer credentials,
- credential hashes,
- Authorization headers,
- Agent JWTs,
- JWT signing secrets,
- runtime private keys,
- provider API keys.

The future evidence model should add stable event schemas, task correlation identifiers, portable export and cryptographic verification of signed action receipts.

---

## 14. Human Identity

Human identity is deliberately secondary.

Current responsibilities are:

- ownership,
- enrollment creation,
- owner authorization,
- dashboard administration,
- governance of agents and credentials.

The current implementation's Human Identity provider is wallet-based. Provider-neutral expansion remains roadmap work.

The crucial invariant is:

> Human authentication must never become runtime authentication.

Google, GitHub, wallet or future Passkey/OIDC methods may be used for human access without changing the Agent or Runtime trust model.

---

## 15. Current Runtime Deployment Constraint

The current A2A gateway ↔ runtime channel uses an authenticated Unix domain socket.

Therefore, in the present architecture:

- the runtime can only receive gateway-delivered A2A traffic when it shares the configured host/runtime directory with the AEra server,
- enrollment and Agent JWT authentication may occur over HTTP.

This is an implementation constraint, not a conceptual limit of the trust model.

Future deployment modes may introduce remote workload identity or mutually authenticated transport without changing the core distinction between agent and runtime identity.

---

## 16. Recovery and Key Lifecycle

Implemented recovery paths include:

### Same agent identity
A new runtime key can be added to an existing agent and the lost key revoked.

### Re-enrollment
The old agent can be revoked and a new enrollment can create a new agent identity.

Not yet implemented:

- pairing-based recovery,
- pairing-based rotation for an existing agent identity.

---

## 17. Current Implemented Security Foundations

The repository contains documented implementation and live-verification tooling for:

- runtime enrollment and proof of possession,
- Ed25519 runtime identity,
- Agent JWT authentication,
- signed agent messages,
- A2A gateway security,
- external peer credentials,
- credential scope/expiry/revocation/rotation,
- replay protection,
- rate limiting,
- runtime-signed responses,
- negative security tests,
- isolated end-to-end execution checks.

These are implementation baselines documented in the repository, not claims about a currently running CI service unless a corresponding GitHub Actions result exists.

---

## 18. Not Yet Implemented

The current architecture explicitly leaves these areas for future work:

- formal runtime capability vocabulary,
- resource/tool-level authorization,
- explicit deny semantics,
- per-request proof-of-possession for every action,
- signed action receipts,
- portable evidence format,
- full delegation model,
- delegation revocation,
- stronger provenance verification,
- direct P2P transport,
- packaged runtime distribution,
- pairing-based key rotation,
- optional WebAuthn support,
- full protocol conformance tooling.

---

## 19. Architectural Invariants

The following rules should remain stable as the project evolves:

1. **Human identity does not equal agent identity.**
2. **Agent identity does not equal runtime identity.**
3. **Authentication does not equal authorization.**
4. **Authorization does not equal execution evidence.**
5. **A2A remains the interoperability protocol; AEraLogIn remains the trust layer around it.**
6. **Private runtime keys remain runtime-local.**
7. **External peer credentials remain separate from internal Agent credentials.**
8. **Revocation must fail closed.**
9. **Logs must not become a credential store.**
10. **New protocols should integrate through adapters around the trust core.**

---

## 20. Source-of-Truth Documentation

The repository now uses a clearer documentation hierarchy:

- `README.md` — public project positioning
- `docs/PROJECT_DIRECTION.md` — architectural direction
- `docs/ROADMAP.md` — priority and implementation roadmap
- `docs/WHITEPAPER.md` — architecture and trust model
- `docs/AGENT_IDENTITY.md` — Agent/Runtime identity implementation
- `docs/A2A_PEER_CREDENTIALS.md` — external peer trust implementation
- `docs/SYSTEM_ANALYSIS.md` — current system implementation analysis

Historical or legacy login-centric material should not override these documents when describing the current architecture.

---

## 21. Summary

AEraLogIn is now best understood as an execution-trust layer for agent systems:

```text
Agent
  ↓
Runtime
  ↓
Authorization
  ↓
A2A
  ↓
Execution
  ↓
Evidence
```

Human identity remains the ownership and governance path supporting that flow.

The central technical objective is therefore no longer simply:

> "Can this user log in?"

It is:

> "Can this system verify which runtime is acting, what it is authorized to do, and what evidence supports the resulting action?"
