# AEraLogIn Trust Infrastructure for the Agentic Web

**Architecture Whitepaper — Version 2.0**  
**Status:** Living architecture document  
**Last reviewed:** October 2026

## 1. Abstract

AI agents increasingly operate as software actors that discover other agents, exchange tasks, access tools and execute actions across organizational and network boundaries.

The core trust problem is no longer only **who owns an account?** It is also:

> **Which agent is acting, which runtime is actually executing, what is that runtime authorized to do, and what evidence can another system verify?**

AEraLogIn is an open trust and authorization layer for that boundary.

The architecture separates:

- Human ownership and governance
- Agent identity
- Runtime identity
- Runtime authorization
- External peer identity
- A2A communication
- Execution evidence
- Delegation and provenance

The primary machine-to-machine trust chain is:

**Agent → Runtime → Authorization → A2A → Execution → Evidence**

The ownership chain remains:

**Human → Agent → Runtime**

AEraLogIn is deliberately complementary to open agent protocols. It does not attempt to replace A2A, MCP, identity standards or model platforms.

## 2. Core Architectural Principle

> **Identity, authorization, execution and evidence must remain independently verifiable.**

These questions are distinct:

**Identity** — Which human, agent, runtime or external peer is this?

**Authorization** — Is this principal permitted to perform this operation against this target?

**Execution authenticity** — Which registered runtime produced the response or execution artifact?

**Evidence** — What security-relevant facts can be inspected or cryptographically verified afterwards?

A valid identity must never be treated as automatic authorization.

A valid authorization decision must not be treated as proof that a specific runtime executed the action.

A log entry must not be treated as cryptographic proof merely because it exists.

## 3. AEraLogIn Trust Architecture

```text
Human / Owner
      |
      | owns / enrolls / governs
      v
Agent Identity
      |
      | bound to
      v
Runtime Identity
      |
      | authenticated execution boundary
      v
Runtime Authorization
      |
      +----------------------+
      |                      |
      v                      v
     A2A              Other Protocol Adapters
      |                      |
      v                      v
External Peers          MCP / DID / ANP /
                         Workload Identity
      |
      v
Execution / Response
      |
      v
Evidence / Provenance
```

The AEra core is the trust boundary. Protocols and human authentication methods are adapters or entry mechanisms around it.

## 4. Agent Identity

An AEra Agent is a software actor with an independent `agent_id` and lifecycle state.

The identity is not tied to a specific:

- LLM
- model provider
- machine
- process instance
- human login provider

This allows the runtime or underlying model to change without silently changing the logical agent.

Agent lifecycle operations are owner-controlled. The current implementation supports owner challenges, agent registration, key lifecycle, capability assignment and revocation.

## 5. Runtime Identity

The runtime is the execution process that actually handles agent work.

The implemented runtime model uses an Ed25519 key generated and held locally by the runtime. The private key does not leave the runtime. AEra registers the public key and verifies signatures produced by the corresponding active key.

The resulting execution boundary is:

```text
Agent
  ↓
Registered Runtime Key
  ↓
Runtime-generated signature
  ↓
Gateway verification
  ↓
Accept / reject
```

Runtime key state and agent state are revocable. Revocation propagates into the runtime authentication and A2A delivery path.

## 6. Runtime Enrollment

The recommended creation flow is runtime-first:

```text
Owner Dashboard
    ↓
Enrollment code
    ↓
Runtime generates Ed25519 key locally
    ↓
Proof of possession
    ↓
Owner approval
    ↓
Agent + Runtime registration
    ↓
Runtime starts
```

The owner does not handle the runtime private key.

The runtime does not handle the owner's wallet key.

Enrollment codes are single-use, short-lived and stored through a hashed secret representation. The submitted public key is bound to the enrollment through a proof-of-possession signature.

This establishes a concrete relationship between:

**owner authorization → agent identity → runtime key**

## 7. Runtime Authorization

Runtime authorization is the central engineering concern of the A2A-first architecture.

The system must distinguish:

1. an identified agent,
2. a registered runtime,
3. an active runtime key,
4. an authorization decision,
5. an actual runtime-generated response.

The current implementation already verifies the runtime side of the A2A path:

- the runtime authenticates with AEra,
- the runtime holds the private key,
- the gateway sends work to the target runtime,
- the runtime signs its response,
- the gateway verifies the signature,
- the key must still be active,
- the returned agent and request identifiers must match the request.

Future authorization work extends this from agent-level capability checks toward explicit runtime-scoped permissions, resources, deny rules and formal authorization semantics.

## 8. A2A as the Primary Interoperability Surface

A2A is the communication and interoperability layer.

AEraLogIn does not define a competing agent-to-agent protocol. Instead, it surrounds A2A traffic with additional trust semantics.

The current architecture exposes:

- an Agent Card,
- `/.well-known/agent-card.json`,
- an A2A gateway,
- `POST /api/a2a`,
- runtime-authenticated delivery,
- external peer credentials,
- replay protection,
- rate limiting,
- runtime-signed responses.

The conceptual separation is:

```text
A2A
  = how agents communicate

AEraLogIn
  = who / which runtime / what authorization / what evidence
```

This keeps the AEra trust core independent of the transport and protocol evolution of A2A.

## 9. External A2A Peer Trust

External agents are separate trust domains.

A peer credential proves:

> **This request is associated with peer X.**

It does not by itself prove:

> **Peer X is authorized to invoke agent Y.**

The implemented model therefore evaluates:

```text
credential
   ↓
ExternalPeerIdentity
   ↓
peer authorization
   ↓
scope checks
   ↓
rate limit
   ↓
replay guard
   ↓
runtime delivery
```

Current peer credentials are:

- opaque rather than JWT-based,
- stored server-side by secret hash,
- owner-issued,
- scoped to agents and skills,
- expiring,
- revocable,
- rotatable,
- associated with an AEra-minted stable `peer_id`.

Invalid credentials fail closed. Credential failures are deliberately collapsed into an opaque authentication error so the gateway does not become an enumeration oracle.

## 10. Capabilities and Authorization

Identity and capability are separate.

A capability is an authorization claim; it is not an identity.

The current agent layer has server-issued capabilities such as:

- `agent.authenticate`
- `agent.read.profile`
- `agent.communicate`
- `agent.interaction.record`

The current A2A peer layer additionally supports scoped agents and scoped skills.

The next architecture step is to formalize a cross-layer capability vocabulary that can express:

- agent scope,
- runtime scope,
- resource scope,
- tool scope,
- explicit deny rules,
- expiration,
- revocation,
- delegation.

## 11. Delegated Agent Execution

Multi-agent systems introduce a second authorization boundary.

The target model is:

```text
Agent A
   |
   | limited delegated authority
   v
Agent B
   |
   v
Runtime B
   |
   v
Authorized action
```

Delegation must not transfer all authority implicitly.

A future delegation model should carry, where applicable:

- issuer
- subject
- audience
- capability
- scope
- expiry
- nonce
- parent task
- delegation chain
- cryptographic proof

Delegation is intentionally separate from peer authentication.

## 12. Verifiable Execution and Evidence

AEraLogIn aims to make execution boundaries inspectable without overstating what cryptography proves.

A signed runtime response can establish that a response was produced by the holder of an active registered runtime key, subject to successful verification.

It does **not**, by itself, prove that:

- the physical world changed as requested,
- a downstream tool actually completed the action,
- a human intended the exact output,
- every intermediate system in a distributed workflow behaved correctly.

The roadmap therefore separates:

**runtime authenticity → authorization decision → execution evidence → provenance**

Future signed action receipts and portable evidence formats should add stronger, explicit semantics around completed actions.

## 13. Logging and Auditability

Logging is an evidence layer, not the authorization mechanism.

Security-sensitive records should eventually be able to represent:

- authorization decision,
- runtime identity,
- target agent,
- peer identity,
- request/task correlation,
- capability evaluation,
- execution result,
- revocation state,
- timestamps,
- provenance relationships.

Sensitive credentials and private keys must never enter logs.

The existing peer credential implementation explicitly excludes plaintext credentials, credential hashes, authorization headers, JWT secrets, private keys and provider API keys from logs and audit records.

## 14. Human Identity

Human identity is intentionally secondary in the A2A-first architecture.

Its responsibilities are:

- ownership,
- enrollment approval,
- administration,
- lifecycle governance,
- optional human-facing authentication.

Human authentication is not runtime authentication.

Wallet, OAuth/OIDC, Passkeys or other future providers may establish a human session, but none of them should become the credential proving that a runtime executed an A2A action.

The existing Human Identity layer therefore remains a governance subsystem rather than the architectural center.

## 15. Protocol Adapters

The trust core should remain protocol-neutral.

```text
                    AEra Trust Core
                          |
        +-----------------+------------------+
        |                 |                  |
       A2A               MCP           Identity / HTTP
        |                 |             / Workload
      Agents            Tools             Identity
```

Potential adapter areas include:

- MCP
- DID-based identities
- HTTP message signatures
- enterprise workload identity
- OAuth/OIDC for human ownership
- future agent identity standards

New protocols should normally be adapters around the AEra trust core, not replacements for it.

## 16. Security Boundaries

The current architecture intentionally keeps these credentials separate:

| Trust domain | Credential / proof | Purpose |
|---|---|---|
| Human owner | dashboard / owner authorization | governance and lifecycle |
| Agent | Agent JWT + Ed25519 identity | agent API authentication |
| Runtime | runtime-held Ed25519 key | execution authenticity |
| External A2A peer | opaque peer credential | inbound peer identity |
| Internal gateway-runtime channel | shared internal secret | local transport authentication |

A credential from one domain must not silently satisfy another domain's authorization requirement.

This is a core security invariant.

## 17. Current Strategic Position

AEraLogIn is not intended to become:

- an LLM or model provider,
- an agent orchestration framework,
- an A2A replacement,
- an MCP replacement,
- a closed agent network,
- a consumer login product.

Its purpose is narrower:

> **Provide a verifiable trust boundary between agent identity, runtime execution, authorization and interoperable agent actions.**

## 18. Long-Term Target

The intended trust path is:

**Human Ownership → Agent → Runtime → Authorization → A2A → Action → Evidence**

For multi-agent execution:

**Human → Agent A → Runtime A → Delegation → Agent B → Runtime B → Authorized Action → Evidence**

The long-term goal is not merely to identify agents. It is to make the execution boundary itself a first-class security primitive.

**AEraLogIn — Agent Execution, Runtime Authorization & Logging Infrastructure**

---

## 19. Implementation Status

Implemented foundations include:

- runtime enrollment,
- runtime-held Ed25519 keys,
- agent identity and lifecycle,
- runtime signature verification,
- revocation,
- A2A Agent Card and gateway,
- external A2A peer credentials,
- credential scope, expiry, rotation and revocation,
- replay protection,
- rate limiting,
- signed runtime responses,
- structured trust evidence in the existing end-to-end path.

Major future work includes:

- formal runtime capability vocabulary,
- resource/tool-level authorization,
- explicit deny semantics,
- signed action receipts,
- portable evidence verification,
- delegation,
- stronger provenance semantics,
- protocol conformance tooling,
- optional human identity provider expansion.
