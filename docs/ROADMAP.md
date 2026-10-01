# AEraLogIn Roadmap

**Living roadmap — October 2026**

This roadmap is standards-driven. AEraLogIn should evolve with the agent ecosystem rather than locking its core architecture to one protocol.

## North Star

Build an interoperable trust layer connecting:

**Human → Agent → Runtime → Capability → Action → Provenance**

## Phase 0 — Multi-Usage Human Access

**Strategic next step: make AEraLogIn Human & A2A accessible to Web2 users without weakening the cryptographic trust model.**

### Human authentication profiles

- [ ] Introduce provider-agnostic Human Identity abstraction
- [ ] Add Google OAuth/OIDC login
- [ ] Add GitHub OAuth/OIDC login
- [x] Retain wallet / SIWE authentication as a first-class profile
- [ ] Map all supported human authentication methods into one AEra Human Identity
- [ ] Ensure OAuth credentials are never used as Agent or Runtime credentials
- [ ] Preserve the existing Agent → Runtime → cryptographic proof chain
- [ ] Keep A2A independent of the human login provider
- [ ] Document account linking between supported authentication profiles
- [ ] Define recovery, unlinking and identity lifecycle rules
- [ ] Add security tests for OAuth/OIDC flows, session binding and account linking

### Multi-Usage objective

A user should be able to enter AEraLogIn through:

**Google → AEra Human Identity → Agent → Runtime → A2A**

or:

**GitHub → AEra Human Identity → Agent → Runtime → A2A**

or:

**Wallet/SIWE → AEra Human Identity → Agent → Runtime → A2A**

All three paths must converge on the same AEra trust architecture.

The objective is not to replace Web3 identity. It is to remove the wallet requirement for users who do not need or want Web3 authentication.

### Architectural rule

**Human authentication is an entry layer. Agent identity and Runtime identity remain cryptographically independent.**

This phase is the next implementation priority before expanding the broader enterprise identity surface.

## Phase 1 — Standards Baseline

### A2A
- [x] Agent Card
- [x] A2A endpoint
- [x] Gateway integration
- [x] Runtime authentication in the AEra flow
- [ ] Verify full A2A 1.0.1 compatibility
- [ ] Track A2A 1.1 changes
- [ ] Add automated A2A conformance checks
- [ ] Evaluate bidirectional streaming
- [ ] Evaluate richer multi-turn workflows

### MCP
- [ ] Define AEra MCP adapter boundary
- [ ] Evaluate MCP 2026-07-28
- [ ] Support protocol-version negotiation
- [ ] Test stateless MCP transport
- [ ] Map AEra capabilities to MCP tool authorization
- [ ] Track MCP deprecations and extensions

## Phase 2 — Agent Identity

- [x] agent_id
- [x] key_id
- [x] owner binding
- [x] Ed25519 runtime keys
- [x] runtime-held private key
- [x] runtime public-key registration
- [x] key rotation/revocation
- [ ] Formal Agent Identity abstraction
- [ ] Identity lifecycle specification
- [ ] Authentication profile abstraction
- [ ] DID adapter interface

### DID / ANP interoperability

- [ ] Prototype did:wba adapter
- [ ] Evaluate did:web
- [ ] Evaluate did:webvh
- [ ] Evaluate HTTP Message Signatures
- [ ] Document trust-model differences
- [ ] Keep DID methods optional rather than hard-coded into the AEra core

## Phase 3 — Authorization

### Capability model

- [ ] Define capability vocabulary
- [ ] Agent-level capabilities
- [ ] Runtime-level restrictions
- [ ] Tool-level permissions
- [ ] Resource-level permissions
- [ ] Explicit deny rules
- [ ] Expiring permissions

### Delegation

- [ ] Agent A → Agent B delegation
- [ ] Scoped delegation
- [ ] Audience restriction
- [ ] Expiration
- [ ] Parent-task binding
- [ ] Nonce/replay protection
- [ ] Delegation revocation

## Phase 4 — Provenance

Build a verifiable action chain:

Human
  ↓
Agent
  ↓
Runtime
  ↓
Delegated Agent
  ↓
Runtime
  ↓
Tool
  ↓
Action

Tasks:

- [ ] Standard event model
- [ ] Signed runtime events
- [ ] Task correlation IDs
- [ ] Delegation chain
- [ ] Runtime attribution
- [ ] Action receipts
- [ ] Audit export
- [ ] Verification utility

## Phase 5 — Enterprise Integration

Potential adapters:

- [ ] OAuth 2.x / OIDC
- [ ] Enterprise IAM
- [ ] SPIFFE / workload identity
- [ ] Existing PKI
- [ ] Machine identity
- [ ] Local/offline deployments
- [ ] Policy engines
- [ ] Network-segment-aware authorization

Target environments:

- industrial machines
- service engineering
- enterprise IT
- monitoring
- document access
- databases
- internal APIs
- controlled software deployment

## Phase 6 — Interoperability Layer

Target architecture:

                         AEra Core
                            |
       +--------------------+--------------------+
       |          |         |        |           |
      A2A        MCP       ANP      DID       Enterprise
       |          |         |        |           |
     Agents     Tools    Networks  Identity      IAM

Principle:

**New protocols should normally become adapters, not replacements for the AEra core.**

## Phase 7 — Conformance & Release Engineering

- [ ] Automated A2A compatibility tests
- [ ] Automated MCP compatibility tests
- [ ] Runtime-signature test suite
- [ ] Key-rotation tests
- [ ] Delegation security tests
- [ ] Replay-attack tests
- [ ] Negative authorization tests
- [ ] Protocol version matrix
- [ ] Public interoperability examples
- [ ] Release compatibility matrix

## Standards Watch

The project should continuously monitor:

| Area | Watch |
|---|---|
| A2A | Releases, 1.1 roadmap, streaming, multi-turn workflows, conformance |
| MCP | Specification revisions, SDK releases, deprecations, auth changes |
| Agent Identity | W3C and other open identity work |
| ANP | did:wba, authentication and interoperability |
| DID | New methods and deployment guidance |
| HTTP | Message signatures and related authentication standards |
| OAuth/OIDC | Delegation, agent authorization and consumer authentication developments |
| SPIFFE | Workload identity for agent runtimes |
| AAIF | Governance and interoperability standards |
| Enterprise IAM | Agent/workload identity integration |

### Weekly review rule

Every standards review should answer:

1. What changed?
2. Is the change stable, draft or experimental?
3. Does AEraLogIn currently depend on the affected feature?
4. Is anything in AEraLogIn now outdated?
5. Is a migration required?
6. Should we implement an adapter?
7. Does the change create a new security requirement?
8. Does the change create a new interoperability opportunity?

## Release Gates

Before a major AEraLogIn release:

- [ ] Current A2A compatibility verified
- [ ] Current MCP compatibility assessed
- [ ] Relevant Agent Identity developments reviewed
- [ ] ANP interoperability reviewed
- [ ] Runtime key lifecycle tested
- [ ] Authorization model reviewed
- [ ] Delegation security reviewed
- [ ] Documentation updated
- [ ] Compatibility matrix updated

## Status Model

- **Stable** — safe to integrate into production architecture
- **Current** — actively maintained and suitable for implementation
- **Draft** — monitor and prototype selectively
- **Experimental** — isolate behind adapters
- **Deprecated** — migration required
- **Superseded** — do not add new dependencies

## Current Strategic Priorities

### Now
1. **Multi-Usage Human Access — Google + GitHub OAuth/OIDC while retaining Wallet/SIWE**
2. A2A 1.0.1 compatibility
3. MCP 2026-07-28 assessment
4. Agent Identity abstraction
5. Runtime identity hardening

### Next
6. did:wba / ANP adapter
7. Capability authorization
8. Delegation
9. Provenance

### Later
10. Enterprise workload identity
11. Cross-protocol trust and conformance
12. Public interoperability test suite

---

**Principle:** AEraLogIn should not chase every new protocol. It should maintain a stable trust core and continuously add well-defined interoperability adapters.

**Multi-Usage Principle:** AEraLogIn should be easy to enter and hard to impersonate. Human authentication may vary; Agent and Runtime trust must remain independently verifiable.