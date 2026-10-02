# AEraLogIn Roadmap — A2A-First

**Strategic direction — October 2026**

> AEraLogIn is centered on agent execution, runtime authorization and A2A interoperability. Human authentication is an ownership and governance entry layer.

## North Star
Human Ownership → Agent → Runtime → Authorization → A2A → Action → Evidence

## P0 — Runtime Authorization
- [x] Runtime enrollment
- [x] Runtime-held Ed25519 keys
- [x] Runtime public-key registration
- [x] Runtime signature verification
- [x] Active-key binding
- [x] Runtime authorization checks
- [x] Negative authorization/security tests
- [ ] Formal capability vocabulary
- [ ] Runtime-scoped capabilities
- [ ] Resource/tool-level permissions
- [ ] Explicit deny rules
- [ ] Expiring permissions
- [ ] Formal revocation semantics

## P0 — A2A Interoperability
- [x] Agent Card
- [x] /.well-known/agent-card.json
- [x] A2A endpoint
- [x] A2A gateway
- [x] Runtime authentication in A2A flow
- [x] External A2A integration tests
- [ ] Automated A2A conformance suite
- [ ] Version compatibility matrix
- [ ] Streaming evaluation
- [ ] Richer multi-turn workflow evaluation

AEraLogIn complements A2A; it does not replace the protocol.

## P0 — Verifiable Execution
Target: Agent → Runtime → Signature → Authorization → A2A Request/Response → Evidence
- [x] Cryptographic runtime identity
- [x] Signed runtime responses
- [x] Gateway verification
- [x] Runtime/request binding checks
- [x] Revocation-aware runtime verification
- [ ] Standard execution event model
- [ ] Task correlation IDs
- [ ] Signed action receipts
- [ ] Response provenance
- [ ] Verification utility
- [ ] Portable evidence format
- [ ] Signed action receipts

## P1 — Agent Identity
- [x] agent_id
- [x] key_id
- [x] Owner binding
- [x] Agent lifecycle
- [x] Agent/runtime relationship
- [ ] Formal Agent Identity specification
- [ ] Identity lifecycle specification
- [ ] Key rotation/revocation specification
- [ ] Optional DID adapters

## P1 — External Peer Authorization
- [x] Peer credential model
- [x] Peer trust checks
- [x] Replay protection
- [x] Rate limiting
- [x] Agent/skill scoping
- [x] Expiration
- [x] Revocation
- [x] Rotation
- [x] Audience handling
- [x] Replay protection
- [x] Rate limiting
- [ ] Formal delegation semantics

## P1 — Delegated Agent Execution
Target: Agent A → delegated authority → Agent B → Runtime B → Action
- [ ] Issuer / subject model
- [ ] Audience restriction
- [ ] Capability scope
- [ ] Expiration
- [ ] Nonce
- [ ] Parent-task binding
- [ ] Delegation chain
- [ ] Delegation revocation
- [ ] Provenance verification

## P1 — Evidence & Auditability
Logging is an evidence layer, not an authorization mechanism.
- [ ] Structured security events
- [ ] Authorization decision records
- [ ] Runtime execution records
- [ ] Correlation IDs
- [ ] Audit export
- [ ] Evidence verification
- [ ] Privacy-aware retention rules

## P2 — Human Identity
Human login is intentionally secondary.
- [x] Existing wallet/SIWE identity
- [x] Owner binding
- [ ] Provider-neutral Human Identity
- [ ] Google/OIDC entry
- [ ] GitHub/OIDC entry
- [ ] Passkey/WebAuthn evaluation
- [ ] Account linking
- [ ] Recovery and unlinking

Human authentication providers must never become Agent or Runtime credentials.

## P2 — Protocol Adapters
### MCP
- [ ] MCP adapter
- [ ] Capability mapping
- [ ] Tool authorization mapping
- [ ] Protocol-version negotiation

### ANP / DID / HTTP signatures
- [ ] did:wba evaluation
- [ ] did:web evaluation
- [ ] did:webvh evaluation
- [ ] HTTP Message Signatures evaluation
- [ ] Adapter interfaces

### Enterprise workload identity
- [ ] OAuth/OIDC integration where appropriate
- [ ] SPIFFE/workload identity adapter
- [ ] Enterprise PKI integration
- [ ] Machine identity integration
- [ ] Offline/local deployment model

## Architectural rule
New protocols should normally become adapters around the AEra trust core, not replacements for it.

## Strategic priorities
### Now
1. Runtime Authorization
2. A2A interoperability and conformance
3. Verifiable execution
4. Agent/runtime cryptographic binding
5. External peer authorization

### Next
6. Capability authorization
7. Delegation
8. Provenance and evidence
9. Agent Identity specification

### Later
10. Human Identity expansion
11. MCP / ANP / DID adapters
12. Enterprise workload identity
13. Cross-protocol conformance tooling

**Principle:** Make the machine-to-machine trust boundary strong first. Human login should make AEraLogIn accessible, not define its architecture.