# AEraLogIn Trust Infrastructure for the Agentic Web

**Architecture Whitepaper — Version 1.0**  
**Status:** Living architecture document  
**Last reviewed:** September 2026

## 1. Abstract

AI agents are evolving from isolated assistants into software entities that can discover other agents, delegate tasks, access tools, interact with APIs and execute actions on behalf of humans and organizations.

This creates an identity and trust problem. Traditional authentication can identify an account, application or user without proving which agent runtime actually executed an operation.

AEraLogIn addresses this by separating:

- Human identity
- Agent identity
- Runtime identity
- Capability authorization
- Agent-to-agent communication
- Tool access
- Action provenance

AEraLogIn is intentionally designed as a trust layer around open protocols rather than as a replacement for them.

The target trust chain is:

**Human → Agent → Runtime → Capability → Action**

For delegated multi-agent workflows:

**Human → Agent A → Runtime A → Agent B → Runtime B → Tool → Action**

## 2. Architectural Principle

> **Identity, execution and authorization must be independently verifiable.**

Authentication answers **who are you?**

Authorization answers **what are you allowed to do?**

Runtime verification answers **which execution environment actually performed the action?**

Provenance answers **how did this action originate and which chain of delegation led to it?**

These concerns should remain separate.

## 3. AEraLogIn Layers

    Human Identity
          |
          v
    Agent Identity
          |
          v
    Runtime Identity
          |
          v
    Cryptographic Proof
          |
          v
    Authorization / Capabilities
          |
          +----------------+
          |                |
          v                v
         A2A              MCP
          |                |
          v                v
       Agents             Tools
          |                |
          +-------+--------+
                  |
                  v
                Action
                  |
                  v
              Provenance

## 4. Human Identity

AEraLogIn currently uses wallet-based authentication and an on-chain identity layer. The human-controlled identity is the root from which agents can be registered and managed.

The agent identity must remain distinct from the underlying AI model provider.

## 5. Agent Identity

An Agent receives an independent identity represented by an agent_id and associated lifecycle state.

The identity belongs to the agent as a software actor, not to a particular LLM.

This permits a runtime to change its underlying model without forcing the agent identity to change.

## 6. Runtime Identity

The runtime is the software process that actually executes an agent.

AEraLogIn currently uses an Ed25519 key generated locally by the Agent Runtime. The private key remains in the runtime. AEraLogIn receives and registers the public key.

This creates a cryptographic binding between an agent and a registered execution runtime.

## 7. Runtime Authentication

The AEra Gateway can verify that a response corresponds to an active registered runtime key.

The resulting chain is:

Agent
  -> Registered Runtime
  -> Public Key
  -> Cryptographic Signature
  -> Gateway Verification

Key rotation and revocation are part of the runtime lifecycle.

## 8. A2A Integration

A2A is treated as the communication layer for agent-to-agent interoperability.

AEraLogIn should not replace A2A. Instead, AEraLogIn can provide identity, runtime authentication and authorization context around A2A communication.

The current A2A protocol release is 1.0.1. The A2A roadmap continues work toward 1.1, bidirectional streaming, richer multi-turn workflows and validation tooling.

AEraLogIn therefore follows a compatibility-first strategy:

- Maintain A2A 1.0.x interoperability.
- Track 1.1 development.
- Keep protocol-specific logic behind an adapter.
- Avoid coupling the AEra core to a single A2A implementation.

## 9. MCP Integration

MCP is treated as the agent-to-tool and agent-to-context integration layer.

The current MCP specification is 2026-07-28. It introduced a stateless protocol core, per-request metadata, protocol version negotiation and significant transport/authentication changes.

AEraLogIn should therefore isolate MCP behind an adapter:

AEra Identity
     |
Agent Identity
     |
Runtime Identity
     |
Authorization
     |
MCP Adapter
     |
MCP Server / Tool

The AEra identity core must not depend on MCP session semantics.

## 10. Agent Identity, DID and ANP

The ecosystem is also developing explicit agent-identity mechanisms, including DID-based approaches and HTTP-level cryptographic authentication.

AEraLogIn should support interoperability with such systems without making one DID method a permanent architectural dependency.

Potential adapters include:

- did:wba
- did:web
- did:webvh
- HTTP Message Signatures
- OAuth/OIDC
- Enterprise workload identity

These should be treated as identity/authentication profiles around the AEra core.

## 11. Delegation

Multi-agent systems require restricted delegation.

Example:

Human
  |
Agent A
  |
delegates limited capability
  |
Agent B
  |
Tool

Delegation should carry, where applicable:

- issuer
- subject
- audience
- capability
- scope
- expiry
- nonce
- parent task
- provenance
- cryptographic proof

Agent A must not automatically transfer all of its authority to Agent B.

## 12. Capability Authorization

AEraLogIn should separate identity from permissions.

Example:

maintenance-agent-01

read.machine.status       ALLOWED
read.temperature          ALLOWED
read.cpu                  ALLOWED
restart.machine           DENIED
modify.configuration      DENIED
download.firmware         DENIED

This becomes especially important in enterprise and industrial environments.

## 13. Provenance

A mature AEraLogIn deployment should be able to represent an auditable action chain:

Human
  |
authorized
  v
Agent A
  |
delegated
  v
Agent B
  |
runtime authenticated
  v
Runtime B
  |
capability verified
  v
MCP Tool
  |
action executed
  v
Result

The goal is not simply logging. The goal is verifiable provenance.

## 14. Enterprise and Industrial Use

A machine-monitoring scenario illustrates the intended architecture.

Instead of exposing machine telemetry broadly:

Machine
  |
Always-online API
  |
Network access

a controlled agent boundary can be used:

Machine
  |
Local Agent Runtime
  |
AEra Identity
  |
Capability Verification
  |
Authorized Request
  |
Machine Data

Potential applications include:

- industrial machines
- server monitoring
- enterprise databases
- internal documents
- maintenance systems
- remote diagnostics
- controlled software deployment

## 15. Protocol Independence

AEraLogIn should remain protocol-neutral at its core.

                    AEra Core
                       |
        +--------------+--------------+
        |              |              |
       A2A            MCP            ANP
        |              |              |
     Agents          Tools        Networks

Additional adapters can be added for OAuth/OIDC, SPIFFE/workload identity, DID methods and future agent-identity standards.

## 16. Strategic Position

AEraLogIn should not become:

- another LLM framework
- another orchestration platform
- another MCP implementation
- another A2A replacement
- another model provider
- a closed proprietary agent network

Its architectural purpose is narrower:

> **Establish and verify trust between humans, agents, runtimes and actions across interoperable agent protocols.**

## 17. Evolution Strategy

The architecture follows four rules:

1. **Standards first** — prefer open protocols and published specifications.
2. **Adapters over forks** — integrate evolving standards without changing the AEra core unnecessarily.
3. **Cryptographic proof over claims** — distinguish declared identity from verified execution.
4. **Version-aware design** — protocol versions, capability negotiation and migration paths are first-class concerns.

## 18. Long-Term Vision

The long-term target is:

**Human → Trusted Agent → Trusted Runtime → Authorized Capability → Verifiable Action**

and, for multi-agent systems:

**Human → Agent A → Runtime A → Agent B → Runtime B → Tool → Action**

Every relevant step can carry identity, authorization and provenance.

That provides a foundation for an agentic internet in which autonomous software can interact without every participant being locked to the same vendor, model, framework or platform.

**AEraLogIn — Identity for humans. Identity for agents. Proof for runtimes. Authorization for actions.**
