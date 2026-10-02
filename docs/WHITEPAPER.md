# AEraLogIn Trust Infrastructure for the Agentic Web

**Architecture Whitepaper — Version 1.0**  
**Status:** Living architecture document  
**Last reviewed:** October 2026

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

## 4. Human Identity and Multi-Usage Access

AEraLogIn supports multiple human authentication profiles while keeping human authentication separate from agent and runtime authentication.

The initial architecture uses wallet-based authentication and an on-chain identity layer. For broader adoption, AEraLogIn will add a Web2-compatible human entry layer using established OAuth/OIDC providers, initially targeting:

- Google
- GitHub

The purpose is to remove the wallet requirement for users who are not Web3-native while preserving the existing wallet-based path for users who want cryptographic wallet identity.

The target model is:

    Human Authentication
           |
      +----+----+----------------+
      |         |                |
    Google    GitHub           Wallet
    OAuth      OAuth            SIWE
      |         |                |
      +---------+----------------+
                |
                v
          AEra Human Identity
                |
                v
          Agent Registration
                |
                v
           Agent Identity
                |
                v
          Runtime Identity
                |
                v
        Cryptographic Proof

OAuth credentials must not become agent or runtime credentials.

Instead:

**OAuth / Wallet = Human authentication**

**Agent identity = Software actor identity**

**Runtime key = Cryptographic execution identity**

**Authorization = Permission to perform an action**

This preserves the core AEraLogIn trust model while making the A2A service accessible to conventional Web2 developers, enterprise users and users without prior Web3 knowledge.

### Multi-Usage Design Goal

The same AEraLogIn trust core should support different human entry methods without creating separate trust architectures.

A user authenticated through Google, GitHub or a wallet should ultimately reach the same agent registration, runtime verification and authorization model.

The A2A layer should remain agnostic to the human login provider. An external agent should verify the relevant agent identity, runtime proof, authorization context and provenance rather than depend on how the human originally authenticated.

This is a deliberate separation of concerns:

**Human login → AEra identity → Agent → Runtime → Authorization → A2A action**

The next implementation step is therefore to introduce a provider-agnostic Human Identity abstraction with Google and GitHub as initial Web2 providers, while retaining wallet/SIWE as a first-class authentication profile.

### 4.1 Dashboard separation

The human-facing application uses two UI surfaces while maintaining one trust architecture.

**AEra Core / Web3 Dashboard** remains the existing Web3-oriented interface for wallet/SIWE authentication, Identity NFT, Resonance and other Web3-specific functions.

**AEra Agent Hub** is a separate, provider-neutral interface focused on Agent registration, Runtime enrollment, A2A credentials, capabilities and authorization. Google and GitHub users enter primarily through this surface. Wallet users may also use it.

This is intentionally a UI separation, not a separation of identity or trust systems:

**AEra Core + Agent Hub → AEra Human Identity → Agent Registry → Runtime Registry → Authorization → A2A/MCP**

The Agent Hub must reuse the same backend Agent Registry and Runtime trust model. There must not be separate Google Agents, GitHub Agents and Wallet Agents.

### 4.2 Provider-neutral owner identity

The current wallet-centric implementation uses the wallet as the Agent owner reference. The target architecture introduces a canonical AEra Human Identity / `owner_id` and treats wallet, Google and GitHub as authentication profiles attached to that identity.

Existing wallet-owned Agents must remain compatible through an explicit migration or compatibility mapping. The migration must not create duplicate Agents or weaken existing owner checks.

For Google/GitHub users, OAuth/OIDC establishes the human authentication session but does not become the Agent or Runtime credential. Sensitive Agent lifecycle operations should additionally use a cryptographic owner authorization mechanism; Passkey/WebAuthn is the current candidate for evaluation.

The resulting separation is:

**Authentication provider → Human Identity → owner_id → Agent → Runtime → cryptographic proof → Authorization → Action**

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

The A2A service must remain independent of the human login provider. Google, GitHub and wallet authentication are entry mechanisms for the human identity layer; they do not define the A2A protocol identity of the agent or runtime.

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

The multi-usage human identity layer follows the same principles: authentication providers are replaceable adapters and must not become dependencies of the AEra agent/runtime trust core.

## 18. Long-Term Vision

The long-term target is:

**Human → Trusted Agent → Trusted Runtime → Authorized Capability → Verifiable Action**

and, for multi-agent systems:

**Human → Agent A → Runtime A → Agent B → Runtime B → Tool → Action**

Every relevant step can carry identity, authorization and provenance.

That provides a foundation for an agentic internet in which autonomous software can interact without every participant being locked to the same vendor, model, framework, authentication provider or platform.

**AEraLogIn — Identity for humans. Identity for agents. Proof for runtimes. Authorization for actions.**