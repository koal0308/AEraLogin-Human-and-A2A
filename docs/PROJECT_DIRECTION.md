# AEraLogIn — Project Direction

## A2A-first reorientation

Human identity remains an important ownership and governance layer, but autonomous agent execution is now the primary engineering domain.

## Core thesis

The security problem is not only **who is this?** It is also:

> **Which runtime is acting, what is it authorized to do, and can another system verify the execution boundary?**

AEraLogIn therefore separates human ownership, agent identity, runtime identity, runtime authorization, A2A communication and execution evidence.

## Priority order

### P0 — Runtime Authorization

Make the relationship between agent, runtime, credential, capability, authorization decision and revocation state explicit and cryptographically meaningful.

### P0 — A2A Interoperability

A2A is the primary interoperability surface. AEraLogIn should remain complementary to the open A2A protocol rather than creating a proprietary agent-to-agent protocol.

### P0 — Verifiable Execution

A consumer should be able to distinguish an authenticated account, an identified agent, an authorized runtime and an actual runtime-generated response.

### P1 — External Peer Authorization

External agents remain separate trust domains. Peer credentials should be scoped, expiring, revocable and bound to a stable peer identity.

### P1 — Evidence and Auditability

Security-relevant decisions and execution events should produce structured evidence suitable for inspection. Evidence must not be confused with authorization itself.

### P2 — Human Identity

Human identity remains focused on ownership, enrollment, administration, governance and optional human-facing authentication.

## Relationship to A2A

~~~text
A2A
  = communication / interoperability

AEraLogIn
  = identity / runtime authorization / execution boundary / evidence
~~~

The two should remain conceptually separate.

## Naming

The project name remains **AEraLogIn**.

For technical documentation, the expanded meaning is:

> **Agent Execution, Runtime Authorization & Logging Infrastructure**

This preserves the recognizable **LogIn** construction through **Log + Infrastructure**, while moving the meaning away from consumer login.

## Design principles

- **Separate identities:** Human, agent, runtime and external peer identities are distinct.
- **Separate credentials:** Credentials are not interchangeable across trust domains.
- **Explicit authorization:** Authentication establishes identity; authorization establishes permission.
- **Runtime-bound execution:** Where execution authenticity matters, authorization should bind to the runtime that actually executes the action.
- **Protocol interoperability:** Use A2A semantics rather than inventing a parallel communication protocol.
- **Fail closed:** An unverifiable or unauthorized request must not become an authorized execution.
- **Evidence without overclaiming:** Logs and assessments provide evidence; they do not automatically constitute authorization.

## Success criteria

The project is successfully reoriented when a developer can understand AEraLogIn without thinking of it primarily as a login system.

The first conceptual path should be:

~~~text
Agent → Runtime → Authorization → A2A → Execution → Evidence
~~~

Human identity should appear as the ownership/governance path supporting that flow.

## Migration rule

Existing human-login functionality should be preserved unless it conflicts with the runtime/A2A architecture.

The reorientation is primarily a change in architecture, documentation, terminology, roadmap and integration priorities. It does not require removing working human identity features.