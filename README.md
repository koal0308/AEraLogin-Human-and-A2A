# AEraLogIn Human & A2A

AEraLogIn is an open-source trust and authorization layer for human-owned AI agents and their execution runtimes.

> **Repository status: Frozen Open-Source Reference Implementation**

This repository preserves the public Human & A2A reference implementation. It is no longer the active development repository. Future architectural and feature development continues separately.

## What this reference demonstrates

AEraLogIn separates four concerns that are often collapsed into a single login credential:

**Human identity → Agent identity → Runtime identity → Authorized action**

A human can own an agent without the human authentication mechanism becoming the agent's execution credential. The runtime uses its own cryptographic identity so that an external party can distinguish an authorized agent/runtime from a mere account credential.

The reference implementation includes:

- Human identity and owner binding
- Agent registration and lifecycle management
- Runtime enrollment and cryptographic runtime keys
- A2A gateway integration
- Agent Cards and peer credentials
- Capability and authorization checks
- Replay protection and rate limiting
- Security-focused negative-proof testing
- External A2A interoperability tests
- SDK and integration examples

## Architecture

```text
Human
  │
  └── owns ──► Agent
                 │
                 └── executes through ──► Runtime
                                           │
                                           ▼
                                   Cryptographic proof
                                           │
                                           ▼
                                      Authorization
                                           │
                                           ▼
                                      A2A / Action
```

The important boundary is:

- **Human authentication** establishes the human/owner context.
- **Agent identity** identifies the software actor.
- **Runtime identity** proves which registered execution runtime acted.
- **Authorization** determines what that actor is permitted to do.
- **A2A** provides interoperable agent-to-agent communication.

## Repository status

This repository is intentionally frozen.

It should be treated as:

- a public reference implementation
- a historical architecture snapshot
- a reproducible security and interoperability reference

It should **not** be treated as the source of truth for unreleased future AEraLogIn development.

## Repository structure

```text
agent/                    Agent identity and lifecycle
agent_runtime/            Runtime identity and execution
a2a_gateway/              A2A authentication, trust and routing
identity/                 Human identity and ownership
aera-agent-security-lab/  Security and external-A2A test lab
sdk/                      Integration SDK
examples/                 Integration examples
tests/                    Automated tests
docs/                     Architecture and API documentation
tools/                    Validation and test utilities
legacy/                   Historical components retained for reference
```

## Getting started

See [QUICKSTART.md](QUICKSTART.md) for the reference setup.

For architecture details:

- [Agent Identity](docs/AGENT_IDENTITY.md)
- [A2A Peer Credentials](docs/A2A_PEER_CREDENTIALS.md)
- [Whitepaper](docs/WHITEPAPER.md)
- [System Analysis](docs/SYSTEM_ANALYSIS.md)

## Testing

The reference repository contains a substantial automated test suite covering Human Identity, Agent Identity, Runtime authentication, A2A credentials and trust, replay protection, authorization and security-lab scenarios.

Run the standard suite with:

```bash
python -m pytest tests/ -q
```

The security lab has its own test suite under `aera-agent-security-lab/`.

Historical verification results describe the tested state at the time of the reference snapshot and should not be interpreted as a guarantee about a future deployment.

## Security

Security issues should be reported according to [SECURITY.md](SECURITY.md).

Do not commit private keys, API tokens, OAuth client secrets, production databases, runtime private keys or deployment credentials.

## License

AEraLogIn Human & A2A is licensed under the Apache License 2.0. See [LICENSE](LICENSE).

## Scope

This project is not an LLM, agent framework, model provider, MCP replacement, or A2A replacement.

Its purpose is to provide a trust boundary between human ownership, agent identity, runtime execution and authorization while remaining interoperable with open agent protocols.

---

**AEraLogIn — identity for humans, identity for agents, proof for runtimes, authorization for actions.**
