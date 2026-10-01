# Phase 0.1 — File-by-File Migration Matrix

**Status:** Planning only  
**Scope:** Human Identity / Multi-Usage Access migration  
**Implementation impact:** None — this document does not change runtime or security behavior.

## Purpose

Phase 0.1 maps the existing repository file by file before implementation begins.

The goal is to introduce provider-neutral Human Identity and a separate Agent Hub without weakening the existing wallet-based Agent Identity, Runtime Identity, or A2A security model.

The migration must **not** become a global `owner_wallet` → `owner_id` replacement. `owner_wallet` has different meanings in different subsystems and must only be migrated where it represents Agent ownership.

## Core architectural rule

The target trust chain is:

```
Human Authentication
        |
        v
AEra Human Identity
        |
        v
Owner Authorization
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
Capability Authorization
        |
        +---- A2A
        |
        +---- MCP
```

Authentication providers are:

- Wallet / SIWE
- Google OAuth/OIDC
- GitHub OAuth/OIDC

They are authentication mechanisms, not Agent or Runtime credentials.

---

# 1. Migration legend

| Symbol | Meaning |
|---|---|
| 🟢 | Keep unchanged |
| 🔵 | Adapt / extend |
| 🟡 | Compatibility migration |
| 🔴 | Security-sensitive refactor |
| ⚪ | Documentation / tests / follow-up |

---

# 2. Agent Core

| File | Current role | Migration action | Phase | Risk |
|---|---|---|---:|---|
| `agent/repository.py` | Agent, enrollment and challenge DB schema | Add Human Identity / owner mapping while retaining `owner_wallet` during migration | 1–2 | High |
| `agent/models.py` | Agent request/response models | Abstract owner authorization; retain compatibility fields during transition | 3 | High |
| `agent/enrollment.py` | Runtime enrollment and Agent creation | Bind enrollment to Human Owner while preserving existing wallet behavior | 2–3 | High |
| `agent/owner_challenges.py` | Cryptographic owner authorization | Introduce provider-neutral Owner Authorization abstraction | 3 | Very High |
| `agent/routes.py` | Agent API and owner challenge endpoints | Resolve owner from authenticated Human Identity and enforce authorization | 3 | Very High |
| `agent/tokens.py` | Agent JWT issuance/verification | Keep provider-independent; do not turn OAuth tokens into Agent credentials | 3 | High |
| `agent/constants.py` | Protocol constants | Version/extend owner authorization protocol only when implementation is ready | 3 | Medium |
| `agent/interactions.py` | Agent ownership and interaction checks | Move ownership lookup toward `owner_id` | 2 | High |
| `agent/crypto.py` | Cryptographic primitives | Keep unchanged | — | Low |
| `agent/errors.py` | Agent errors | Add owner-authorization errors only if required | 3 | Low |

## Hard boundary

The Runtime must not know whether its Human Owner authenticated with Wallet, Google or GitHub.

The existing chain remains:

```
Runtime
  -> Ed25519 key
  -> Agent authentication
  -> Agent JWT
```

It must not become:

```
Google token
  -> Agent JWT
```

---

# 3. New Human Identity layer

A new provider-neutral identity package should be introduced rather than adding all new logic to `server.py`.

Suggested structure:

```
identity/
├── models.py
├── repository.py
├── providers.py
├── sessions.py
└── authorization.py
```

## `identity/models.py`

**New.**

Defines concepts such as:

- `HumanIdentity`
- `IdentityProvider`
- `IdentityBinding`
- `OwnerAuthorization`

## `identity/repository.py`

**New.**

Owns persistence for:

- `human_identities`
- `human_identity_providers`

Potential future table:

- `agent_owner_bindings`

## `identity/providers.py`

**New.**

Provider adapters:

- WalletProvider
- GoogleProvider
- GitHubProvider

The provider layer maps:

```
Provider credential
       ↓
Human Identity
```

It must never map:

```
Provider credential
       ↓
Agent
```

## `identity/authorization.py`

**New.**

Defines the provider-independent owner authorization interface.

Initial implementations:

- WalletAuthorization
- WebAuthnAuthorization

---

# 4. Human Identity database

The target model is:

```
human_identities
----------------
human_id
status
created_at
updated_at
```

and:

```
human_identity_providers
------------------------
id
human_id
provider
provider_subject
email
email_verified
created_at
last_login_at
```

The provider subject must be the stable provider identifier. Email must not become the primary identity key.

Existing wallet identities are mapped into this layer first.

---

# 5. Agent ownership migration

Current model:

```
Agent
  |
  +-- owner_wallet
```

Target model:

```
Agent
  |
  +-- owner_id
       |
       +-- AEra Human Identity
             |
             +-- wallet
             +-- google
             +-- github
```

During migration, keep:

```
owner_id
owner_wallet   # compatibility / audit
```

Do **not** immediately drop `owner_wallet`.

Existing wallet-owned Agents must map to the new Human Identity without creating duplicate Agents.

---

# 6. `server.py`

`server.py` currently contains several unrelated responsibilities.

### Keep unchanged

- Existing AEra OAuth provider functionality
- `/oauth/authorize`
- `/oauth/complete`
- `/oauth/token`
- `/api/v1/verify`

These endpoints represent:

```
External Application
        ↓
AEra OAuth
```

They are not Google/GitHub Human Login.

### Adapt later

- Dashboard session creation
- Agent dashboard APIs
- Human Identity resolution

### Add later

- Google OIDC login
- GitHub OAuth/OIDC login

New authentication code should preferably be routed into the Human Identity layer rather than becoming more monolithic code inside `server.py`.

---

# 7. Existing AEra OAuth subsystem

The following remain independent:

- `oauth_clients`
- `oauth_codes`
- `oauth_sessions`
- existing OAuth endpoints
- OAuth client tests

This subsystem is an OAuth Provider for third-party applications.

It must not be confused with:

- Google Login
- GitHub Login
- Human Identity
- Agent Identity

No global OAuth migration is required.

---

# 8. Existing Web3 dashboard

## `user-dashboard.html`

Role after migration:

**AEra Core / Web3 Dashboard**

Keep Web3-specific functionality here:

- Wallet/SIWE
- Identity NFT
- Resonance
- Web3/community functionality

The dashboard should not become a combined:

```
Wallet + Google + GitHub + NFT + Resonance + Agent + Runtime + A2A + MCP
```

application.

Instead, it should provide an entry point to the Agent Hub.

---

# 9. New Agent Hub

Create a new provider-neutral dashboard, initially:

```
agent-dashboard.html
```

and potentially later:

```
/agents
```

The Agent Hub is the main interface for:

- Human Identity
- Agents
- Runtime enrollment
- Runtime status
- Agent keys
- Capabilities
- Owner authorization
- A2A
- MCP

Google and GitHub users primarily enter through this surface.

Wallet users may use it as well.

There must be **one Agent system**, not separate Google, GitHub and Wallet Agent systems.

---

# 10. `aera-agents.js`

Current API separation:

```
/api/agents
/api/dashboard/agents
```

This boundary should remain.

Adapt the UI so it does not treat the wallet address as the primary Agent identity.

The frontend should request operations such as:

```
Create Agent
List Agents
Revoke Agent
Rotate Key
```

The server resolves the authenticated Human Owner.

Do not trust a client-supplied `owner_wallet` or future `owner_id`.

---

# 11. `aera-agent-enroll.js`

Keep the Runtime enrollment flow:

```
Dashboard
   ↓
Enrollment Code
   ↓
Runtime
   ↓
Ed25519 Key
   ↓
Proof of Possession
   ↓
Owner Authorization
   ↓
Agent
```

Only the final owner authorization abstraction changes.

The Runtime private key must remain entirely local to the Runtime.

---

# 12. Agent Runtime

## `agent_runtime/*`

**Do not migrate in Phase 0.1–3 unless a test demonstrates a concrete dependency.**

Keep unchanged:

- Ed25519 key generation
- private key handling
- enrollment CLI
- Runtime authentication
- Runtime signing
- Agent JWT consumption
- key rotation
- revocation
- runtime internal secret

The Runtime is intentionally Human-Provider agnostic.

---

# 13. A2A Gateway

## `a2a_gateway/credentials.py`

Keep the external peer credential model.

Internal ownership lookup may eventually move from:

```
agents.owner_wallet
```

to:

```
agents.owner_id
```

but the external peer must never receive Human Provider information.

An external peer must not learn:

- Wallet
- Google
- GitHub
- Human Identity identifiers

## `a2a_gateway/routing.py`

Keep provider-independent.

The Gateway should reason about:

- Agent
- Runtime
- key state
- capabilities
- authorization
- peer identity

not Human Login Provider.

## `a2a_gateway/card.py`

Keep unchanged.

Agent Cards must not publish:

- owner wallet
- Human Identity
- OAuth tokens
- internal credentials

## `a2a_gateway/trust.py`

Only adapt if internal Agent ownership queries require `owner_id`.

---

# 14. Documentation

## `docs/AGENT_IDENTITY.md`

Update only after the implementation exists.

Current wallet-specific owner challenge documentation must eventually describe the provider-neutral Owner Authorization model.

## `docs/agent-api.html`

Update after implementation.

The current:

```
owner_wallet
owner_challenge_id
owner_signature
```

model becomes an abstraction around Owner Authorization.

## `docs/A2A_PEER_CREDENTIALS.md`

Keep the external protocol unchanged.

Only internal ownership examples should be updated.

## `docs/ROADMAP.md`

Already updated for this architecture.

## `docs/WHITEPAPER.md`

Already updated conceptually; final implementation details should be added only after implementation.

---

# 15. Tests

The current Agent security test suite is a major asset and must remain green throughout the migration.

## Existing tests to extend

- `tests/agent/test_agent_enrollment.py`
- `tests/agent/test_dashboard_agents.py`
- `tests/agent/test_agent_layer.py`
- `tests/agent/test_jti_binding.py`
- `tests/agent/test_a2a_credentials.py`
- `tests/agent/test_a2a_gateway.py`
- `tests/agent/test_a2a_trust.py`
- `tests/agent/testclient.py`

## New test package

Create:

```
tests/identity/
├── test_human_identity.py
├── test_wallet_provider.py
├── test_google_provider.py
├── test_github_provider.py
├── test_identity_linking.py
├── test_owner_authorization.py
├── test_webauthn.py
└── test_identity_session.py
```

---

# 16. Security Lab

The existing:

```
aera-agent-security-lab/
```

must remain focused on Agent/Runtime/A2A security.

Later extend it with:

- stolen Human session
- Google identity confusion
- GitHub identity confusion
- provider linking attacks
- Owner Authorization replay
- cross-Human Agent access
- cross-provider privilege escalation

Do not weaken existing mutation/security checks.

---

# 17. Live E2E tools

The following currently use explicit wallet-based Agent ownership:

- `tools/enrollment_live_e2e.py`
- `tools/runtime_live_e2e.py`
- `tools/release_live_e2e.py`
- `tools/agent_live_negative.py`
- `tools/live_check_a2a_credentials.py`
- `tools/live_check_a2a_trust.py`
- `tools/live_check_a2a_required_policy.py`

Keep them unchanged during the first migration stages.

They are valuable regression tests for the existing wallet security model.

Add new Human Identity E2E tests alongside them rather than replacing the old tests immediately.

---

# 18. Security-sensitive fields

The following current security bindings must not simply disappear:

```
owner_wallet
owner_challenge_id
owner_signature
agent_id
key_id
jti
aud
sub
```

They must be replaced only by an equivalent or stronger binding.

For example:

```
Human Identity
     +
Owner Authorization
     +
Agent ID
     +
operation-bound challenge
```

must continue to prevent:

- cross-owner access
- replay
- authorization substitution
- identity confusion
- capability escalation

---

# 19. Migration order

The implementation should follow this sequence:

```
Phase 1
Human Identity foundation
        ↓
Phase 2
Wallet → Human Identity migration
        ↓
Phase 3
Provider-neutral Owner Authorization
        ↓
Phase 4
Agent Hub
        ↓
Phase 5
Google OIDC
        ↓
Phase 6
GitHub OAuth/OIDC
        ↓
Phase 7
Account Linking
        ↓
Phase 8
Documentation / cleanup / deprecation
```

---

# 20. First implementation boundary

The first code change should be limited to:

1. Add Human Identity models.
2. Add Human Identity repository.
3. Add database tables.
4. Map existing wallet users to Human Identities.
5. Keep existing wallet authentication behavior.
6. Keep existing Agent behavior.
7. Keep Runtime unchanged.
8. Keep A2A unchanged.
9. Keep AEra OAuth provider unchanged.
10. Require all existing Agent/security tests to remain green.

Google and GitHub should **not** be implemented in Phase 1.

This proves that the new identity abstraction can coexist with the existing production security model before introducing additional providers.

---

# 21. Hard migration rule

> No existing security control may become weaker as a result of adding a new Human Authentication provider.

In particular, this must never become:

```
Google Login
    ↓
Dashboard JWT
    ↓
Delete Agent
```

It must remain:

```
Google Login
    ↓
AEra Human Identity
    ↓
Owner Authorization
    ↓
Delete Agent
```

The same applies to GitHub.

---

# 22. Final target architecture

```
                    AEraLogIn
                        |
          +-------------+-------------+
          |                           |
   Human Authentication        Existing AEra OAuth
          |                           |
    +-----+-----+                     |
    |     |     |                     |
 Wallet Google GitHub                 |
    |     |     |                     |
    +-----+-----+                     |
          |                           |
          v                           |
   AEra Human Identity               |
          |                           |
       owner_id                       |
          |                           |
          v                           |
   Owner Authorization                |
          |                           |
          v                           |
    Agent Registry                    |
          |                           |
          v                           |
    Runtime Registry                  |
          |                           |
          v                           |
    Cryptographic Proof               |
          |                           |
     +----+----+                      |
     |         |                      |
    A2A       MCP                     |
```

The key principle is:

**Two user interfaces, one Human Identity layer, one Agent/Runtime trust core.**

The project is not being migrated from Web3 to Web2.

It is being extended from wallet-only Human Authentication to provider-neutral Human Identity while preserving the cryptographic Agent and Runtime trust boundaries.
