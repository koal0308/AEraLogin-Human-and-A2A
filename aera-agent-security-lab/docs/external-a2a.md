# External A2A Interoperability

This document describes how the AEra Agent Runtime talks to **third-party agents**
that speak the public Agent2Agent (A2A) protocol.

> **Internal A2A and external A2A are not the same protocol.**
> `src/a2a/protocol.py` implements AEra's *internal* notarised envelope protocol.
> `src/external_a2a/` implements the *public* A2A standard. They share a name and
> nothing else. Neither one was changed to accommodate the other.

---

## 1. Status: what is actually proven

| Claim | Status |
|---|---|
| AEra successfully interoperated with **Sanctum Beacon** using the standard A2A protocol | **Proven live** |
| AEra is "A2A compatible" in general | **Not claimed.** One agent, one binding, one auth mode. |
| Agent Card discovery works | Proven — but discovery alone is *not* interoperability |
| A real task request was sent and a valid response received | **Proven live** (see §7) |

The runner reports each stage separately and exits non-zero unless **all five**
pass. A run that discovers a card but fails to exchange a message is a FAIL.

---

## 2. The external agent used

| Field | Value |
|---|---|
| Name | Sanctum Beacon |
| Agent Card | `https://sanctum-beacon.onrender.com/.well-known/agent-card.json` |
| A2A endpoint | `https://sanctum-beacon.onrender.com/a2a` |
| `protocolVersion` | `0.3.0` |
| Transport | `JSONRPC` |
| Authentication | none required |
| Skills | `community-discovery`, `find-open-work` |
| Documentation | `https://sanctum-beacon.onrender.com/agents.md` |

It was chosen from a public register of live A2A agents after probing candidates
for an actual response. Four other agents also answered and remain usable as
fallbacks: Korova Milk Bar (0.3), SCRIPTMASTERLABS (1.0), Feeless402 (0.3),
Cape Partners (1.0). The selection criteria were: publicly reachable, no
credentials required, read-only, and documented.

---

## 3. Discovery mechanism actually used

    GET https://{domain}/.well-known/agent-card.json

This is the IANA-registered well-known URI defined by the A2A specification
(§8.2, registration in §14.3). It was **verified against the specification and
against the live endpoint** — it is not a path inherited from a planning
document. An explicit card URL may also be passed directly, which covers the
"direct configuration" case without inventing a second discovery convention.

Registry-based and authenticated extended-card discovery are **not** implemented.

---

## 4. Agent Card formats encountered

Two mutually incompatible card shapes are live in the wild, and the parser
handles both because real agents were observed using each:

**v0.3 (legacy, what Sanctum Beacon serves)**
```json
{ "protocolVersion": "0.3.0", "url": ".../a2a", "preferredTransport": "JSONRPC" }
```

**v1.0 (current)**
```json
{ "supportedInterfaces": [
    { "url": ".../a2a", "protocolBinding": "JSONRPC", "protocolVersion": "1.0" } ] }
```

Both are normalised into `AgentCard.interfaces`, and `preferred_interface()`
selects the first entry this client can actually speak. Card order is respected
as the agent's stated preference. Patch versions are ignored for compatibility
(`0.3.0` → `0.3`).

The JSON-RPC method name depends on the version, and both are supported:

| Protocol version | Method |
|---|---|
| `0.3` | `message/send` |
| `1.0` | `SendMessage` |

An `A2A-Version: Major.Minor` header is sent on every request.

The whole card is treated as **untrusted input**: every field is type-checked,
strings are capped at 4000 characters, lists at 200 entries, and no card value
is ever interpolated into a shell command or an LLM system prompt by this code.

---

## 5. Authentication method actually used

**None.** The selected agent's A2A endpoint is open, and the card declares no
security requirements.

An important subtlety, learned from real cards: several live agents publish a
`securitySchemes` map while leaving the A2A endpoint open — the schemes describe
a *separate* REST API. Therefore `requires_authentication` is keyed on a
non-empty `securityRequirements` / `security` list, **not** on the presence of a
scheme definition.

`BearerTokenAdapter` and `ApiKeyAdapter` exist and are unit-tested, but they can
only be used with a credential **issued by the external provider and supplied
explicitly** on the command line. OAuth2, OpenID Connect and mTLS are not
implemented; an agent requiring them will fail cleanly at the Authentication
stage rather than silently degrading.

---

## 6. The security boundary

This is the part that matters most.

**AEra credentials never leave the AEra trust boundary.** Specifically, the
following are never transmitted to an external agent:

- the AEra Agent JWT (`aera-agent-api` / `aera-agent-relay` audiences)
- `AGENT_JWT_SECRET`
- the agent's Ed25519 private key
- the owner wallet private key

This is enforced structurally, not by convention:

1. `select_adapter()` accepts only `card`, `bearer_token`, `api_key` and
   `api_key_header`. **It cannot be given an `AeraIdentityClient` at all**, so
   there is no code path by which it could reach for an AEra token. A test
   asserts this signature.
2. `_reject_aera_credential()` refuses any supplied credential that looks like a
   JWT (`eyJ…` with three segments), contains an AEra audience marker, looks
   like PEM key material, contains `AGENT_JWT_SECRET`, or is a 32-byte
   `0x…` hex private key.
3. A test inspects the **actual request bytes and headers** sent to the external
   agent and asserts that no AEra marker, DID, JWT or key material appears.

The AEra identity is used to authorise the interaction *inside* AEra and to
attribute it in the audit trail. It is an authorisation subject, not a
credential for third parties.

### SSRF protection

The A2A specification (§13.2) requires it, and the Agent Card supplies a URL
controlled by a third party, so every outbound request is validated:

- `https` only (plain `http` requires an explicit opt-in flag)
- credentials embedded in the URL are rejected
- ports restricted to `{80, 443, 8080, 8443}`
- DNS resolution checked against private, loopback, link-local, multicast,
  reserved and unspecified ranges — including IPv4-mapped IPv6, so
  `::ffff:127.0.0.1` and `169.254.169.254` are blocked
- redirects are followed **manually**, at most 3, and each hop is re-validated
- response bodies are streamed and capped at 2 MiB
- a dedicated 30 s timeout, deliberately separate from the LLM provider timeout

### Untrusted content

Responses from an external agent are **untrusted data**. Sanctum Beacon says so
itself in its own reply. This client extracts text and returns it; it does not
execute it, does not feed it to a tool and does not treat it as an instruction.

---

## 7. Reproducible live test

```bash
cd aera-agent-security-lab
../venv/bin/python -m src.cli.a2a_external \
    --agent https://sanctum-beacon.onrender.com \
    --skill community-discovery
```

Observed result:

```
AEra agent registered and authenticated: did:aera:agent:73f41483fc1a3d452456f072adcbc261
Agent Card : https://sanctum-beacon.onrender.com/.well-known/agent-card.json
Agent      : Sanctum Beacon v1.1.0
Interface  : JSONRPC 0.3.0 -> https://sanctum-beacon.onrender.com/a2a
Auth       : none (no security requirements declared)
-> community-discovery: Hello. What is this community and what is it for?
<- [message] Sanctum is open to agents. Read .../agents.md ...
AEra agent revoked: HTTP 200

AEra Identity: PASS
Agent Card Discovery: PASS
Authentication: PASS
A2A Request: PASS
A2A Response: PASS
```

The disposable AEra agent is revoked at the end of every run, including on
failure.

Options: `--message`, `--bearer-token`, `--api-key`, `--audit-file`,
`--timeout`, `--allow-http`, `--allow-private` (local testing only),
`--no-aera` (external-only smoke test), `--keep-agent`.

---

## 8. Audit trail

Each interaction produces one JSONL record containing the AEra `agent_id`, the
external agent name, the card URL, the endpoint, the protocol version, the skill
requested, the HTTP status, the request/task id, success or failure, the error
category, and an ISO-8601 UTC timestamp.

The auth field records the **scheme name only** (`none`, `bearer`, `apiKey`).
A scrubbing pass additionally redacts any JWT-like, PEM-like or secret-like value
before anything is written, and truncates long values. No credential is ever
persisted.

---

## 9. Mapping into the AEra runtime

```
AEra owner  --(EIP-191 challenge)-->  AEra agent identity  (internal, unchanged)
                                            |
                                            | authorises + attributes
                                            v
                              src/external_a2a/  (new, additive)
                                            |
                                            | standard A2A / JSON-RPC / HTTPS
                                            v
                                   external third-party agent
```

Nothing in `agent/`, `server.py`, `src/a2a/protocol.py`, `src/identity/` or
`src/config/settings.py` was modified. The external client is a new, additive
package with its own error taxonomy (`network`, `auth`, `protocol`, `remote`,
`ssrf_blocked`); AEra identity failures deliberately remain `AeraError` so the
two domains cannot be confused in logs.

---

## 10. Limitations (explicit)

- **One agent, one binding.** JSON-RPC only. gRPC and HTTP+JSON bindings are not
  implemented.
- **No streaming, no push notifications.** `message/stream` and webhook delivery
  are unimplemented; the chosen agent advertises neither.
- **No OAuth2 / OIDC / mTLS.** Only no-auth, bearer and header API keys.
- **No task lifecycle management.** `tasks/get`, `tasks/cancel` and resubscribe
  are not implemented; the client sends one message and reads one reply.
- **DNS rebinding window.** **CLOSED in Phase 2.** The hostname is now resolved
  once, every resolved address is policy-checked, and the connection is made to
  a validated IP literal while the original hostname is preserved for the Host
  header and TLS SNI. No second, unchecked resolution occurs. See
  `docs/a2a-gateway.md` §12.
- **No trust extension, no signature verification of external agents.** There is
  no cryptographic proof that Sanctum Beacon is who its card claims. Transport
  TLS is the only authentication of the remote party.
- **Remote availability.** The chosen agent is hosted on a free tier and may be
  slow to wake or temporarily unavailable; this is a property of the remote
  service, not of the client.

---

## 11. Test coverage

| File | Tests |
|---|---|
| `tests/unit/test_external_a2a_card.py` | 14 |
| `tests/unit/test_external_a2a_auth.py` | 20 |
| `tests/unit/test_external_a2a_net.py` | 31 |
| `tests/unit/test_external_a2a_audit.py` | 7 |
| `tests/integration/test_external_a2a_client.py` | 20 |
| **Total** | **92** |

Unit and integration tests use `httpx.MockTransport` and never touch the
network, so they are deterministic and do not depend on a third party staying
online. The live proof is the CLI runner in §7.

A negative proof (`negproof_external_a2a.py`) injects six mutants — disabled SSRF
checks, removed AEra credential rejection, wrong JSON-RPC method, ignored
JSON-RPC errors, wrong auth-required logic, disabled audit scrubbing — and
confirms that **6 of 6 are caught** before restoring the baseline.
