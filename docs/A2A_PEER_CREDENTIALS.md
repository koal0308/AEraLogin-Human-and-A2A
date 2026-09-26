# External A2A Peer Credentials (Part H)

How an external agent proves *who it is* when it calls AEra's inbound A2A
gateway, and what that proof does and does not buy it.

Status: implemented, unit- and integration-tested, and live-verified against
running services in **both** authentication modes —
`tools/live_check_a2a_credentials.py` (26/26, `optional`) and
`tools/live_check_a2a_required_policy.py` (17/17, `required`).

---

## 1. Where this sits

AEra has three separate trust levels. They are never merged.

| Level | Principal | Proof | Verified by |
|---|---|---|---|
| 1 | Human owner | dashboard session JWT | `server._dashboard_owner_from_request` |
| 2 | AEra Agent | Agent JWT + Ed25519 identity | `agent/tokens.py`, on `/api/agents/*` |
| 3 | External A2A peer | opaque bearer credential | `a2a_gateway/credentials.py`, on `/api/a2a` |

A Level-2 Agent JWT presented at Level 3 grants **nothing**. It is refused
before the credential store is even opened, so an AEra token can never be
looked up as if it were a peer credential. The same applies to dashboard JWTs,
OAuth tokens, `AGENT_JWT_SECRET` and private-key material.

The Agent Identity Layer (`agent/`) is untouched by this feature.
`aera-a2a-gateway` is deliberately **not** in `agent.constants.AUDIENCE_ALLOWLIST`.

---

## 2. Credential format

```
aera_a2a_<cred_id>_<secret>
```

* `secret` — 256 bits from `secrets.token_hex(32)`.
* `cred_id` — 128-bit public lookup handle, indexed, safe to log.
* The credential is **opaque**: it carries no claims. It is not a JWT, and
  there is no signing secret for it anywhere.
* The server stores only `SHA-256(secret)`. The plaintext is never written to
  the database, a log, or an audit record.
* Comparison uses `hmac.compare_digest`, so a wrong secret cannot be recovered
  byte by byte through response timing.
* The `aera_a2a_` prefix makes a leaked credential greppable in a log
  aggregator or a public repository.

### Why opaque rather than a JWT

Revocation has to be immediate and authoritative, so every request must consult
the store anyway. A JWT would therefore add a server-wide signing secret and
buy nothing — while making one leaked secret a problem for every peer.

---

## 3. Storage

One table, `a2a_peer_credentials` (database went from 27 to 28 tables):

`cred_id` (PK) · `peer_id` · `peer_label` · `secret_hash` · `status` ·
`issued_at` · `expires_at` · `scoped_agents` · `scoped_skills` · `audience` ·
`issuer` · `owner_address` · `revoked_at` · `revoked_reason` · `last_used_at`

Indexed on `owner_address`, `peer_id`, `status`; `cred_id` lookup is the
primary key, so verification is one indexed read rather than a scan.

The database is authoritative for existence, active/revoked state, expiry,
scope, owner and peer identity.

**Fail closed.** If the store is unavailable the caller is *not* promoted:
under `optional` the request proceeds anonymously only when no credential was
offered; a credential that cannot be verified is an authentication failure, and
under `required` the request is rejected outright. Broken authentication
infrastructure never becomes authenticated access.

---

## 4. Issuance

Owner-authorised only. **There is no self-registration.**

```
POST /api/dashboard/a2a-credentials
Authorization: Bearer <dashboard JWT>

{ "peer_label": "Sanctum Beacon",
  "peer_id": "peer_…",                 // omit to mint a new peer
  "scoped_agents": ["did:aera:agent:…"],
  "scoped_skills": ["agent.read.profile"],
  "ttl_days": 90 }
```

The owner identity comes **exclusively** from the authenticated dashboard JWT.
`owner`, `owner_address` and `owner_wallet` in the query string or request body
are ignored. Every requested `scoped_agents` entry is checked server-side
against `agents.owner_wallet`; scoping to an agent you do not own returns
`403 not_your_agent` rather than being silently dropped.

The response contains the plaintext credential **exactly once**:

```json
{ "success": true, "cred_id": "…", "peer_id": "peer_…",
  "credential": "aera_a2a_…",
  "warning": "This is the only time the credential is shown. …" }
```

`GET /api/dashboard/a2a-credentials` lists the owner's credentials as metadata
only — never the secret, and never anything beginning with `aera_a2a_`.

---

## 5. Lifetime, revocation, rotation

* **Lifetime** — 90 days by default, configurable per issuance (`ttl_days`) or
  globally via `AERA_A2A_CREDENTIAL_TTL_DAYS`. `expires_at` is stored and
  checked server-side on **every** request.
* **Revocation** — `POST /api/dashboard/a2a-credentials/{cred_id}/revoke`.
  Effective on the very next request; there is no validity window to wait out.
  The row is never deleted, so `revoked_at`/`revoked_reason` and the historical
  peer identity stay auditable. Revoking a credential that is absent, already
  revoked, or another owner's all return the same `404`.
* **Rotation** — `POST /api/dashboard/a2a-credentials` with
  `"rotate_cred_id": "<existing cred_id>"` (plus the fresh scope). The server
  looks the credential up **for the session owner only** and reuses its
  `peer_id`; an unknown or foreign `cred_id` returns `404 unknown_credential`.
  The scope is re-validated like any issuance, and a body `peer_id` is always
  ignored. Hand the new credential over, then revoke the old one. Nothing is
  revoked implicitly at issuance.
  Multiple simultaneously valid credentials per peer are supported, so rotation
  needs no downtime.

---

## 6. Peer identity

`peer_id` is **AEra-minted** (`peer_<24 hex>`) and stable across rotation. It is
never derived from an IP address, wallet, e-mail, agent id, dashboard JWT or
anything in the request body — a caller cannot name itself.

A verified credential yields an `ExternalPeerIdentity` carrying `peer_id`,
`credential_id` and the scopes. `external_agent_id` records whatever the caller
*claimed*; it stays untrusted. `is_trusted_aera_agent` is always `False`.

---

## 7. Authorisation is a separate step

A valid credential proves **"this is peer X"**. It does not prove **"peer X may
talk to agent Y"**. The two are never collapsed:

```
verify credential → ExternalPeerIdentity → authorize(peer, target, skill)
                  → rate limit → replay guard → runtime delivery
```

* empty `scoped_agents` — no restriction at that dimension
* non-empty `scoped_agents` — only those agents
* `scoped_skills` — restricts which A2A skills may be invoked
* an owner can only grant scopes for agents they own; a caller can never widen
  its own scope

Authorisation failure, an unknown agent, a revoked agent and an agent belonging
to someone else all produce the **same** opaque error, so an authenticated peer
cannot enumerate agents.

---

## 8. Authorization header handling

Only `Authorization: Bearer <credential>` is accepted. Credentials in request
JSON or URL query parameters are not read at all.

A malformed or invalid credential is an authentication **failure** (HTTP 401),
never a silent downgrade to anonymous. Ignoring a bad credential would hide
caller bugs and let an attacker probe for parser differences.

Every failure mode — unknown `cred_id`, wrong secret, expired, revoked, wrong
audience, wrong issuer — returns the single wording
`invalid or expired credential`, so the endpoint is not an enumeration oracle.

---

## 9. Authentication policy

`AERA_A2A_AUTH_POLICY=optional|required`, default **`optional`**.

| | `optional` | `required` |
|---|---|---|
| no credential | anonymous caller | 401 |
| valid credential | authenticated peer | authenticated peer |
| invalid credential | 401 | 401 |

The default stays `optional` because Phase-2 live interoperability was verified
with anonymous A2A, and making credentials mandatory is a breaking change for
every existing peer — that must be a deliberate operator decision. An
unrecognised value falls back to `optional`, so a typo cannot silently lock out
every peer; enabling `required` must be spelled correctly.

The Agent Card advertises the `aeraPeerCredential` bearer scheme it actually
implements. Under `optional`, `security` stays empty (the gateway genuinely
does accept anonymous callers); under `required`, `security` becomes
`[{"aeraPeerCredential": []}]`. The card never names a credential, an issuance
URL, or any hint about which credentials exist.

Both modes are live-verified, each against a service actually running in that
mode — `optional` on the shared instance, `required` on a dedicated isolated
instance:

| | anonymous caller | valid credential |
|---|---|---|
| `optional` | 200 | 200, authenticated |
| `required` | **401** | 200, authenticated |

---

## 10. Rate limiting

Part H **adds** an authenticated dimension; it removes nothing. All of these
remain active:

* global bucket
* network/source-address bucket
* per-target-agent bucket
* **new:** per-credential bucket (`SCOPE_CREDENTIAL`, keyed on `cred_id`)

Authenticated callers do **not** bypass the global limit. The per-credential
key is stable, so a distributed flood cannot get a fresh bucket simply by
rotating IP addresses. The limiter runs before any expensive database or
runtime work, so a rejected caller costs nothing.

---

## 11. Replay

Unchanged. Bearer credentials are **reusable** caller credentials; there is
deliberately no second, credential-level replay mechanism. A2A request replay
is still `message_id` + `a2a_inbound_requests`: the same credential may make
any number of requests with different message IDs, and a duplicate message ID
is still rejected. Both properties are covered by regression tests and by the
live check.

---

## 12. What is never logged

Plaintext credentials, secrets, `secret_hash`, the `Authorization` header,
dashboard JWTs, Agent JWTs, `AGENT_JWT_SECRET`, private keys and provider API
keys never reach a log, an audit record, an HTTP response or an exception.
`CredentialRecord.__repr__` and `ExternalPeerIdentity.__repr__` are overridden
so a traceback cannot leak one either.

Safe to log, and what is actually logged: `peer_id`, `cred_id`, target agent,
skill, timestamp, and a success/failure category. Internal exceptions return
`internal error`; the detail goes to the server-side audit field only.

---

## 13. Limitations

* Scope is enforced at agent and skill granularity only — there is no
  per-method, per-field or quota-based scoping.
* `last_used_at` is best-effort telemetry: a failure to record it never fails
  an otherwise valid request, so it is not a reliable audit clock.
* The `x-api-key` header is parsed but buys no privilege; there is no API-key
  store, and it does not satisfy `required`.
* Rate-limit buckets are in-process. Across multiple workers each process holds
  its own buckets.
* Credential lifetime is checked at request time only; there is no background
  job that prunes or reports expired credentials.
* `optional` remains the default, so the gateway is still open to anonymous
  callers unless an operator sets `required`.

---

## 14. Verification

| Suite | Result |
|---|---|
| `pytest tests/` | 492 passed, 3 skipped, 12 xfailed |
| Agent security lab | 237 passed |
| `negproof_a2a_credentials.py` | 29/29 mutants caught |
| `negproof_a2a_gateway.py` | 10/10 |
| `negproof_a2a_ratelimit.py` | 7/7 |
| `negproof_agent_runtime.py` | 14/14 |
| `tools/live_check_a2a_credentials.py` | 26/26 against the running service (`optional`) |
| `tools/live_check_a2a_required_policy.py` | 17/17 against an isolated service (`required`) |

The live checks use a throwaway owner, throwaway agents and throwaway
credentials, and remove all of them afterwards — including on failure.

The `required` check refuses to run against a service whose agent card does not
report `required`, so it cannot accidentally certify the mode it is supposed to
be testing while pointed at an `optional` instance.
