# AEraLogIn Agent Identity Layer

Additive subsystem on top of AEraLogIn. Fully deactivatable via
`AGENT_LAYER_ENABLED=false` (default). Never touches OAuth / Wallet / NFT /
Resonance Score logic.

## Architecture

```
Owner Wallet (EOA / EIP-1271)
     │  (2)  personal_sign over restricted canonical JSON
     ▼
POST /api/agents/owner-challenge  ──┐
POST /api/agents/register           │  operations: register, key_add,
POST /api/agents/{id}/keys          │  key_rotate, key_revoke,
POST /api/agents/{id}/keys/rotate   │  agent_revoke, capabilities
DELETE /api/agents/{id}/keys/{kid}  │
DELETE /api/agents/{id}             │
PATCH /api/agents/{id}/capabilities─┘

Agent Process (holds Ed25519 private key, never sent to server)
     │
     ▼
POST /api/agents/{id}/challenge      (60 s, single-use, bound to agent+key+aud)
POST /api/agents/{id}/authenticate   → returns Agent JWT (HS256, 15 min)
POST /api/agents/tokens/revoke       (self-revoke or owner)
POST /api/agents/verify-jwt
POST /api/agents/messages            (JWT ∧ Ed25519 message signature)
POST /api/agents/interactions        (JWT + capability + Ed25519)
GET  /api/agents/{id}                (public metadata)
```

## Security Model (Spec v1.2)

| Aspect | Guarantee |
|---|---|
| Owner binding | Owner Challenge (persistent, 120 s, single-use, bound to `(owner, op, agent)`) + EIP-191 / EIP-1271 signature over canonical JSON. |
| Agent authentication | Agent Challenge (60 s, single-use, bound to `(agent_id, key_id, aud)`) + Ed25519. |
| Audience | Server-side allowlist: `aera-agent-api`, `aera-agent-relay`. Fixed per endpoint. |
| JWT | HS256, `AGENT_JWT_SECRET` ≠ `OAUTH_JWT_SECRET`. Strict `require=[exp,iat,sub,jti,aud,iss]`. `typ=agent` enforced. |
| JWT lifecycle | `agent_jti` register – verifier reads status, does NOT single-use. Reusable within `exp`. Revocation cascades on key/agent revoke. |
| Message auth | Independent Ed25519 signature over canonical message payload. JWT alone never authenticates a message. |
| Replay protection | Layer-per-layer stores: `agent_challenges`, `owner_challenges`, `agent_jti`, `agent_message_ids` – disjoint. |
| Canonical JSON | Restricted profile: fixed ASCII keys, no floats, no nulls in required fields, NFC UTF-8, codepoint-sorted keys. Python ↔ Node byte-identity verified by T-31. |

## Key Management

* Ed25519 via `cryptography` (already present, no new dependency).
* Public key encoded as `ed25519:<base64url-nopad(32B)>`.
* Signatures encoded as `base64url-nopad(64B)`.
* Max 5 active keys per agent. Rotation = INSERT new + revoke old + cascade JWT revocation, all in one SQLite `BEGIN IMMEDIATE`.
* Agent revocation cascades to all keys and all active JWTs.

## Capabilities (Spec §12.1)

`agent.authenticate`, `agent.read.profile`, `agent.communicate`,
`agent.interaction.record`. Server-issued only. JWT capabilities MUST be a
subset of server-recorded capabilities.

## Normal flow: Create Agent → Enrollment → Runtime (recommended)

Enrollment ("runtime pairing") is the normal way to create an agent. The owner
never handles a key; the runtime never handles the wallet.

```
Dashboard (owner session)                       Agent Runtime (owner's machine)
1. Create Agent → POST /api/dashboard/agents/enrollments
   ← enrollment_code (shown ONCE, 15 min)
                                                2. python -m agent_runtime enroll <code>
                                                   generates Ed25519 key LOCALLY
                                                3. POST /api/agents/enrollments/claim
                                                   {enrollment_code, public_key, signature(PoP)}
4. dashboard shows key fingerprint              runtime prints the SAME fingerprint
5. owner compares, signs owner challenge
   (operation=register, agent_id="enrollment:<id>")
   POST /api/agents/enrollments/{id}/complete
   → agent_id + key_id created
                                                6. runtime polls POST /api/agents/enrollments/status,
                                                   writes <key>.identity.json (public ids only)
                                                7. python -m agent_runtime run   (no manual ids)
```

| Step | Endpoint | Auth |
|---|---|---|
| create | `POST /api/dashboard/agents/enrollments` `{label, capabilities?}` | dashboard session |
| view | `GET /api/dashboard/agents/enrollments/{id}` | dashboard session (own only) |
| cancel | `DELETE /api/dashboard/agents/enrollments/{id}` | dashboard session (own only) |
| claim | `POST /api/agents/enrollments/claim` `{enrollment_code, public_key, signature}` | enrollment secret + PoP |
| status | `POST /api/agents/enrollments/status` `{enrollment_code}` | enrollment secret |
| complete | `POST /api/agents/enrollments/{id}/complete` `{owner_wallet, owner_challenge_id, owner_signature}` | owner wallet signature |

**Fingerprint.** `SHA-256(raw 32-byte public key)`, first 80 bits, shown as
`XXXX-XXXX-XXXX-XXXX-XXXX`. It is public. Comparing the dashboard value with the
runtime's output proves that the key AEra received is the key *your* runtime
generated (and not one submitted by someone who intercepted the code). The
runtime also aborts if the server echoes a different fingerprint.

The resulting agent is created by the same function as `/register`; it is
indistinguishable from a manually registered agent.

### Enrollment security properties (as implemented, `agent/enrollment.py`)

| Property | Value |
|---|---|
| Code format | `aera-enroll-<16 hex id>.<32 char secret>` (secret = 192 bits) |
| TTL | 15 minutes (`ENROLLMENT_TTL_SECONDS`) |
| Open enrollments | max 5 per owner (`429 too_many_open_enrollments`) |
| Storage | only `SHA-256(secret)`; constant-time compare; never logged or returned again |
| Single use | one claim (`pending → key_submitted`), one completion (`→ completed`), conditional UPDATEs in `BEGIN IMMEDIATE` |
| PoP | Ed25519 signature by the NEW key over canonical JSON `{protocol: "aera-agent-enroll", version, enrollment_id, public_key, domain}` — bound to this enrollment and this key |
| Owner binding | only the creating owner; owner challenge must be `operation=register`, `agent_id="enrollment:<id>"`. A plain `/register` challenge cannot complete an enrollment and vice versa |
| One key, one agent | a public key already active on an agent is refused (`409 key_already_registered`) |
| Rate limits | claim 30/min per IP + 10/min per enrollment id; status 120/min per IP + 60/min per id; complete 10/min per owner |

Failure behaviour:

| Case | Result |
|---|---|
| unknown id **or** wrong secret | `404 invalid_enrollment_code` (identical — no id oracle) |
| malformed code | `400 invalid_enrollment_code` |
| invalid / foreign-key / wrong-enrollment PoP | `401 invalid_proof_of_possession`; enrollment stays `pending` |
| second claim / reused code | `409 enrollment_already_claimed` |
| expired | `410 enrollment_expired` (view shows `expired`) |
| cancelled | claim `409`; runtime stops with `enrollment_cancelled` |
| complete by another owner | `404 unknown_enrollment` |
| complete with bad signature / wrong challenge | `401` |
| complete before claim / twice | `409 enrollment_not_claimed` / `enrollment_not_open` |

## Runtime installation & startup

There is **no installer and no package**. The runtime is the `agent_runtime`
module in this repository and runs from the source tree.

1. **Prerequisites:** Python 3.11 (tested with 3.11.2), Linux/macOS (the
   gateway ↔ runtime channel is a Unix domain socket).
2. **Install:**
   ```bash
   git clone https://github.com/koal0308/AEraLogin-Human-and-A2A.git
   cd AEraLogin-Human-and-A2A
   python3 -m venv venv && . venv/bin/activate
   pip install -r requirements-dev.txt     # includes cryptography, httpx
   ```
3. **Configure** (environment variables; nothing is written back):

   | Variable | Default | Purpose |
   |---|---|---|
   | `AERA_BASE_URL` | `http://127.0.0.1:8840` | AEra server |
   | `AERA_RUNTIME_KEY_PATH` | `~/.aera/agent_key.json` | private key file (0600) |
   | `AERA_RUNTIME_KEY_PASSPHRASE` | – | if set: key sealed with scrypt + AES-GCM (`scrypt-aesgcm-v1`); if unset the key is stored **unencrypted** (0600) and `enroll` says so |
   | `AERA_RUNTIME_AGENT_ID` / `AERA_RUNTIME_KEY_ID` | – | explicit identity; **if either is set, the identity file is ignored** |
   | `AERA_RUNTIME_INTERNAL_SECRET` | – | required by `run`; must equal the server's value (gateway ↔ runtime channel) |
   | `AERA_RUNTIME_DIR` | `/tmp/aera-runtime` | socket directory; must equal the server's value |
   | `AERA_RUNTIME_PROVIDER` / `AERA_RUNTIME_MODEL` | `mock` / – | LLM backend; `mock` needs no API key |
   | `AERA_RUNTIME_LOG_LEVEL`, `AERA_RUNTIME_TIMEOUT`, `AERA_RUNTIME_MAX_REPLY` | `INFO`, `30`, `2000` | operational |

4. **Enroll:** `python -m agent_runtime enroll <code>` (options: `--timeout
   <seconds>` default 900, `--reuse-key` to enroll an existing not-yet-registered
   key). Writes `<key stem>.identity.json` (0600) containing only `agent_id`,
   `key_id`, `aera_base_url`. Refuses if that identity file already exists.
5. **Start:** `python -m agent_runtime run` — authenticates (Agent JWT), opens
   the socket, prints `runtime RUNNING agent_id=… provider=… socket=…`.
6. **Health:** `python -m agent_runtime health` (queries the running runtime
   over the authenticated socket).
7. **Normal run:** re-authenticates on demand; checks liveness with AEra every
   5 minutes; answers gateway calls with an Ed25519-signed reply. The gateway
   authenticates its request with an HMAC envelope (`AERA_RUNTIME_INTERNAL_SECRET`)
   and accepts a reply only if it is signed by an **active** registered key of
   the target agent and carries the same `agent_id` and `request_id` as the request.
8. **Exit codes / failures:** `2` config error (e.g. internal secret missing);
   `1` key/identity/provider error or AEra unreachable at start; `3` agent or
   key revoked (at start, or discovered at a liveness check).

Note: the enrollment code as a CLI argument is visible in shell history and
`ps` for its (≤ 15 min, single-use) lifetime.

Same host: the A2A gateway reaches the runtime over a local Unix socket
(`AERA_RUNTIME_DIR`, authenticated with `AERA_RUNTIME_INTERNAL_SECRET`). A
runtime can therefore only *receive* A2A traffic when it runs on the same host
as the AEra server. Enrollment and Agent JWT authentication work over HTTP from
anywhere.

## Security boundary

**PRIVATE KEY NEVER LEAVES THE RUNTIME.** AEra receives only the public key and
a proof-of-possession signature. AEra never receives a private key, seed,
mnemonic or decrypted key material; `LocalKeyStore` has no method that returns
private bytes. The owner wallet key never touches the runtime.

## Advanced / Developer: manual registration

Still supported and unchanged: generate a key yourself
(`python -m agent_runtime keygen`), then `POST /api/agents/register` with an
owner signature and the public key, and start the runtime with
`AERA_RUNTIME_AGENT_ID` / `AERA_RUNTIME_KEY_ID`.

## Revocation

* Key revoke (`DELETE /api/agents/{id}/keys/{key_id}`) and agent revoke
  (`DELETE /api/agents/{id}`) need an owner signature and cascade to all
  dependent Agent JWTs immediately.
* After agent revoke: existing JWTs fail `verify-jwt`, the runtime cannot
  re-authenticate, `agent_runtime run` exits `3`, the A2A gateway refuses the
  agent as a target, and a runtime reply signed by a revoked key is rejected.
* External peer credentials are a separate system: revoking an agent does not
  change credential status, and revoking a credential does not touch agents.

## Recovery ("runtime lost / new machine")

Implemented:

* **Same `agent_id` (Advanced):** generate a new key on the new machine, owner
  adds it (`POST /api/agents/{id}/keys`, `key_add`), owner revokes the lost key
  (`key_revoke`), start the runtime with explicit
  `AERA_RUNTIME_AGENT_ID`/`AERA_RUNTIME_KEY_ID`.
* **Re-enrollment:** revoke the old agent, create a new enrollment and run
  `agent_runtime enroll` with a new key path. This creates a **new `agent_id`**.

Not implemented: pairing-based key rotation or recovery for an existing
`agent_id`; enrollment always creates a new agent.

## Reproducible end-to-end check

```bash
./venv/bin/python tools/release_live_e2e.py          # --port 8892 by default
```

Starts its own AEra server on an isolated port with a fresh schema-only
database and freshly random secrets, then runs the chained workflow: enrollment
(+ negative cases) → runtime run/health → Agent JWT → signed L2 message →
external peer credential → `/api/a2a` → runtime reply → trust evidence →
recovery (same agent) → agent revocation → re-enrollment → log/secret audit.
It never touches `aera.db` data or port 8840 and prints no secrets.

## Configuration

```env
AGENT_LAYER_ENABLED=false     # master switch (default off)
AGENT_JWT_SECRET=<>=32 bytes> # required if AGENT_LAYER_ENABLED=true
                              # MUST differ from OAUTH_JWT_SECRET and TOKEN_SECRET
```

Generate secret:
```
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

## Local Test Guide

```
export AGENT_LAYER_ENABLED=true
export AGENT_JWT_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
venv/bin/python -m pytest tests/agent -q
```

E2E flow: `tests/agent/test_e2e.py::test_e2e_full_flow` performs Owner →
Register A + B → Auth A/B → Message A→B → Interaction → Audit assertions →
replay rejection.

## Phase-2 – NOT implemented

* Per-request PoP nonces (`agent_pop_nonces`) – documented in Spec §9.5 as roadmap only.
* On-chain agent registry / Ed25519 precompile.
* Direct P2P agent-to-agent transport.
* Server-side EdDSA JWKS.
* Capability delegation between agents.
* Installer / packaged runtime (source tree + `python -m agent_runtime` only).
* Pairing-based key rotation for an existing agent (see Recovery).
* WebAuthn.
