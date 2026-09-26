# AEra Agent Security Test Report

**Date:** 2026-09-23
**Target:** `https://aeralogin.com` — deployed AEra Agent Identity Layer (production)
**Harness:** `aera-agent-security-lab/` (isolated; contains no production code)
**LLM:** DeepSeek `deepseek-chat` via `https://api.deepseek.com` (real API calls)
**Artifacts:** `run-artifacts/deepseek-run.json`, `run-artifacts/mock-run.json`

> **Production integrity:** no file under `agent/`, `server.py`, `tests/` or
> `tools/` was modified. Newest production `.py` mtime is `2026-09-22 19:15`
> (the previous hardening session); all lab files are `2026-09-23 16:03`.
> Only `__pycache__/*.pyc` were touched, as a side effect of importing.

---

## 1. Result summary

### Normal flow

| Step | Result |
|---|---|
| A authentication | **PASS** |
| B authentication | **PASS** |
| A → B (notarised by AEra) | **PASS** |
| B → DeepSeek | **PASS** |
| DeepSeek → B | **PASS** |
| B → A (notarised by AEra) | **PASS** |
| Full round trip | **PASS** |

### Attacks

| Test | Attack | Result |
|---|---|---|
| SEC-01 | Replay | **BLOCKED** |
| SEC-02 | Tampering | **BLOCKED** |
| SEC-03 | Hash attack | **BLOCKED** |
| SEC-04 | Sender spoof | **BLOCKED** |
| SEC-05 | Key spoof | **BLOCKED** |
| SEC-06 | JWT mismatch | **BLOCKED** |
| SEC-07 | Receiver attack | **BLOCKED** |
| SEC-08 | Expiry attack | **BLOCKED** |
| SEC-09 | Invalid JWT | **BLOCKED** |
| SEC-10 | Wrong audience | **BLOCKED** |
| SEC-11 | JTI attack | **BLOCKED** |
| SEC-12 | Fake B | **BLOCKED** |
| SEC-13 | Response replay | **BLOCKED** |
| SEC-14 | Field mutation | **BLOCKED** |

**14 / 14 blocked. 0 attacks succeeded.**

### Teardown

| Agent | Revoked | Keys deactivated | Old JWT rejected |
|---|---|---|---|
| A | PASS (HTTP 200) | PASS | PASS (401) |
| B | PASS (HTTP 200) | PASS | PASS (401) |
| C | PASS (HTTP 200) | PASS | PASS (401) |

Database check: `lab agents active: 0`, `lab keys active: 0`, `lab jti active: 0`,
`lab agents revoked: 12` (accumulated over all runs). 26 tables — schema unchanged.

### Regression

| Suite | Result |
|---|---|
| Existing AEra tests (`tests/`) | **207 passed, 12 xfailed, 0 failed** |
| Lab offline tests | **53 passed** |
| Lab live checks | **26 / 26 passed** |
| Service | `active`, `NRestarts=0` |

---

## 2. What AEraLogIn itself verified

Every item below was observed as a real HTTP response from production.

| Property | Enforced at | Evidence |
|---|---|---|
| Owner authorisation for registration | `/register` | EIP-191 signature over the canonical owner challenge; single-use |
| Agent possesses its private key | `/authenticate` | Ed25519 over the canonical challenge; challenge single-use, TTL 60 s |
| JWT authenticity | `tokens.verify` | 10 forged/invalid variants → all `401` |
| JWT audience separation | `tokens.verify` | api token on `/messages` → `401 invalid_audience`; relay token on `/verify-jwt` → `401 invalid_audience`; relay token on `/messages` → `200` (positive control) |
| JTI lifecycle | `agent_jti` | genuinely revoked token → `401 jti_revoked` |
| JWT identity binding | `tokens.verify` | `sub`/`key_id`/`aud`/`owner_wallet`/`jti` mutations → all `401` |
| Sender ↔ JWT binding | `messages.verify_and_store` | `401 sender_jwt_mismatch` |
| Sender key belongs to sender and is active | `_load_active_key` | `401 revoked_key` |
| Receiver exists and is active | `_agent_active` | checked in-transaction |
| Envelope integrity (9 fields + key set) | `canonical_json` + Ed25519 | `401 message_signature_invalid` for every mutation |
| Message expiry (TTL 300 s) | `_iso_to_epoch` | `401 expired_message` |
| One-time delivery | `agent_message_ids` PK | `401 message_replay` (requests **and** responses) |
| Revocation cascade | `DELETE /{agent_id}` | agent + keys + JTIs all revoked; old JWTs → `401` |

## 3. What Agent A / Agent B verified locally

The receiving runtime does **not** trust a message merely because AEra accepted
the JWT. `LocalVerifier` independently checks, in order:

1. exact `AGENT_MESSAGE_KEYS` vocabulary + protocol/version
2. `receiver_agent_id == self` (receiver binding)
3. expected sender (A accepts responses only from B)
4. `expires_at` in the future
5. local replay window `(receiver, message_id)`
6. sender key belongs to the claimed sender **and** is `active`
   (fetched live from `GET /api/agents/{agent_id}`)
7. **`content_hash` recomputed from the bytes actually received**
8. Ed25519 signature over the canonical payload

`LocalTransport` deliberately performs **zero** validation, proven by
`test_local_transport_performs_no_validation`, so no security property can be
silently credited to the transport.

## 4. What Agent C attempted

Agent C is a fully legitimate AEra agent — own `agent_id`, own disposable owner
EOA, own Ed25519 key, own real server-issued JWTs for both audiences. C held
**none** of: A/B Ed25519 private keys, A/B Agent JWTs, A/B owner keys,
`AGENT_JWT_SECRET`.

C attempted replay, content tampering, hash manipulation, sender spoofing,
key-ID spoofing, JWT/sender mismatch, receiver redirection, expired messages,
10 invalid-JWT variants, cross-audience reuse, 5 JWT-claim mutations, forged B
responses, response replay, and 10 signed-field mutations.

## 5. Attacks rejected by AEra (12 of 14)

SEC-01, SEC-03, SEC-04, SEC-05, SEC-06, SEC-07, SEC-08, SEC-09, SEC-10,
SEC-11, SEC-13, SEC-14 — each with a real `401` and the production error code
(see `docs/attack-matrix.md` for every sub-variant).

## 6. Attacks rejected locally (2 of 14)

| Test | Why AEra cannot see it |
|---|---|
| **SEC-02** Content tampering | The relay never receives the content. The envelope and its signature remain perfectly valid; only the out-of-band bytes changed. Detected by recomputing `content_hash` → `content_hash_mismatch`. |
| **SEC-12** Fake B response | AEra *did* also reject C's forged relay submission (`401 sender_jwt_mismatch`). But if content were ever delivered by a channel AEra does not mediate, only A's local check (`message_signature_invalid`, and `sender_mismatch` for an honestly-signed C message) prevents A from acting on it. |

**This is the central finding: AEra's guarantees are necessary but not
sufficient. A correct AEra agent MUST implement receiver-side verification.**

## 7. What could not be tested, and why

| # | Limitation | Consequence |
|---|---|---|
| **L-1** | **M-01 — no content transport.** `POST /api/agents/messages` notarises; it does not deliver or store content. `MessageRequest.content` exists in the model but is never read, and there is no inbox/polling/push endpoint. | End-to-end content confidentiality, integrity-in-transit and delivery guarantees **cannot** be attributed to AEra. They were provided by the local transport + verifier. No delivery endpoint was invented. |
| **L-2** | No man-in-the-middle test against the real channel. | The out-of-band channel is in-process. A network MITM against TLS was out of scope. |
| **L-3** | `AGENT_JWT_SECRET` compromise not tested. | By design: the attacker model excludes server-secret compromise. Note the production code already defends the sub-case of audience pivoting (`row["aud"] != payload["aud"]`). |
| **L-4** | EIP-1271 (contract-wallet owners) not exercised. | `owner_challenges._verify_eip1271` is inert without a real `BASE_RPC_URL`. Disposable EOAs use EIP-191. |
| **L-5** | On-chain interaction recording not exercised. | `onchain_tx_hash` stays `NULL` in this deployment; no blockchain transaction was performed, as instructed. |
| **L-6** | Owner-key theft not tested. | Out of scope: possession of an owner key is, by design, full control of that agent. |

## 8. Discrepancies between expectation and reality

Documented rather than hidden, as required.

| # | Expected | Observed | Assessment |
|---|---|---|---|
| D-1 | SEC-04 sender spoofing → signature error | `401 sender_jwt_mismatch` | **Correct and stronger.** Production checks the sender↔JWT binding *before* the signature. C cannot reach the signature check at all, because it has no JWT for A. |
| D-2 | SEC-05 key spoofing → signature error | `401 revoked_key` | **Correct.** `_load_active_key` queries `WHERE key_id=? AND agent_id=?`; A's key under sender C returns no row, mapped to `revoked_key`. Slightly misleading error *name*, but the rejection is right. Cosmetic only. |
| D-3 | SEC-09 forged-claim variants → `invalid_issuer` / `invalid_audience` / `wrong_typ` | all `401 invalid_signature` | **Correct precedence.** HMAC is verified before claims. Claim-specific codes are unreachable without the server secret — which is the point. |
| D-4 | First `revoked_jti` probe reported `invalid_audience` | — | **Harness defect in my own test**, found and fixed: an api-audience token had been replayed on the relay, so the audience check fired first and the revocation was never actually exercised. Corrected to test the revoked token on its own audience via `/verify-jwt` → now genuinely `401 jti_revoked`. |
| D-5 | DeepSeek reachable | first run `HTTP 402 Insufficient Balance` | External dependency, not a security issue. The `finally:` teardown still revoked all three agents (verified: 0 left active). Agent B now reports `provider_error` distinctly, so an outage can never be mistaken for a successful round trip. |

## 9. Evidence that the tests actually detect failures

Negative proof (`tools/negative_proof.sh`): removing the `content_hash` and
Ed25519 checks from `LocalVerifier` causes **10 security tests to fail**;
restoring them returns the suite to 53 passed. A green suite therefore means
something.

Two further self-inflicted defects were found by the tests and fixed in the
**implementation**, not by weakening the test:

* `vars(DeepSeekProvider)` exposed the raw API key → introduced `Secret`, which
  redacts in `repr`, `str`, `format`, `vars()`, logs and pytest output.
* `Settings` leaked the key via its dataclass `repr` → custom redacting `repr`.

## 10. Secret hygiene

| Check | Result |
|---|---|
| DeepSeek key present in any lab file | **none** (grep for the literal key) |
| `sk-` occurrences in lab sources | only two test canaries |
| `.env` in `.gitignore` | yes |
| Key in `repr`/`str`/`vars`/logs | blocked by `Secret`, covered by 3 tests |
| DeepSeek key sent to AEra | never — separate clients, separate headers |
| Agent keys / JWTs sent to DeepSeek | never |
| Private keys logged | never; `AeraIdentityClient.__repr__` prints only `agent_id` |
| User's real wallet key | never requested, read or stored — disposable EOAs only |

## 11. Reproduction

```bash
cd aera-agent-security-lab

# Phases 1-4 (offline, no network, no production contact)
../venv/bin/python -m pytest tests -q                 # 53 passed

# Proof that the tests detect a weakened check
sh tools/negative_proof.sh                            # 10 failed -> 53 passed

# Phases 5-9 (live, disposable agents, auto-teardown)
../venv/bin/python -m src.cli.lab --provider mock     --json-out run-artifacts/mock-run.json
../venv/bin/python -m src.cli.lab --provider deepseek --json-out run-artifacts/deepseek-run.json

# Phase 10 (regression)
cd .. && export PATH="$HOME/.local/opt/node/bin:$PATH"
./venv/bin/python -m pytest tests -q                  # 207 passed
```

---

## 12. Conclusion

The deployed AEra Agent Identity Layer **withstood all 14 realistic
agent-to-agent attack scenarios**. A legitimate, fully registered attacker
agent with valid credentials of its own could not impersonate, replay, redirect
or modify communication between two other agents.

Two honest qualifications:

1. **AEra is not an end-to-end content transport** (M-01). It is a strong
   identity, integrity and anti-replay notary for message *envelopes*. Any claim
   of end-to-end content delivery would be false for the current API.
2. **Receiver-side verification is mandatory.** SEC-02 is invisible to AEra by
   construction. An agent implementation that trusts AEra's `200` without
   recomputing `content_hash` from the bytes it actually received is exploitable,
   even though AEra itself behaved correctly.

Recommended follow-up (design only, no production change made):
document requirement 2 in the public Agent SDK guidance, and decide whether
`MessageRequest.content` should be removed from the model or given a defined
meaning — today its presence invites the incorrect assumption that AEra
transports content.
