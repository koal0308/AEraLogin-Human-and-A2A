# Attack Matrix

Machine-readable source of truth: `run-artifacts/deepseek-run.json` (key `attacks`).

Layer legend:

| Layer | Meaning |
|---|---|
| `AERA` | Rejected by the deployed production Agent Identity Layer (real HTTP response) |
| `LOCAL` | Rejected by the receiving agent runtime, because AEra structurally cannot see it (M-01) |

| Test | Attack | Layer | Expected | Observed (live) |
|---|---|---|---|---|
| SEC-01 | Message replay | AERA | BLOCK | `401 message_replay` |
| SEC-02 | Content tampering | LOCAL | BLOCK | `content_hash_mismatch` |
| SEC-03 | Content hash manipulation | AERA | BLOCK | `401 message_signature_invalid` |
| SEC-04 | Sender spoofing | AERA | BLOCK | `401 sender_jwt_mismatch` |
| SEC-05 | Key-ID spoofing | AERA | BLOCK | `401 revoked_key` |
| SEC-06 | JWT/sender mismatch | AERA | BLOCK | `401 sender_jwt_mismatch` |
| SEC-07 | Receiver manipulation | AERA | BLOCK | `401 message_signature_invalid` |
| SEC-08 | Expired message | AERA | BLOCK | `401 expired_message` |
| SEC-09 | Invalid JWT (10 variants) | AERA | BLOCK | all `401` |
| SEC-10 | Cross-audience JWT | AERA | BLOCK | `401 invalid_audience` |
| SEC-11 | JTI / identity binding (5 mutations) | AERA | BLOCK | all `401 invalid_signature` |
| SEC-12 | Fake B response | LOCAL | BLOCK | `message_signature_invalid` |
| SEC-13 | Response replay | AERA | BLOCK | `401 message_replay` |
| SEC-14 | Signed field mutation (9 fields + injected key) | AERA | BLOCK | all `401` |

## SEC-09 sub-variants

| Variant | Observed |
|---|---|
| missing bearer | `401 missing_bearer` |
| malformed | `401 invalid_token` |
| random `aaa.bbb.ccc` | `401 invalid_token` |
| expired | `401 invalid_signature` |
| wrong issuer | `401 invalid_signature` |
| wrong audience | `401 invalid_signature` |
| wrong typ | `401 invalid_signature` |
| unknown JTI | `401 invalid_signature` |
| `alg=none` | `401 invalid_token` |
| genuinely revoked JTI | `401 jti_revoked` |

Note: variants forged with an attacker-chosen secret fail at the HMAC check
before any claim-specific check is reached. This is correct precedence — the
attacker does not hold `AGENT_JWT_SECRET`. The revoked-JTI case uses a REAL
server-issued token, really revoked through `POST /api/agents/tokens/revoke`,
and is tested on its own audience so the rejection cannot be attributed to an
audience mismatch.

## SEC-11 sub-variants

`sub`, `key_id`, `aud`, `owner_wallet`, `jti` each mutated and re-signed with an
attacker secret → all `401 invalid_signature`.

## SEC-14 sub-variants

| Field mutated | AEra | Local runtime |
|---|---|---|
| `message_id` | `message_signature_invalid` | `message_signature_invalid` |
| `sender_agent_id` | `sender_jwt_mismatch` | `unknown_key` |
| `sender_key_id` | `revoked_key` | `unknown_key` |
| `receiver_agent_id` | `message_signature_invalid` | `receiver_mismatch` |
| `issued_at` | `message_signature_invalid` | `message_signature_invalid` |
| `expires_at` | `message_signature_invalid` | `message_signature_invalid` |
| `content_hash` | `message_signature_invalid` | `content_hash_mismatch` |
| `protocol` | `message_signature_invalid` | `message_signature_invalid` |
| `version` | `message_signature_invalid` | `message_signature_invalid` |
| injected extra key | `message_signature_invalid` | `message_signature_invalid` |
