# Architecture

## Trust model

```
   CLI
    |
    v
 Agent A  --(1) signed A2A envelope -->  AEraLogIn  /api/agents/messages
 (runtime)                               (notarises: sender, key, receiver,
    |                                     signature, expiry, replay)
    | (2) content out-of-band (M-01)
    v
 Agent B  --(3) LOCAL re-verification: content_hash + Ed25519 + sender + receiver
 (runtime)
    |
    | (4) prompt (NO AEra credentials, NO agent keys)
    v
 DeepSeek API
    |
    | (5) completion
    v
 Agent B  --(6) signed A2A response --> AEraLogIn --> notarised
    |
    | (7) content out-of-band
    v
 Agent A  --(8) LOCAL re-verification, expected_sender = B
    |
    v
   CLI

 Agent C (attacker): own agent_id, own owner EOA, own Ed25519 key,
                     own real Agent JWTs. Holds NO key or token of A or B.
```

## Who owns what

| Asset | Owner | Never leaves |
|---|---|---|
| Ed25519 private key | each agent runtime | the `AeraIdentityClient` instance |
| Owner EOA private key | each agent runtime (disposable) | the process |
| Agent JWT | each agent runtime | `Authorization` header to AEra |
| `AGENT_JWT_SECRET` | AEra server only | the server — the lab never imports it |
| DeepSeek API key | Agent B's provider | `Authorization` header to DeepSeek |

The LLM is a **tool**, not an identity. DeepSeek never sees an AEra credential;
AEra never sees the DeepSeek key.

## Module map

| Module | Responsibility |
|---|---|
| `src/config/settings.py` | env loading; `Settings.__repr__` redacts the API key |
| `src/crypto/aera_crypto.py` | **re-exports** production `canonical_json`, `Ed25519Signer`, `verify_signature` |
| `src/identity/aera_client.py` | owner challenge → register → challenge → authenticate; per-audience token cache |
| `src/a2a/protocol.py` | envelope build/sign, relay submission, `LocalVerifier`, `LocalTransport` |
| `src/providers/` | `LLMProvider` ABC, `DeepSeekProvider`, `MockProvider`, `Secret` |
| `src/agents/legit.py` | Agent A (requester), Agent B (LLM worker) |
| `src/attacker/attacks.py` | Agent C + SEC-01..SEC-14 |
| `src/cli/lab.py` | live phases 5–9 with `finally:` teardown |

## Why canonical JSON is imported, not reimplemented

Re-implementing the encoder would risk silent divergence, and every signature
test would then be self-referential. `tests/unit/test_crypto.py` asserts
identity (`lab.canonical_json is prod.canonical_json`), so a future copy-paste
fork fails the suite immediately.

## The two-layer defence and why both are needed

M-01: `POST /api/agents/messages` notarises but does not transport content.

* **AEra** can prove: sender identity, sender key validity, receiver existence
  and status, envelope integrity, expiry, and one-time delivery per
  `(receiver_agent_id, message_id)`.
* **AEra cannot** detect SEC-02 (content swapped while the envelope is left
  intact), because it never receives the bytes.
* Therefore the receiving runtime **must** recompute `content_hash` from the
  bytes it actually received. `LocalTransport` deliberately validates nothing,
  so the test suite cannot accidentally credit the transport for a check.

## Teardown guarantee

`src/cli/lab.py` performs revocation inside a `finally:` block, so an exception
anywhere (including a provider outage) still revokes all three agents. This was
proven when DeepSeek returned HTTP 402: all three agents were revoked and
0 disposable agents remained active.
