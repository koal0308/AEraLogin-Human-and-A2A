# AEra Agent Security Lab

Isolated integration + security test harness for the **already deployed** AEra
Agent Identity Layer.

It proves two things with real traffic:

1. an external LLM (DeepSeek) can operate **behind** an AEra agent identity and
   complete a full A2A round trip, and
2. a legitimate but hostile third agent cannot break that communication.

**This harness contains no production code and modifies none.**
`agent/`, `server.py`, `tests/` and `tools/` are read-only to it.

## Results (2026-09-23, live against https://aeralogin.com)

| | |
|---|---|
| Full A → B → DeepSeek → B → A round trip | **PASS** |
| Attacks blocked | **14 / 14** |
| Live checks | **26 / 26** |
| Lab offline tests | **127 passed** |
| Existing AEra regression | **207 passed, 0 failed** |
| Disposable agents left active | **0** |

### Multi-model network

Three different vendors' models, three independent AEra identities, one identity
layer. The provider of each agent was rotated across three live runs; nothing in
the identity layer changed between them.

| Run | Agent A (orchestrator) | Agent B (analyst) | Agent C (reviewer) | Checks |
|---|---|---|---|---|
| 1 | grok `grok-4.6` | deepseek `deepseek-chat` | claude `claude-sonnet-5` | **32 / 32** |
| 2 | claude `claude-sonnet-5` | grok `grok-4.6` | deepseek `deepseek-chat` | **32 / 32** |
| 3 | deepseek `deepseek-chat` | claude `claude-sonnet-5` | grok `grok-4.6` | **32 / 32** |

All 9 hops: relay `200` **and** independent receiver-side `content_hash` +
Ed25519 verification. No OpenAI dependency anywhere.

> **AEra identity belongs to the Agent Runtime, not to the underlying LLM provider.**

Write-up: [`../agent-agent Prompts/AEra-multi-model-agent-report.md`](../agent-agent%20Prompts/AEra-multi-model-agent-report.md)

Full write-up: [`docs/AEra-agent-security-test-report.md`](docs/AEra-agent-security-test-report.md)
Attack details: [`docs/attack-matrix.md`](docs/attack-matrix.md)
Design: [`docs/architecture.md`](docs/architecture.md)
API ground truth: [`../docs/AEra-agent-api-discovery.md`](../docs/AEra-agent-api-discovery.md)

## The one thing to remember

`POST /api/agents/messages` **notarises** envelopes; it does **not** transport
content (finding M-01). AEra proves *who* sent *what hash* to *whom*, once,
within the TTL — but never sees the bytes.

**Therefore every AEra agent must recompute `content_hash` from the content it
actually received and verify the sender's Ed25519 signature locally.** Attack
SEC-02 is invisible to AEra by construction and is caught only by that local
check.

## Setup

```bash
cp .env.example .env     # then fill in the provider keys you want to use
```

Provider keys are read from the environment only. They are never logged, never
placed in an A2A payload and never sent to AEraLogIn — and no AEra JWT or private
key is ever sent to a provider. `.env` is gitignored. Keys are also picked up from
the parent AEra `.env`; only the `DEEPSEEK_`/`XAI_`/`GROK_`/`ANTHROPIC_`/`CLAUDE_`
prefixes are importable, so no AEra secret can be pulled in.

## Run

```bash
# Phases 1-4 — offline, no network
../venv/bin/python -m pytest tests -q

# Prove the tests actually detect a weakened check
sh tools/negative_proof.sh

# Phases 5-9 — live, disposable agents, automatic teardown
../venv/bin/python -m src.cli.lab --provider mock
../venv/bin/python -m src.cli.lab --provider deepseek \
    --json-out run-artifacts/deepseek-run.json

# Multi-model network — live, three vendors, three identities
../venv/bin/python -m src.cli.network --agent-a-provider grok \
    --agent-b-provider deepseek --agent-c-provider claude \
    --json-out run-artifacts/network-run1.json

# Phase 10 — existing AEra regression
cd .. && export PATH="$HOME/.local/opt/node/bin:$PATH"
./venv/bin/python -m pytest tests -q
```

Options: `--question`, `--base-url`, `--skip-attacks`, `--json-out`.

## Safety properties

* **Disposable identities.** Every run generates fresh owner EOAs locally. Your
  real wallet key is never requested, read or stored.
* **Guaranteed teardown.** All three agents are revoked in a `finally:` block —
  proven when DeepSeek returned HTTP 402 mid-run and teardown still completed.
* **No invented API.** Only the 14 endpoints that actually exist are used.
* **No bypasses.** Real Ed25519 keys, real JWTs, real signatures, real replay
  protection. No security check is disabled anywhere.
* **Production canonical JSON.** The encoder is imported from `agent.crypto`,
  and a test asserts object identity so a future fork fails immediately.

## Layout

```
src/config/      settings + secret redaction
src/crypto/      re-export of the PRODUCTION canonical JSON / Ed25519
src/identity/    owner-challenge -> register -> challenge -> authenticate
src/a2a/         envelope build/sign, relay, LocalVerifier, LocalTransport
src/providers/   LLMProvider ABC, Grok/DeepSeek/Claude/Mock, registry, Secret
src/agents/      Agent A (requester), Agent B (LLM worker), RoleAgent, reference
src/attacker/    Agent X (ATTACKER) + SEC-01..SEC-14
src/cli/lab.py       live security runner, phases 5-9
src/cli/network.py   live multi-model network runner
tests/unit/         crypto, providers, config, multi-model
tests/integration/  three-identity A2A network
tests/security/     local attack tests
tools/              negative_proof.sh, negative_proof_multi_model.sh
```

## Adding another model backend

Implement `LLMProvider.generate(prompt, system=None) -> LLMResult` in
`src/providers/` and add it to `src/providers/registry.py::_BUILDERS`. The
identity layer is entirely unaffected — the model is a tool, never an identity.
Backends speaking the OpenAI wire format only need to subclass
`OpenAICompatibleProvider` and set a base URL and model (that is all
`GrokProvider` and `DeepSeekProvider` are).

## Naming: Agent C vs Agent X

`Agent C` is a **legitimate** reviewer agent in the multi-model network.
The **attacker** is `Agent X` (`src/attacker/attacks.py`). `AgentC = AgentX`
survives only as a deprecated alias and must not be used in new code.
