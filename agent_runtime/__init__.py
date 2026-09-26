"""AEra packaged Agent Runtime.

The process that actually *is* an agent: it holds the Ed25519 private key,
authenticates to AEra with it, receives A2A messages through the gateway, asks
an LLM provider for an answer and replies.

What this package is NOT:

  * a second identity system. `agent_id`, `key_id`, the Ed25519 keypair, the
    Agent JWT, owner challenges, capabilities, JTI and revocation all remain
    the Agent Identity Layer's business. This package consumes them.
  * a holder of the owner's wallet key. Owner approval is a separate human
    action performed through the dashboard.
  * a holder of `AGENT_JWT_SECRET`. AEra signs tokens; the runtime only
    presents them.

Layout:

  config.py         configuration, with secrets kept out of everything publishable
  keystore.py       local Ed25519 key: generate, seal, load, sign
  identity.py       challenge/authenticate against AEra, JWT lifecycle, revocation
  internal_auth.py  the authenticated Gateway <-> Runtime channel
  lifecycle.py      runtime states and honest health
  messaging.py      inbound message -> provider -> reply, with no tool dispatch
  provider.py       LLM provider abstraction (provider is a tool, not an identity)
  server.py         the Unix-socket server process
  __main__.py       CLI: keygen / run / health
"""
from __future__ import annotations

__all__ = ["__version__"]

__version__ = "1.0.0"
