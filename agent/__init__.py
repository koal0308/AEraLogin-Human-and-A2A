"""AEraLogIn – Agent Identity Layer (Phase 1).

Additive subsystem. Fully disabled unless env `AGENT_LAYER_ENABLED=true`.
Never mutates existing OAuth / Wallet / NFT logic.

Spec: agent-agent Prompts/AGENT_IDENTITY_SPEC.md v1.2
"""
from __future__ import annotations

import os

__version__ = "1.0.0-phase1"


def is_enabled() -> bool:
    return os.getenv("AGENT_LAYER_ENABLED", "false").strip().lower() in {
        "1", "true", "yes", "on",
    }
