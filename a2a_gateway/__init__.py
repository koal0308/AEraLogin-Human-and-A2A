"""Inbound standard-A2A gateway.

This package lets an EXTERNAL agent that speaks the public Agent2Agent protocol
reach an AEra agent. It is strictly additive and sits *beside* the AEra Agent
Identity Layer; it does not modify it.

Three identity levels are kept apart on purpose:

    LEVEL 1  AEra human identity     wallet / Identity NFT / Resonance
    LEVEL 2  AEra agent identity     agent_id / key_id / Ed25519 / Agent JWT
    LEVEL 3  external A2A identity   external peer / transport auth

There is NO automatic trust escalation between them. An authenticated external
peer is an `ExternalPeerIdentity`, never an AEra agent, and it never acquires an
agent_id, an owner_wallet, a capability or a Resonance score by talking to us.

Relationship to the other two A2A surfaces:

    agent/messages.py       AEra-internal notarised relay  (unchanged)
    src/external_a2a/       AEra as A2A CLIENT  (outbound)
    a2a_gateway/            AEra as A2A SERVER  (inbound)  <- this package
"""
from __future__ import annotations

import os


def is_enabled() -> bool:
    """The gateway is off unless explicitly switched on."""
    return os.getenv("AERA_A2A_GATEWAY_ENABLED", "").strip().lower() in (
        "1", "true", "yes", "on")


__all__ = ["is_enabled"]
