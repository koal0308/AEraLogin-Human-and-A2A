"""Legitimate AEra agents A (requester) and B (LLM worker)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import httpx

from ..a2a.protocol import (
    Envelope,
    LocalTransport,
    LocalVerificationError,
    LocalVerifier,
    build_envelope,
    relay,
    relay_error,
)
from ..crypto.aera_crypto import AUD_AGENT_RELAY
from ..identity.aera_client import AeraIdentityClient
from ..providers.base import LLMError, LLMProvider

LEGIT_CAPABILITIES = [
    "agent.authenticate", "agent.read.profile",
    "agent.communicate", "agent.interaction.record",
]


@dataclass
class RelayOutcome:
    accepted: bool
    status: int
    agent_error: Optional[str]


class BaseAgent:
    def __init__(self, http: httpx.Client, *, name: str) -> None:
        self.http = http
        self.name = name
        self.identity = AeraIdentityClient(http, name=name)
        self.verifier: Optional[LocalVerifier] = None

    @property
    def agent_id(self) -> Optional[str]:
        return self.identity.agent_id

    def bootstrap(self, *, label: Optional[str] = None) -> dict:
        data = self.identity.register(capabilities=LEGIT_CAPABILITIES, label=label)
        self.verifier = LocalVerifier(http=self.http, self_agent_id=data["agent_id"])
        return data

    def notarise(self, env: Envelope) -> RelayOutcome:
        """Submit to the REAL relay using a relay-audience JWT."""
        r = relay(self.http, env, bearer=self.identity.token(aud=AUD_AGENT_RELAY))
        return RelayOutcome(r.status_code == 200, r.status_code, relay_error(r))


class AgentA(BaseAgent):
    """Requester. Owns its Ed25519 key; never exposes it."""

    def __init__(self, http: httpx.Client, *, name: str = "AgentA") -> None:
        super().__init__(http, name=name)
        self.peer_agent_id: Optional[str] = None

    def bind_peer(self, peer_agent_id: str) -> None:
        self.peer_agent_id = peer_agent_id
        assert self.verifier is not None
        self.verifier.expected_sender_agent_id = peer_agent_id

    def send_request(self, transport: LocalTransport, *, question: str) -> tuple[Envelope, RelayOutcome]:
        assert self.peer_agent_id, "peer not bound"
        env = build_envelope(self.identity,
                             receiver_agent_id=self.peer_agent_id,
                             content=question.encode("utf-8"))
        outcome = self.notarise(env)
        if outcome.accepted:
            transport.deliver(self.peer_agent_id, env)
        return env, outcome

    def receive_response(self, transport: LocalTransport) -> tuple[Optional[str], Optional[str]]:
        """Returns (answer, rejection_code). A verifies BEFORE trusting."""
        env = transport.pop(self.agent_id or "")
        if env is None:
            return None, "no_message"
        assert self.verifier is not None
        try:
            self.verifier.verify(env)
        except LocalVerificationError as e:
            return None, e.code
        return env.content.decode("utf-8", errors="replace"), None


class AgentB(BaseAgent):
    """LLM worker. Verifies independently, then calls the provider."""

    SYSTEM_PROMPT = (
        "You are an AEra agent worker. Answer concisely and factually."
    )

    def __init__(self, http: httpx.Client, provider: LLMProvider,
                 *, name: str = "AgentB") -> None:
        super().__init__(http, name=name)
        self.provider = provider
        self.last_provider_error: Optional[str] = None

    def handle(self, transport: LocalTransport) -> tuple[Optional[Envelope], Optional[RelayOutcome], Optional[str]]:
        """Pop -> verify locally -> LLM -> signed response. Returns
        (response_envelope, relay_outcome, rejection_code)."""
        env = transport.pop(self.agent_id or "")
        if env is None:
            return None, None, "no_message"
        assert self.verifier is not None
        try:
            p = self.verifier.verify(env)
        except LocalVerificationError as e:
            return None, None, e.code

        try:
            result = self.provider.generate(env.content.decode("utf-8"),
                                            system=self.SYSTEM_PROMPT)
        except LLMError as e:
            # A provider outage is an availability failure, NOT a security
            # failure. Report it distinctly so the attack phase can continue
            # and the report cannot silently claim a successful round trip.
            self.last_provider_error = str(e)
            return None, None, "provider_error"

        resp = build_envelope(self.identity,
                              receiver_agent_id=p["sender_agent_id"],
                              content=result.text.encode("utf-8"))
        outcome = self.notarise(resp)
        if outcome.accepted:
            transport.deliver(p["sender_agent_id"], resp)
        return resp, outcome, None
