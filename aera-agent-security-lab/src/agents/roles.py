"""Role-based agents for the multi-model network.

Identity principle enforced by construction:

    LLM PROVIDER != AGENT IDENTITY

Every agent owns its own `agent_id`, `key_id`, Ed25519 private key and JWT
lifecycle via `AeraIdentityClient`. The provider is an injected dependency that
the identity layer knows nothing about -- which is exactly what makes the
provider-swap test possible.
"""
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
)
from ..agents.legit import LEGIT_CAPABILITIES, BaseAgent, RelayOutcome
from ..providers.base import LLMError, LLMProvider

ORCHESTRATOR = "orchestrator"
ANALYST = "analyst"
REVIEWER = "reviewer"


@dataclass
class HopResult:
    """One A2A hop: AEra notarisation + receiver-side local verification."""
    sender: str
    receiver: str
    relay_ok: bool
    relay_status: Optional[int]
    relay_error: Optional[str]
    local_ok: bool
    local_error: Optional[str]
    message_id: str

    @property
    def ok(self) -> bool:
        return self.relay_ok and self.local_ok


@dataclass
class ProviderCall:
    provider: str
    model: str
    ok: bool
    error: Optional[str] = None
    chars: int = 0


class RoleAgent(BaseAgent):
    """An AEra agent with a role and an interchangeable LLM provider."""

    def __init__(self, http: httpx.Client, provider: LLMProvider, *,
                 name: str, role: str) -> None:
        super().__init__(http, name=name)
        self.provider = provider
        self.role = role
        self.last_provider_error: Optional[str] = None

    # -- identity ---------------------------------------------------------- #
    def bootstrap(self, *, label: Optional[str] = None) -> dict:
        data = self.identity.register(capabilities=LEGIT_CAPABILITIES,
                                      label=label or f"lab-agent-{self.role}")
        self.verifier = LocalVerifier(http=self.http, self_agent_id=data["agent_id"])
        return data

    @property
    def provider_name(self) -> str:
        return self.provider.name

    @property
    def model(self) -> str:
        return getattr(self.provider, "model", "-")

    def describe(self) -> str:
        return (f"{self.name}\n"
                f"  role:     {self.role}\n"
                f"  provider: {self.provider_name}\n"
                f"  model:    {self.model}\n"
                f"  agent_id: {self.agent_id}\n"
                f"  key_id:   {self.identity.key_id}")

    # -- LLM --------------------------------------------------------------- #
    def think(self, prompt: str, *, system: Optional[str] = None) -> tuple[Optional[str], ProviderCall]:
        """Call the provider. An outage is an availability failure, never a
        security failure, and is reported as a distinct state."""
        try:
            res = self.provider.generate(prompt, system=system)
        except LLMError as e:
            self.last_provider_error = str(e)
            return None, ProviderCall(self.provider_name, self.model, False, str(e))
        return res.text, ProviderCall(self.provider_name, self.model, True,
                                      chars=len(res.text))

    # -- A2A --------------------------------------------------------------- #
    def send(self, transport: LocalTransport, *, receiver: "RoleAgent",
             content: str) -> tuple[Envelope, RelayOutcome]:
        env = build_envelope(self.identity,
                             receiver_agent_id=receiver.agent_id or "",
                             content=content.encode("utf-8"))
        outcome = self.notarise(env)
        if outcome.accepted:
            transport.deliver(receiver.agent_id or "", env)
        return env, outcome

    def receive(self, transport: LocalTransport, *,
                expected_sender: Optional[str] = None
                ) -> tuple[Optional[str], Optional[str], Optional[Envelope]]:
        """Pop and INDEPENDENTLY verify. Returns (content, error, envelope).

        The receiver never trusts a message merely because AEra accepted the
        JWT: content_hash is recomputed from the bytes actually received and
        the Ed25519 signature is checked locally.
        """
        env = transport.pop(self.agent_id or "")
        if env is None:
            return None, "no_message", None
        assert self.verifier is not None
        previous = self.verifier.expected_sender_agent_id
        if expected_sender:
            self.verifier.expected_sender_agent_id = expected_sender
        try:
            self.verifier.verify(env)
        except LocalVerificationError as e:
            return None, e.code, env
        finally:
            self.verifier.expected_sender_agent_id = previous
        return env.content.decode("utf-8", errors="replace"), None, env


def hop(sender: RoleAgent, receiver: RoleAgent, transport: LocalTransport,
        content: str) -> tuple[Optional[str], HopResult]:
    """One complete A2A hop: sign -> AEra notarise -> deliver -> verify."""
    env, outcome = sender.send(transport, receiver=receiver, content=content)
    if not outcome.accepted:
        return None, HopResult(sender.name, receiver.name, False, outcome.status,
                               outcome.agent_error, False, "not_delivered",
                               env.message_id)
    body, err, _ = receiver.receive(transport, expected_sender=sender.agent_id)
    return body, HopResult(sender.name, receiver.name, True, outcome.status,
                           outcome.agent_error, err is None, err, env.message_id)


# --------------------------------------------------------------------------- #
# Role prompts
# --------------------------------------------------------------------------- #
ORCHESTRATOR_SYSTEM = (
    "You are the orchestrator agent in a multi-agent network. Be concise and "
    "precise. Do not invent facts."
)
ANALYST_SYSTEM = (
    "You are the analyst agent. Produce a structured, independent analysis. "
    "Explicitly list your assumptions and your uncertainties. Do not speculate "
    "beyond the information given."
)
REVIEWER_SYSTEM = (
    "You are the reviewer agent. Review the analysis independently. Identify "
    "factual errors, missing security considerations, unsupported assumptions "
    "and contradictions. State your confidence and remaining uncertainty."
)

ANALYST_TASK = (
    "Independently analyze the AEra Agent Identity Layer. Focus on "
    "authentication, cryptographic identity, replay protection and possible "
    "attack surfaces.\n\n"
    "Base your analysis ONLY on the reference material below. If something is "
    "not covered by it, say so explicitly instead of speculating.\n\n"
    "Original question:\n{question}\n\n"
    "=== REFERENCE MATERIAL (verified from the deployed implementation) ===\n"
    "{context}\n=== END REFERENCE MATERIAL ==="
)
REVIEWER_TASK = (
    "Review this analysis independently. Identify factual errors, missing "
    "security considerations, unsupported assumptions and contradictions.\n\n"
    "Check the analysis against the reference material below.\n\n"
    "Original question:\n{question}\n\n"
    "=== REFERENCE MATERIAL (verified from the deployed implementation) ===\n"
    "{context}\n=== END REFERENCE MATERIAL ===\n\n"
    "Analysis to review:\n{analysis}"
)
SYNTHESIS_TASK = (
    "Synthesize a final answer from an analyst's analysis and a reviewer's "
    "independent review. Where they disagree, say so explicitly.\n\n"
    "Original question:\n{question}\n\nAnalyst analysis:\n{analysis}\n\n"
    "Reviewer review:\n{review}"
)
