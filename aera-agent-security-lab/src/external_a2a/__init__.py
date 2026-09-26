"""External (standard) A2A client adapter.

This package speaks the PUBLIC Agent2Agent protocol to agents operated by third
parties. It is deliberately SEPARATE from `src.a2a.protocol`, which implements
AEra's INTERNAL notarised envelope protocol. The two are not the same protocol
and this package never mixes them:

    src/a2a/protocol.py   -> AEra internal A2A (Ed25519 envelope + AEra relay)
    src/external_a2a/     -> standard A2A (Agent Card + JSON-RPC over HTTPS)

See docs/external-a2a.md for the documented differences.
"""
from .audit import AuditLog, AuditRecord, build_record
from .auth import (
    A2AAuthAdapter,
    ApiKeyAdapter,
    BearerTokenAdapter,
    NoAuthAdapter,
    describe_required_auth,
    select_adapter,
)
from .card import (
    AgentCard,
    AgentInterface,
    AgentSkill,
    CardValidationError,
    parse_agent_card,
)
from .client import A2AClient, A2AResponse, discover_agent, get_agent_card
from .net import NetPolicy
from .errors import (
    A2AAuthError,
    A2AError,
    A2ANetworkError,
    A2AProtocolError,
    A2ARemoteError,
)

__all__ = [
    "AgentCard",
    "AgentInterface",
    "AgentSkill",
    "CardValidationError",
    "parse_agent_card",
    "A2AClient",
    "A2AResponse",
    "discover_agent",
    "get_agent_card",
    "NetPolicy",
    "A2AAuthAdapter",
    "NoAuthAdapter",
    "BearerTokenAdapter",
    "ApiKeyAdapter",
    "select_adapter",
    "describe_required_auth",
    "AuditLog",
    "AuditRecord",
    "build_record",
    "A2AError",
    "A2ANetworkError",
    "A2AAuthError",
    "A2AProtocolError",
    "A2ARemoteError",
]
