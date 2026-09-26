"""Metadata-only audit for inbound A2A traffic.

Logged: who called (as far as we know), what they asked for, which agent was
targeted, what happened, how long it took.

Never logged: AEra JWTs, AGENT_JWT_SECRET, private keys, bearer tokens, API
keys, wallet keys, or full message content. Message text is reduced to a length
and a truncated non-reversible fingerprint so that duplicates can be correlated
without retaining what was said.
"""
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger("aera.a2a_gateway")

#: Anything matching these is scrubbed wherever it appears in a record.
_CREDENTIAL_MARKERS = (
    "eyJ", "-----BEGIN", "AGENT_JWT_SECRET", "TOKEN_SECRET",
    "PRIVATE KEY", "Bearer ", "ed25519:",
)

_MAX_VALUE_LEN = 300


@dataclass
class InboundAuditRecord:
    timestamp: str
    request_id: Optional[str]
    message_id: Optional[str]
    peer: dict[str, Any]
    auth_method: str
    target_agent: Optional[str]
    method: Optional[str]
    skill_id: Optional[str]
    protocol_version: Optional[str]
    result: str
    http_status: int
    error_code: Optional[int] = None
    latency_ms: Optional[float] = None
    content_bytes: Optional[int] = None
    content_fingerprint: Optional[str] = None
    #: AEra's own assessment of the peer, when trust observation is enabled.
    #: Level and confidence band only -- never the factors, never the score,
    #: never the owner's wallet or standing. This line can end up in a log
    #: aggregator, and the tuning of a security control does not belong there.
    trust: Optional[dict[str, Any]] = None

    def to_dict(self) -> dict[str, Any]:
        return scrub(asdict(self))


def content_fingerprint(text: str) -> str:
    """Short, non-reversible marker so replays can be correlated in logs."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def scrub(value: Any) -> Any:
    if isinstance(value, str):
        for marker in _CREDENTIAL_MARKERS:
            if marker in value:
                return "[redacted]"
        if len(value) > _MAX_VALUE_LEN:
            return value[:_MAX_VALUE_LEN] + "...[truncated]"
        return value
    if isinstance(value, dict):
        return {k: ("[redacted]" if _is_secret_key(k) else scrub(v))
                for k, v in value.items()}
    if isinstance(value, list):
        return [scrub(v) for v in value[:50]]
    return value


def _is_secret_key(key: Any) -> bool:
    if not isinstance(key, str):
        return False
    lowered = key.lower()
    return any(marker in lowered for marker in
               ("token", "secret", "password", "private", "authorization",
                "api_key", "apikey", "credential", "wallet"))


def build_record(*, request_id: Any, message_id: Optional[str], peer,
                 target_agent: Optional[str], method: Optional[str],
                 skill_id: Optional[str], protocol_version: Optional[str],
                 result: str, http_status: int,
                 error_code: Optional[int] = None,
                 latency_ms: Optional[float] = None,
                 content: Optional[str] = None,
                 trust: Optional[dict[str, Any]] = None) -> InboundAuditRecord:
    return InboundAuditRecord(
        timestamp=datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        request_id=str(request_id) if request_id is not None else None,
        message_id=message_id,
        peer=peer.to_audit_dict() if peer is not None else {},
        auth_method=getattr(peer, "authentication_method", "none"),
        target_agent=target_agent,
        method=method,
        skill_id=skill_id,
        protocol_version=protocol_version,
        result=result,
        http_status=http_status,
        error_code=error_code,
        latency_ms=round(latency_ms, 2) if latency_ms is not None else None,
        content_bytes=len(content.encode("utf-8")) if content is not None else None,
        content_fingerprint=content_fingerprint(content) if content else None,
        trust=trust,
    )


def emit(record: InboundAuditRecord) -> dict[str, Any]:
    payload = record.to_dict()
    logger.info("a2a_inbound %s", json.dumps(payload, sort_keys=True, default=str))
    return payload
