"""Audit trail for external A2A interactions.

Deliberately records *metadata only*. No bearer token, no API key, no AEra JWT,
no Ed25519 private key and no wallet key is ever written here. The auth field
stores the scheme *name* (e.g. "bearer"), never the credential.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

#: Substrings that must never appear in an audit record value.
_FORBIDDEN_MARKERS = ("eyJ", "-----BEGIN", "AGENT_JWT_SECRET", "PRIVATE KEY")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class AuditRecord:
    """One external A2A interaction, as it is safe to persist."""

    timestamp: str
    aera_agent_id: Optional[str]
    external_agent_name: Optional[str]
    agent_card_url: Optional[str]
    endpoint_url: Optional[str]
    protocol_version: Optional[str]
    skill_id: Optional[str]
    auth_scheme: str
    http_status: Optional[int]
    request_id: Optional[str]
    task_id: Optional[str]
    success: bool
    error_category: Optional[str] = None
    error_message: Optional[str] = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _scrub(value: Any) -> Any:
    """Replace anything that looks like a credential. Defence in depth."""
    if isinstance(value, str):
        for marker in _FORBIDDEN_MARKERS:
            if marker in value:
                return "[redacted: credential-like value]"
        if len(value) > 500:
            return value[:500] + "...[truncated]"
    if isinstance(value, dict):
        return {k: _scrub(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub(v) for v in value[:50]]
    return value


def build_record(
    *,
    aera_agent_id: Optional[str],
    card: Any = None,
    interface: Any = None,
    skill_id: Optional[str] = None,
    auth_scheme: str = "none",
    http_status: Optional[int] = None,
    request_id: Optional[str] = None,
    task_id: Optional[str] = None,
    success: bool = False,
    error_category: Optional[str] = None,
    error_message: Optional[str] = None,
    **extra: Any,
) -> AuditRecord:
    return AuditRecord(
        timestamp=_utc_now(),
        aera_agent_id=aera_agent_id,
        external_agent_name=getattr(card, "name", None),
        agent_card_url=getattr(card, "card_url", None),
        endpoint_url=getattr(interface, "url", None),
        protocol_version=getattr(interface, "protocol_version", None)
        or getattr(card, "protocol_version", None),
        skill_id=skill_id,
        auth_scheme=auth_scheme,
        http_status=http_status,
        request_id=request_id,
        task_id=task_id,
        success=success,
        error_category=error_category,
        error_message=_scrub(error_message) if error_message else None,
        extra={k: _scrub(v) for k, v in extra.items()},
    )


class AuditLog:
    """Append-only JSONL audit log."""

    def __init__(self, path: Optional[Path | str] = None) -> None:
        self.path = Path(path) if path else None
        self.records: list[AuditRecord] = []

    def append(self, record: AuditRecord) -> AuditRecord:
        payload = _scrub(record.to_dict())
        self.records.append(record)
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")
        return record

    def render(self) -> str:
        return "\n".join(
            json.dumps(_scrub(r.to_dict()), ensure_ascii=False, sort_keys=True)
            for r in self.records
        )
