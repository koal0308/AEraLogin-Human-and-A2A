"""Capability helpers."""
from __future__ import annotations

from .constants import CAPABILITY_ALLOWLIST, DEFAULT_CAPABILITIES


def normalize(requested: list[str] | None) -> list[str]:
    if not requested:
        return list(DEFAULT_CAPABILITIES)
    result = []
    for c in requested:
        if isinstance(c, str) and c in CAPABILITY_ALLOWLIST:
            result.append(c)
    if not result:
        result = list(DEFAULT_CAPABILITIES)
    return sorted(set(result))


def require(jwt_payload: dict, cap: str) -> None:
    from .tokens import AgentJWTError
    caps = jwt_payload.get("capabilities") or []
    if cap not in caps:
        raise AgentJWTError("capability_denied", 403)
