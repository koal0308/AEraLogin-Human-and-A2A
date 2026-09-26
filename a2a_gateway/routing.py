"""Target agent routing.

The external caller may NAME a target agent. It may not describe one. Every
property that matters -- existence, status, key state, capabilities -- is read
from AEra's own database, never taken from the request.

Specifically ignored if present in the payload: owner_wallet, capabilities,
trust level, permissions, key ids. Supplying them changes nothing.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from .constants import (
    ERR_INVALID_PARAMS,
    ERR_UNSUPPORTED_OPERATION,
    SKILL_TO_CAPABILITY,
)
from .validation import GatewayError

#: Deliberately identical wording for "no such agent" and "not routable", so the
#: gateway cannot be used to enumerate which agent ids exist.
_OPAQUE_UNKNOWN = "target agent is not available"


@dataclass(frozen=True)
class RoutedAgent:
    """An AEra agent that we have confirmed is a legitimate routing target."""

    agent_id: str
    status: str
    capabilities: tuple[str, ...]
    active_key_count: int
    label: Optional[str] = None
    created_at: Optional[str] = None

    def public_profile(self) -> dict[str, Any]:
        """Exactly what an external caller may learn. No wallet, no keys."""
        return {
            "agent_id": self.agent_id,
            "status": self.status,
            "capabilities": list(self.capabilities),
            "active_keys": self.active_key_count,
            "created_at": self.created_at,
            "label": self.label,
        }


def _load_agent(conn, agent_id: str) -> Optional[dict]:
    row = conn.execute(
        "SELECT agent_id, status, capabilities, label, created_at "
        "FROM agents WHERE agent_id = ?",
        (agent_id,),
    ).fetchone()
    if row is None:
        return None
    keys = row.keys() if hasattr(row, "keys") else None
    if keys is not None:
        return {k: row[k] for k in keys}
    return {
        "agent_id": row[0], "status": row[1], "capabilities": row[2],
        "label": row[3], "created_at": row[4],
    }


def _count_active_keys(conn, agent_id: str) -> int:
    row = conn.execute(
        "SELECT COUNT(*) FROM agent_keys WHERE agent_id = ? AND status = 'active'",
        (agent_id,),
    ).fetchone()
    return int(row[0]) if row else 0


def resolve_target_agent(conn, agent_id: str, *, skill_id: Optional[str] = None
                         ) -> RoutedAgent:
    """Resolve and authorise a routing target, or raise GatewayError.

    Conditions, all checked against AEra's own data:
      * the agent exists
      * its status is 'active' (revoked agents are never routable)
      * it has at least one active key
      * it holds the capability the requested skill maps to
    """
    from agent.repository import loads_capabilities  # existing helper, unchanged

    record = _load_agent(conn, agent_id)
    if record is None:
        raise GatewayError(ERR_INVALID_PARAMS, _OPAQUE_UNKNOWN,
                           internal=f"agent {agent_id} does not exist")

    status = (record.get("status") or "").lower()
    if status != "active":
        # Same external wording as "unknown": a revoked agent must not be
        # distinguishable from a nonexistent one by an outside observer.
        # The real status goes to the internal audit field only.
        raise GatewayError(ERR_INVALID_PARAMS, _OPAQUE_UNKNOWN,
                           internal=f"agent {agent_id} has status {status!r}")

    active_keys = _count_active_keys(conn, agent_id)
    if active_keys < 1:
        raise GatewayError(ERR_INVALID_PARAMS, _OPAQUE_UNKNOWN,
                           internal=f"agent {agent_id} has no active key")

    capabilities = tuple(loads_capabilities(record.get("capabilities")))

    if skill_id is not None:
        required = SKILL_TO_CAPABILITY.get(skill_id)
        if required is None:
            raise GatewayError(ERR_UNSUPPORTED_OPERATION,
                               f"skill '{skill_id}' is not offered by this gateway")
        if required not in capabilities:
            raise GatewayError(
                ERR_UNSUPPORTED_OPERATION,
                f"target agent does not offer the '{required}' capability",
                internal=f"agent {agent_id} lacks {required}")

    return RoutedAgent(
        agent_id=record["agent_id"],
        status=status,
        capabilities=capabilities,
        active_key_count=active_keys,
        label=record.get("label"),
        created_at=record.get("created_at"),
    )
