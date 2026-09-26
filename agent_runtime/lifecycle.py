"""Runtime lifecycle states.

The important property here is that health is *honest*. A process that is
running but whose agent identity has been revoked is NOT healthy — it cannot do
the one thing it exists to do. Reporting it as healthy would hide exactly the
condition an operator most needs to see, and §19 of the brief requires the
runtime to react to revocation rather than carry on.

So `REVOKED` and `DEGRADED` are explicit terminal-ish states, and `is_healthy`
is false for both.
"""
from __future__ import annotations

import enum
import threading
from dataclasses import dataclass, field
from typing import Any, Optional


class RuntimeState(str, enum.Enum):
    STARTING = "STARTING"        # process up, nothing proven yet
    READY = "READY"              # key loaded, identity known, not yet authenticated
    AUTHENTICATING = "AUTHENTICATING"
    RUNNING = "RUNNING"          # holds a valid Agent JWT, serving requests
    DEGRADED = "DEGRADED"        # reachable but impaired (e.g. provider down)
    REVOKED = "REVOKED"          # AEra has revoked this agent or its key
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"


#: States in which the runtime may accept and answer inbound A2A work.
SERVING_STATES = frozenset({RuntimeState.RUNNING, RuntimeState.DEGRADED})

#: Once revoked, a runtime never returns to service on its own. Re-authorisation
#: is an owner action, not something the runtime can grant itself.
TERMINAL_STATES = frozenset({RuntimeState.REVOKED, RuntimeState.STOPPED})


@dataclass
class LifecycleStatus:
    """Thread-safe current state plus a short, metadata-only reason."""

    state: RuntimeState = RuntimeState.STARTING
    reason: str = ""
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def set(self, state: RuntimeState, reason: str = "") -> None:
        with self._lock:
            if self.state in TERMINAL_STATES and state not in TERMINAL_STATES:
                # A revoked agent must not be able to talk itself back into
                # service because a later call happened to succeed.
                return
            self.state = state
            self.reason = reason

    def get(self) -> RuntimeState:
        with self._lock:
            return self.state

    @property
    def is_serving(self) -> bool:
        return self.get() in SERVING_STATES

    @property
    def is_healthy(self) -> bool:
        return self.get() is RuntimeState.RUNNING

    @property
    def is_revoked(self) -> bool:
        return self.get() is RuntimeState.REVOKED

    def snapshot(self, extra: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        """Metadata only — never tokens, keys or provider credentials."""
        with self._lock:
            payload: dict[str, Any] = {
                "state": self.state.value,
                "healthy": self.state is RuntimeState.RUNNING,
                "serving": self.state in SERVING_STATES,
            }
            if self.reason:
                payload["reason"] = self.reason
        if extra:
            payload.update(extra)
        return payload
