"""The internal Gateway <-> Runtime channel.

THREAT MODEL
------------
The public gateway is unauthenticated. If an external caller could influence
which local process the gateway talks to, the gateway would become an SSRF
engine with our own credentials attached. If any local process could talk to a
runtime, a compromised unprivileged account on this host would be able to make
an AEra agent answer on its behalf.

Both are closed structurally rather than by filtering.

1. NO CALLER-SUPPLIED ADDRESS EXISTS.
   The socket path is *derived* from the agent id:

       <runtime dir>/<hex sha256(agent_id)[:32]>.sock

   There is no field, header or metadata key anywhere in the inbound A2A
   request that can name a runtime, a host, a port or a path. The gateway
   cannot be persuaded to connect somewhere else, because there is no input
   that feeds the address. A hostile `agent_id` maps to a socket that simply
   does not exist, and the agent id itself is validated and resolved against
   AEra's database before we get here.

2. "LOCALHOST IS TRUSTED" IS NOT USED.
   Two independent, *directional* protections:

   * Gateway -> Runtime: every request carries an HMAC-SHA256 tag over the
     canonical envelope, keyed with a secret shared only between the AEra
     process and the runtime process. A local attacker without that secret
     cannot invoke a runtime, even with write access to the socket.

   * Runtime -> Gateway: the runtime signs its response with the agent's
     **Ed25519 private key**, and the gateway verifies that signature against
     the public key already registered in AEra's database.

   The second direction deliberately introduces no new secret. The existing
   Agent Identity Layer stays the single cryptographic authority: a process
   that cannot produce a valid Ed25519 signature cannot impersonate an agent's
   runtime, no matter what else it controls.

3. THE INTERNAL SECRET IS NEVER REACHABLE FROM OUTSIDE.
   It appears in no response, no Agent Card, no audit record and no error
   message. It is an *inbound* verification key only; nothing the gateway
   returns to an external caller is derived from it.

Replay of internal envelopes is bounded by a timestamp window; end-to-end
message replay remains the gateway's existing job and is not duplicated here.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from pathlib import Path
from typing import Any, Optional

#: How far apart the two local clocks may be. Same machine, so this is tight.
MAX_ENVELOPE_AGE_SECONDS = 30

#: Where per-agent runtime sockets live. Operator-controlled, never request-controlled.
DEFAULT_RUNTIME_DIR = "/tmp/aera-runtime"

ENV_SECRET = "AERA_RUNTIME_INTERNAL_SECRET"
ENV_RUNTIME_DIR = "AERA_RUNTIME_DIR"


class InternalAuthError(Exception):
    """An internal envelope was not authentic, fresh or well-formed."""


def runtime_dir() -> Path:
    return Path(os.getenv(ENV_RUNTIME_DIR) or DEFAULT_RUNTIME_DIR)


def internal_secret() -> Optional[str]:
    """The shared local secret, or None if the channel is not configured."""
    value = (os.getenv(ENV_SECRET) or "").strip()
    return value or None


def socket_path_for(agent_id: str) -> Path:
    """Derive the socket path for an agent. Pure function of the agent id.

    Hashed rather than used verbatim so that an agent id can never escape the
    runtime directory through path traversal, and so the filename length is
    bounded (Unix socket paths are limited to ~108 bytes).
    """
    if not agent_id or not isinstance(agent_id, str):
        raise InternalAuthError("agent id required to locate a runtime")
    digest = hashlib.sha256(agent_id.encode("utf-8")).hexdigest()[:32]
    return runtime_dir() / f"{digest}.sock"


def _canonical(payload: dict[str, Any]) -> bytes:
    """Deterministic bytes for signing. Sorted keys, no whitespace drift."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def sign_envelope(payload: dict[str, Any], secret: str) -> str:
    return hmac.new(secret.encode("utf-8"), _canonical(payload),
                    hashlib.sha256).hexdigest()


def build_envelope(*, agent_id: str, request_id: str, body: dict[str, Any],
                   secret: str, issued_at: Optional[int] = None) -> dict[str, Any]:
    """Wrap a call to a runtime in an authenticated envelope."""
    payload = {
        "agent_id": agent_id,
        "request_id": request_id,
        "issued_at": int(issued_at if issued_at is not None else time.time()),
        "body": body,
    }
    return {"payload": payload, "tag": sign_envelope(payload, secret)}


def verify_envelope(envelope: Any, secret: str, *,
                    now: Optional[float] = None) -> dict[str, Any]:
    """Verify an inbound envelope and return its payload, or raise.

    Order matters: structure, then authenticity, then freshness. Freshness is
    checked last so that an unauthenticated caller cannot use timing
    differences to probe our clock.
    """
    if not isinstance(envelope, dict):
        raise InternalAuthError("envelope must be an object")
    payload = envelope.get("payload")
    tag = envelope.get("tag")
    if not isinstance(payload, dict) or not isinstance(tag, str):
        raise InternalAuthError("envelope is malformed")

    expected = sign_envelope(payload, secret)
    # Constant-time: a byte-wise early exit would leak the tag one byte at a time.
    if not hmac.compare_digest(expected, tag):
        raise InternalAuthError("internal authentication failed")

    issued_at = payload.get("issued_at")
    if not isinstance(issued_at, int):
        raise InternalAuthError("envelope has no valid timestamp")
    current = now if now is not None else time.time()
    if abs(current - issued_at) > MAX_ENVELOPE_AGE_SECONDS:
        raise InternalAuthError("envelope is outside the freshness window")

    return payload
