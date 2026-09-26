"""Gateway -> Runtime link.

This is the only place where the public gateway talks to a local process, and
it is deliberately narrow.

NO CALLER-SUPPLIED DESTINATION
------------------------------
There is exactly one input to the address calculation: the `agent_id`, and by
the time we get here that id has already been validated for shape and resolved
against AEra's database (exists, active, has an active key, holds the required
capability). The socket path is then *derived* by hashing it.

An external caller therefore cannot express a destination at all. There is no
URL, host, port or path field anywhere in the A2A request that reaches this
module. That is what makes SSRF structurally impossible here rather than
filtered.

VERIFYING THE ANSWER
--------------------
A reply is only accepted if it carries a valid Ed25519 signature from the
agent's registered public key. The gateway reads that public key from AEra's
own `agent_keys` table. So even a local process that somehow gained write
access to the socket path cannot make the gateway return an answer attributed
to an agent, because it cannot forge that signature.

This reuses the existing trust anchor instead of inventing a second one.
"""
from __future__ import annotations

import json
import logging
import socket
import uuid
from dataclasses import dataclass
from typing import Any, Optional

logger = logging.getLogger("aera.gateway.runtime")

CONNECT_TIMEOUT_SECONDS = 2.0
READ_TIMEOUT_SECONDS = 120.0
MAX_RESPONSE_BYTES = 256 * 1024


class RuntimeUnavailable(Exception):
    """No runtime is listening for this agent, or it did not answer usably."""


class RuntimeAuthenticityError(Exception):
    """A reply arrived but was not provably from this agent's runtime."""


@dataclass(frozen=True)
class RuntimeReply:
    text: str
    provider: str
    model: str
    tool_attempt_detected: bool = False


def _active_public_keys(conn, agent_id: str) -> list[str]:
    """Registered active public keys for the agent, from AEra's own data."""
    rows = conn.execute(
        "SELECT public_key FROM agent_keys "
        "WHERE agent_id = ? AND status = 'active'",
        (agent_id,),
    ).fetchall()
    keys = []
    for row in rows:
        value = row[0] if not hasattr(row, "keys") else row["public_key"]
        if isinstance(value, str) and value:
            keys.append(value)
    return keys


def _verify_agent_signature(conn, agent_id: str, result: dict[str, Any],
                            signature: str) -> None:
    """Check the reply against the agent's registered active public keys.

    `verify_signature` takes the ENCODED public key and the base64url
    signature and does its own decoding, so nothing is pre-decoded here.
    Every active key is tried, because a rotation may be in flight.
    """
    from agent.crypto import verify_signature

    canonical = json.dumps(result, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    for encoded in _active_public_keys(conn, agent_id):
        try:
            if verify_signature(encoded, signature, canonical):
                return
        except Exception:  # noqa: BLE001 - a bad stored key must not crash routing
            continue
    raise RuntimeAuthenticityError(
        "runtime reply was not signed by a registered active key")


def runtime_is_available(agent_id: str) -> bool:
    """Whether a runtime socket exists for this agent. No connection made."""
    from agent_runtime.internal_auth import internal_secret, socket_path_for

    if not internal_secret():
        return False
    try:
        return socket_path_for(agent_id).is_socket()
    except Exception:  # noqa: BLE001
        return False


def call_runtime(conn, agent_id: str, *, text: str,
                 request_id: Optional[str] = None) -> RuntimeReply:
    """Send one message to the agent's runtime and return its verified reply."""
    from agent_runtime.internal_auth import (
        build_envelope,
        internal_secret,
        socket_path_for,
    )

    secret = internal_secret()
    if not secret:
        raise RuntimeUnavailable("runtime channel is not configured")

    path = socket_path_for(agent_id)
    if not path.is_socket():
        raise RuntimeUnavailable("no runtime is registered for this agent")

    envelope = build_envelope(
        agent_id=agent_id,
        request_id=request_id or str(uuid.uuid4()),
        body={"op": "message", "text": text},
        secret=secret,
    )

    raw = _roundtrip(path, json.dumps(envelope).encode("utf-8") + b"\n")

    try:
        response = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeUnavailable("runtime returned an unreadable response") from exc

    result = response.get("result")
    signature = response.get("agent_signature")
    if not isinstance(result, dict) or not isinstance(signature, str):
        raise RuntimeUnavailable("runtime response is malformed")

    # Authenticity BEFORE content: nothing in `result` is trusted until the
    # signature has been checked against a key AEra already knows.
    _verify_agent_signature(conn, agent_id, result, signature)

    if result.get("agent_id") != agent_id:
        raise RuntimeAuthenticityError("runtime replied for a different agent")

    if not result.get("ok"):
        error = result.get("error") or {}
        raise RuntimeUnavailable(
            f"runtime refused the request: {error.get('code', 'unknown')}")

    data = result.get("data") or {}
    reply_text = data.get("text")
    if not isinstance(reply_text, str) or not reply_text.strip():
        raise RuntimeUnavailable("runtime produced no reply text")

    return RuntimeReply(
        text=reply_text,
        provider=str(data.get("provider") or "unknown"),
        model=str(data.get("model") or "unknown"),
        tool_attempt_detected=bool(data.get("tool_attempt_detected")),
    )


def _roundtrip(path, payload: bytes) -> bytes:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(CONNECT_TIMEOUT_SECONDS)
    try:
        try:
            client.connect(str(path))
        except (OSError, socket.timeout) as exc:
            raise RuntimeUnavailable("runtime is not accepting connections") from exc

        client.settimeout(READ_TIMEOUT_SECONDS)
        client.sendall(payload)

        chunks: list[bytes] = []
        total = 0
        while True:
            try:
                chunk = client.recv(8192)
            except (OSError, socket.timeout) as exc:
                raise RuntimeUnavailable("runtime did not answer in time") from exc
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_RESPONSE_BYTES:
                raise RuntimeUnavailable("runtime response is too large")
            chunks.append(chunk)
            if chunk.endswith(b"\n"):
                break
        if not chunks:
            raise RuntimeUnavailable("runtime closed the connection")
        return b"".join(chunks)
    finally:
        client.close()
