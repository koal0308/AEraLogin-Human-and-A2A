"""The runtime process: a Unix-socket server that answers the AEra gateway.

WHY A UNIX SOCKET AND NOT A TCP PORT
------------------------------------
A loopback TCP port is reachable by every process and every user on the host,
and on a misconfigured box sometimes from outside it. A Unix domain socket is a
filesystem object, so the operating system enforces who may even *connect*,
before a single byte of our code runs. The socket is created inside a directory
whose mode is 0700 and the socket itself is 0600.

That is the first of two layers. The second is the HMAC envelope in
`internal_auth` — because "it came over the local socket" is an argument about
the channel, not about the sender, and §17 rules out treating localhost as
trusted. An attacker who somehow obtains socket access still cannot produce a
valid envelope.

The response is signed with the agent's Ed25519 key so the gateway can verify
it really came from this agent's runtime, using the public key AEra already
holds. No new secret is introduced for that direction.
"""
from __future__ import annotations

import json
import logging
import os
import socket
import socketserver
import threading
import time
from typing import Any, Optional

from agent.crypto import b64u_encode

from .internal_auth import (
    InternalAuthError,
    internal_secret,
    socket_path_for,
    verify_envelope,
)
from .lifecycle import LifecycleStatus, RuntimeState
from .messaging import MessageRejected, process_message
from .provider import ProviderFailure

logger = logging.getLogger("aera.runtime")

MAX_REQUEST_BYTES = 128 * 1024
OP_MESSAGE = "message"
OP_HEALTH = "health"


class RuntimeServer:
    """Owns the socket, the identity, the provider and the lifecycle state."""

    def __init__(self, *, identity, provider, status: Optional[LifecycleStatus] = None,
                 max_reply_chars: int = 2000) -> None:
        self.identity = identity
        self.provider = provider
        self.status = status or LifecycleStatus()
        self.max_reply_chars = max_reply_chars
        self.socket_path = socket_path_for(identity.agent_id)
        self._server: Optional[socketserver.ThreadingUnixStreamServer] = None
        self._thread: Optional[threading.Thread] = None

    # -- request handling ----------------------------------------------------
    def handle_payload(self, raw: bytes) -> dict[str, Any]:
        """Verify, dispatch, respond. Never raises to the socket layer."""
        request_id = ""
        try:
            secret = internal_secret()
            if not secret:
                # Refuse to serve rather than fall back to an unauthenticated
                # channel. A runtime that answers anyone is worse than one that
                # answers nobody.
                return self._error("runtime_misconfigured",
                                   "internal channel is not configured")
            try:
                envelope = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                return self._error("bad_request", "payload is not valid JSON")

            try:
                payload = verify_envelope(envelope, secret)
            except InternalAuthError as exc:
                # Deliberately uniform: an unauthenticated local caller learns
                # only that it was refused, not which check failed.
                logger.warning("runtime rejected an internal request: %s", exc)
                return self._error("unauthorized", "internal authentication failed")

            request_id = str(payload.get("request_id") or "")
            if payload.get("agent_id") != self.identity.agent_id:
                # This socket serves exactly one agent.
                return self._error("wrong_agent", "request is not for this agent")

            body = payload.get("body") or {}
            operation = body.get("op")

            if operation == OP_HEALTH:
                return self._ok(request_id, self.health())

            if operation != OP_MESSAGE:
                return self._error("unsupported_operation",
                                   f"unsupported operation {operation!r}",
                                   request_id=request_id)

            if self.status.is_revoked:
                return self._error("revoked", "this agent has been revoked",
                                   request_id=request_id)
            if not self.status.is_serving:
                return self._error("not_ready",
                                   f"runtime is {self.status.get().value}",
                                   request_id=request_id)

            return self._handle_message(request_id, body)

        except Exception as exc:  # noqa: BLE001 - nothing internal may escape
            logger.exception("runtime internal error")
            return self._error("internal_error", "internal error",
                               request_id=request_id)

    def _handle_message(self, request_id: str, body: dict[str, Any]) -> dict[str, Any]:
        try:
            reply = process_message(body.get("text"), self.provider,
                                    max_reply_chars=self.max_reply_chars)
        except MessageRejected as exc:
            return self._error("invalid_message", str(exc), request_id=request_id)
        except ProviderFailure as exc:
            # A provider outage is an operational fault, not a security one.
            # The runtime stays a valid identity; it just cannot think right now.
            self.status.set(RuntimeState.DEGRADED, f"provider {exc.kind}")
            logger.warning("provider failure kind=%s provider=%s", exc.kind, exc.provider)
            return self._error("provider_unavailable",
                               "the agent's model backend is unavailable",
                               request_id=request_id)

        if self.status.get() is RuntimeState.DEGRADED:
            self.status.set(RuntimeState.RUNNING, "")

        logger.info("a2a_inbound_handled request_id=%s %s", request_id,
                    reply.safe_dict())
        return self._ok(request_id, {
            "text": reply.text,
            "provider": reply.provider,
            "model": reply.model,
            "tool_attempt_detected": reply.tool_attempt_detected,
        })

    # -- responses -----------------------------------------------------------
    def _sign(self, response: dict[str, Any]) -> dict[str, Any]:
        """Prove this really is the agent's runtime.

        Signed with the Ed25519 agent key, verifiable by the gateway against
        the public key registered with AEra. This is why the internal channel
        needs no second shared secret for this direction.
        """
        canonical = json.dumps(response, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=True).encode("utf-8")
        return {"result": response,
                "agent_signature": b64u_encode(self.identity.keystore.sign(canonical))}

    def _ok(self, request_id: str, data: dict[str, Any]) -> dict[str, Any]:
        return self._sign({"ok": True, "request_id": request_id,
                           "agent_id": self.identity.agent_id,
                           "issued_at": int(time.time()), "data": data})

    def _error(self, code: str, message: str, *, request_id: str = "") -> dict[str, Any]:
        return self._sign({"ok": False, "request_id": request_id,
                           "agent_id": self.identity.agent_id,
                           "issued_at": int(time.time()),
                           "error": {"code": code, "message": message}})

    def health(self) -> dict[str, Any]:
        return self.status.snapshot({
            "agent_id": self.identity.agent_id,
            "key_id": self.identity.key_id,
            "provider": self.provider.describe(),
        })

    # -- socket lifecycle ----------------------------------------------------
    def start(self) -> None:
        path = self.socket_path
        path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(path.parent, 0o700)
        if path.exists():
            path.unlink()

        server = _build_server(str(path), self)
        # 0600 before anyone can connect: created inside a 0700 directory, then
        # narrowed immediately.
        os.chmod(path, 0o600)
        self._server = server
        self._thread = threading.Thread(target=server.serve_forever,
                                        name="aera-runtime", daemon=True)
        self._thread.start()
        logger.info("runtime listening agent_id=%s socket=%s",
                    self.identity.agent_id, path)

    def stop(self) -> None:
        self.status.set(RuntimeState.STOPPING)
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self.socket_path.exists():
            try:
                self.socket_path.unlink()
            except OSError:  # pragma: no cover
                pass
        self.status.set(RuntimeState.STOPPED)


class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        runtime: RuntimeServer = self.server.runtime  # type: ignore[attr-defined]
        chunks: list[bytes] = []
        total = 0
        self.request.settimeout(30)
        try:
            while True:
                chunk = self.request.recv(8192)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_REQUEST_BYTES:
                    return
                chunks.append(chunk)
                if chunks and chunks[-1].endswith(b"\n"):
                    break
        except (socket.timeout, OSError):
            return

        response = runtime.handle_payload(b"".join(chunks))
        try:
            self.request.sendall(
                json.dumps(response).encode("utf-8") + b"\n")
        except OSError:  # pragma: no cover - peer vanished
            pass


def _build_server(path: str, runtime: RuntimeServer):
    class _Server(socketserver.ThreadingUnixStreamServer):
        allow_reuse_address = True
        daemon_threads = True

    server = _Server(path, _Handler)
    server.runtime = runtime  # type: ignore[attr-defined]
    return server
