"""Request handling: validate -> authenticate -> route -> replay -> respond.

The ordering matters. Structure is checked before meaning, the target is
resolved from AEra's own data before anything is executed, and the replay guard
is claimed only once a request is otherwise fully acceptable -- so a malformed
request cannot burn a legitimate message id.

Content trust: the inbound text is treated as DATA. It is never used to select
privileges, never used to pick a different agent than the one named and
validated, and never executed or forwarded to a tool.
"""
from __future__ import annotations

import time
from typing import Any, Optional

from . import audit as gw_audit
from .auth import InboundAuthError, authenticate_request, failed_peer
from .card import AGENT_NAME
from .constants import (
    A2A_PROTOCOL_VERSION,
    ERR_FORBIDDEN,
    ERR_INTERNAL,
    ERR_INVALID_REQUEST,
    ERR_RATE_LIMITED,
    ERR_UNAUTHENTICATED,
    ERR_UNSUPPORTED_OPERATION,
    MAX_REQUEST_BYTES,
    RATE_LIMIT_MESSAGE,
    SKILL_COMMUNICATE,
    SKILL_READ_PROFILE,
)
from .credentials import authorize_request
from .peer import AUTH_BEARER, anonymous_peer
from .ratelimit import SCOPE_AGENT, SCOPE_CREDENTIAL, get_limiter
from .replay import remember
from .routing import resolve_target_agent
from .trust import (
    EV_AUTHORIZATION_DENIED,
    EV_INVALID_REQUEST,
    EV_RATE_LIMITED,
    EV_REPLAY_REJECTED,
    EV_REQUEST_SUCCESS,
)
from .validation import (
    GatewayError,
    validate_jsonrpc_envelope,
    validate_message_send,
)


def _error_response(rpc_id: Any, code: int, message: str,
                    data: Optional[dict] = None) -> dict[str, Any]:
    """A JSON-RPC error that is safe to send outside.

    `message` is always a curated string. Exception text, stack traces, SQL
    errors, paths and configuration never reach this function.
    """
    error: dict[str, Any] = {"code": code, "message": message}
    if data:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": rpc_id, "error": error}


def _message_response(rpc_id: Any, *, message_id: str, text: str,
                      data: Optional[dict] = None,
                      context_id: Optional[str] = None) -> dict[str, Any]:
    parts: list[dict[str, Any]] = [{"kind": "text", "text": text}]
    if data is not None:
        parts.append({"kind": "data", "data": data})
    result: dict[str, Any] = {
        "kind": "message",
        "messageId": message_id,
        "role": "agent",
        "parts": parts,
    }
    if context_id:
        result["contextId"] = context_id
    return {"jsonrpc": "2.0", "id": rpc_id, "result": result}


def handle_request(body: Any, headers, *, conn_factory,
                   protocol_version: str = "",
                   raw_size: Optional[int] = None) -> tuple[dict[str, Any], int]:
    """Process one inbound JSON-RPC request. Returns (response_body, http_status).

    Always returns a JSON-RPC response; never raises to the transport layer.
    """
    started = time.perf_counter()
    rpc_id: Any = None
    peer = anonymous_peer()
    inbound = None
    result_label = "error"
    error_code: Optional[int] = None
    http_status = 200
    internal_note = ""
    #: Set when the failure is a replay, so the evidence layer can tell a
    #: deliberate duplicate apart from an ordinary malformed request. They mean
    #: very different things about a peer.
    replay_rejected = False

    try:
        if raw_size is not None and raw_size > MAX_REQUEST_BYTES:
            raise GatewayError(ERR_INVALID_REQUEST,
                               f"request exceeds {MAX_REQUEST_BYTES} bytes")

        rpc_id, method, params = validate_jsonrpc_envelope(body)

        try:
            peer = authenticate_request(headers, conn_factory=conn_factory)
        except InboundAuthError as exc:
            peer = failed_peer(AUTH_BEARER)
            # 401. The message is already uniform for every credential failure
            # mode, so this discloses nothing about which credentials exist.
            raise GatewayError(ERR_UNAUTHENTICATED, exc.message) from exc

        # An authenticated caller gets its own bucket immediately after
        # identification -- before parsing the message body, so a compromised
        # credential cannot spend the server's parsing budget either. The
        # global and per-source buckets in routes.py have already been charged
        # for this request; this one is additional, never a replacement.
        if peer.is_authenticated and peer.credential_id:
            cred_decision = get_limiter().check(SCOPE_CREDENTIAL, peer.credential_id)
            if not cred_decision.allowed:
                raise GatewayError(ERR_RATE_LIMITED, RATE_LIMIT_MESSAGE,
                                   retry_after=cred_decision.retry_after)

        inbound = validate_message_send(rpc_id, method, params,
                                        protocol_version=protocol_version)

        # Authorisation is a SEPARATE question from authentication. A valid
        # credential proves which peer is calling; it does not decide which
        # agent that peer may address. Checked before the database is touched,
        # and the refusal is worded identically to "unknown target" so that an
        # out-of-scope agent is indistinguishable from one that does not exist.
        if peer.is_authenticated and not authorize_request(
                peer, target_agent_id=inbound.target_agent_id,
                skill_id=inbound.skill_id):
            raise GatewayError(
                ERR_FORBIDDEN, "target agent is not available",
                internal=(f"credential {peer.credential_id} is not scoped for "
                          f"agent={inbound.target_agent_id} "
                          f"skill={inbound.skill_id}"))

        # Per-target limit. This is the one dimension that cannot be enforced in
        # routes.py, because the target is only known after parsing -- but it is
        # still enforced BEFORE any database access, so a flood aimed at one
        # agent is rejected without ever touching SQLite. Parsing up to this
        # point is bounded by MAX_REQUEST_BYTES and is pure CPU.
        #
        # It is a separate bucket from the per-peer one on purpose: without it,
        # a distributed flood spread over many source addresses would stay under
        # every per-peer limit while still hammering a single agent.
        agent_decision = get_limiter().check(SCOPE_AGENT, inbound.target_agent_id)
        if not agent_decision.allowed:
            raise GatewayError(ERR_RATE_LIMITED, RATE_LIMIT_MESSAGE,
                               retry_after=agent_decision.retry_after)

        conn = conn_factory()
        try:
            target = resolve_target_agent(conn, inbound.target_agent_id,
                                          skill_id=inbound.skill_id)

            if not remember(conn, message_id=inbound.message_id,
                            target_agent=target.agent_id, rpc_id=rpc_id):
                replay_rejected = True
                raise GatewayError(ERR_INVALID_REQUEST,
                                   "duplicate request: this messageId has already "
                                   "been processed")
            conn.commit()

            # Dispatch inside the connection scope: verifying a runtime reply
            # requires reading the agent's registered public keys, and that
            # lookup must use AEra's own data rather than anything cached.
            response = _dispatch(inbound, target, conn)
        finally:
            conn.close()

        result_label = "success"
        return response, 200

    except GatewayError as exc:
        error_code = exc.code
        internal_note = exc.internal
        http_status = _http_status_for(exc.code, peer)
        result_label = "rate_limited" if exc.code == ERR_RATE_LIMITED else "rejected"
        data = {"retryAfter": exc.retry_after} if exc.retry_after else None
        return _error_response(rpc_id, exc.code, exc.message, data), http_status

    except Exception as exc:  # noqa: BLE001 - nothing internal may escape
        error_code = ERR_INTERNAL
        internal_note = f"{type(exc).__name__}: {exc}"
        result_label = "internal_error"
        http_status = 500
        # Deliberately generic: no exception text, no traceback, no DB detail.
        return _error_response(rpc_id, ERR_INTERNAL, "internal error"), 500

    finally:
        trust_view = _observe_peer(
            peer, conn_factory=conn_factory, inbound=inbound,
            result_label=result_label, error_code=error_code,
            replay_rejected=replay_rejected)
        record = gw_audit.build_record(
            request_id=rpc_id,
            message_id=getattr(inbound, "message_id", None),
            peer=peer,
            target_agent=getattr(inbound, "target_agent_id", None),
            method=getattr(inbound, "method", None),
            skill_id=getattr(inbound, "skill_id", None),
            protocol_version=protocol_version or A2A_PROTOCOL_VERSION,
            result=result_label,
            http_status=http_status,
            error_code=error_code,
            latency_ms=(time.perf_counter() - started) * 1000.0,
            content=getattr(inbound, "text", None),
            trust=trust_view,
        )
        if internal_note:
            gw_audit.logger.debug("a2a_inbound_detail %s", gw_audit.scrub(internal_note))
        gw_audit.emit(record)


def _evidence_event(result_label: str, error_code: Optional[int],
                    replay_rejected: bool) -> Optional[str]:
    """Translate the outcome of one request into the evidence vocabulary.

    Deliberately narrow. An internal error is AEra's fault, not the peer's, so
    it produces no evidence at all -- charging a peer for our own 500 would let
    a bug in AEra quietly destroy a peer's standing.
    """
    if result_label == "success":
        return EV_REQUEST_SUCCESS
    if replay_rejected:
        return EV_REPLAY_REJECTED
    if error_code == ERR_FORBIDDEN:
        return EV_AUTHORIZATION_DENIED
    if error_code == ERR_RATE_LIMITED:
        return EV_RATE_LIMITED
    if error_code in (ERR_INVALID_REQUEST, ERR_UNSUPPORTED_OPERATION):
        return EV_INVALID_REQUEST
    return None


def _observe_peer(peer, *, conn_factory, inbound, result_label,
                  error_code, replay_rejected) -> Optional[dict]:
    """Persist evidence about an AUTHENTICATED peer, and optionally assess it.

    Three properties of this function are load-bearing:

      1. It does nothing for an anonymous caller. No peer_id means no row, so
         unauthenticated traffic cannot grow the evidence table or manufacture
         a trust identity.
      2. It runs only after authentication has already succeeded, which means
         the per-credential rate limit already applies to it. Trust collection
         therefore inherits an existing bound rather than needing a new one.
      3. It can never change the response. It runs in `finally`, after the
         return value is decided, and every failure inside it is swallowed.
    """
    from . import trust as gw_trust

    if not getattr(peer, "is_authenticated", False) or not peer.peer_id:
        return None

    event = _evidence_event(result_label, error_code, replay_rejected)
    observe = gw_trust.trust_is_observed()
    if event is None and not observe:
        return None

    try:
        conn = conn_factory()
    except Exception:  # noqa: BLE001 - observation must not break a request
        return None
    try:
        gw_trust.init_schema(conn)
        if event is not None:
            gw_trust.record_event(
                conn, peer_id=peer.peer_id, credential_id=peer.credential_id,
                target_agent_id=getattr(inbound, "target_agent_id", None),
                skill_id=getattr(inbound, "skill_id", None),
                event_type=event, outcome=result_label)
            conn.commit()
        if not observe:
            return None
        assessment = gw_trust.assess_peer(conn, peer.peer_id)
        return assessment.to_audit_dict() if assessment else None
    except Exception:  # noqa: BLE001
        return None
    finally:
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass


def _dispatch(inbound, target, conn=None) -> dict[str, Any]:
    """Execute the requested skill. Only skills we can truly fulfil exist here."""
    if inbound.skill_id == SKILL_READ_PROFILE:
        profile = target.public_profile()
        summary = (
            f"AEra agent {profile['agent_id']} is {profile['status']} with "
            f"{len(profile['capabilities'])} declared capabilities."
        )
        return _message_response(
            inbound.rpc_id,
            message_id=f"aera-{inbound.message_id}",
            text=summary,
            data={"agent": profile, "servedBy": AGENT_NAME},
            context_id=inbound.context_id,
        )

    if inbound.skill_id == SKILL_COMMUNICATE:
        return _dispatch_communicate(inbound, target, conn)

    # Unreachable: validation already restricts skill_id to SUPPORTED_SKILLS.
    raise GatewayError(ERR_INVALID_REQUEST, "unsupported skill")


def _dispatch_communicate(inbound, target, conn) -> dict[str, Any]:
    """Hand the message to the agent's own runtime process.

    The target agent has already been resolved from AEra's database and checked
    for status, active keys and the `agent.communicate` capability. The runtime
    address is derived from that verified agent id -- the caller cannot name a
    destination.
    """
    from .runtime_link import (
        RuntimeAuthenticityError,
        RuntimeUnavailable,
        call_runtime,
    )

    try:
        reply = call_runtime(conn, target.agent_id, text=inbound.text,
                             request_id=str(inbound.message_id))
    except RuntimeAuthenticityError as exc:
        # A reply arrived that was not signed by a key AEra has registered for
        # this agent. That is a security event, not an outage: refuse rather
        # than pass unauthenticated content to an external caller.
        raise GatewayError(ERR_INTERNAL, "internal error",
                           internal=f"runtime authenticity failure: {exc}") from exc
    except RuntimeUnavailable as exc:
        raise GatewayError(
            ERR_UNSUPPORTED_OPERATION,
            "target agent is not currently reachable for conversation",
            internal=f"runtime unavailable: {exc}") from exc

    return _message_response(
        inbound.rpc_id,
        message_id=f"aera-{inbound.message_id}",
        text=reply.text,
        # Provider and model are disclosed deliberately: they say which tool
        # produced the words, and they carry no credential. The agent identity
        # is unchanged by them, which is the point of provider independence.
        data={"agent": target.public_profile(), "servedBy": AGENT_NAME,
              "provider": reply.provider, "model": reply.model},
        context_id=inbound.context_id,
    )


def _http_status_for(code: int, peer) -> int:
    """Map JSON-RPC errors onto sensible HTTP statuses.

    JSON-RPC purists would return 200 for everything; returning a meaningful
    status is friendlier to proxies and monitoring without breaking clients,
    which read the `error` object either way.
    """
    if code == ERR_RATE_LIMITED:
        # Checked before the auth status: a rate-limited caller must be told to
        # slow down, not handed a 401 that invites an immediate credential retry.
        return 429
    if code == ERR_UNAUTHENTICATED:
        return 401
    if code == ERR_FORBIDDEN:
        # 403, not 404: the caller is authenticated, and pretending the agent
        # does not exist would be a lie to a known party. The *message* is
        # still the opaque one, so no agent is confirmed or denied by it.
        return 403
    if getattr(peer, "authentication_status", "") == "failed":
        return 401
    return 200
