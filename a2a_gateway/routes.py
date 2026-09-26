"""Public HTTP surface of the inbound A2A gateway.

Two routes, both public:

    GET   /.well-known/agent-card.json   discovery
    POST  /api/a2a                       JSON-RPC endpoint

`/api/agents/messages` is NOT touched. That remains the AEra-internal
verification/notarisation relay for signed envelopes between AEra agents, and it
keeps its own semantics, its own replay namespace and its own auth.
"""
from __future__ import annotations

import json
import os

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from . import credentials, replay, trust
from .card import any_runtime_available, build_agent_card, card_is_safe_to_publish
from .constants import (
    A2A_PROTOCOL_VERSION,
    ERR_INVALID_REQUEST,
    ERR_PARSE,
    ERR_RATE_LIMITED,
    GATEWAY_PATH,
    MAX_REQUEST_BYTES,
    RATE_LIMIT_MESSAGE,
    WELL_KNOWN_PATH,
)
from .handler import handle_request
from .ratelimit import SCOPE_GLOBAL, SCOPE_PEER, client_source, get_limiter

router = APIRouter(tags=["a2a-gateway"])


def _public_url() -> str:
    return (os.getenv("PUBLIC_URL") or "https://aeralogin.com").rstrip("/")


def _conn_factory():
    """Reuse the Agent Layer's connection helper; do not open a second pool."""
    from agent.repository import get_connection

    conn = get_connection()
    replay.init_schema(conn)
    credentials.init_schema(conn)
    trust.init_schema(conn)
    return conn


@router.get(WELL_KNOWN_PATH)
async def agent_card() -> JSONResponse:
    """Public Agent Card. Contains nothing that is not meant to be public."""
    card = build_agent_card(_public_url(),
                            runtime_available=any_runtime_available())
    safe, leaked = card_is_safe_to_publish(card)
    if not safe:  # pragma: no cover - guards against a future careless edit
        return JSONResponse(
            status_code=500,
            content={"error": "agent card failed its publication self-check"},
        )
    return JSONResponse(
        content=card,
        headers={
            "Cache-Control": "public, max-age=300",
            "A2A-Version": A2A_PROTOCOL_VERSION,
        },
    )


@router.post(GATEWAY_PATH)
async def a2a_endpoint(request: Request) -> JSONResponse:
    """Inbound standard A2A over JSON-RPC."""
    # Rate limiting comes FIRST, before the body is even read off the socket.
    # A limiter that runs after parsing, validation or a database lookup still
    # lets an attacker spend our CPU and disk on every rejected request; the
    # only thing it would then protect is the response. Both checks below are
    # in-memory and O(1), so a rejected request costs essentially nothing.
    limiter = get_limiter()
    source = client_source(request)

    decision = limiter.check(SCOPE_GLOBAL, "all")
    if not decision.allowed:
        return _rate_limited(decision)

    decision = limiter.check(SCOPE_PEER, source)
    if not decision.allowed:
        return _rate_limited(decision)

    raw = await request.body()

    if len(raw) > MAX_REQUEST_BYTES:
        return _rpc_error(None, ERR_INVALID_REQUEST,
                          f"request exceeds {MAX_REQUEST_BYTES} bytes", 413)

    try:
        body = json.loads(raw.decode("utf-8")) if raw else None
    except (UnicodeDecodeError, json.JSONDecodeError):
        return _rpc_error(None, ERR_PARSE, "invalid JSON", 400)

    if body is None:
        return _rpc_error(None, ERR_INVALID_REQUEST, "empty request body", 400)

    protocol_version = (request.headers.get("A2A-Version") or "").strip()

    payload, status = handle_request(
        body,
        request.headers,
        conn_factory=_conn_factory,
        protocol_version=protocol_version,
        raw_size=len(raw),
    )
    headers = {"A2A-Version": A2A_PROTOCOL_VERSION}
    if status == 429:
        # The per-target limit is enforced inside the handler (it needs the
        # target id), so lift its Retry-After back up to the HTTP layer.
        retry_after = ((payload.get("error") or {}).get("data") or {}).get("retryAfter")
        headers["Retry-After"] = str(retry_after or 60)
    return JSONResponse(content=payload, status_code=status, headers=headers)


def _rate_limited(decision) -> JSONResponse:
    """429 with Retry-After.

    The body deliberately reveals nothing beyond "you are going too fast": no
    configured limits, no remaining budget, no whether the global or the
    per-peer bucket was the one that tripped. Leaking which dimension was hit
    would tell an attacker exactly how to tune a distributed flood to stay
    under the per-peer limit while still saturating the global one.
    """
    return JSONResponse(
        status_code=429,
        content={
            "jsonrpc": "2.0",
            "id": None,
            "error": {
                "code": ERR_RATE_LIMITED,
                "message": RATE_LIMIT_MESSAGE,
                "data": {"retryAfter": decision.retry_after},
            },
        },
        headers={
            "A2A-Version": A2A_PROTOCOL_VERSION,
            "Retry-After": str(decision.retry_after),
        },
    )


def _rpc_error(rpc_id, code: int, message: str, status: int) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"jsonrpc": "2.0", "id": rpc_id,
                 "error": {"code": code, "message": message}},
        headers={"A2A-Version": A2A_PROTOCOL_VERSION},
    )
