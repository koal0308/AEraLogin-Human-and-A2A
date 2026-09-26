"""End-to-end client behaviour against a mocked external agent.

The fixtures below are the REAL shapes observed live on
https://sanctum-beacon.onrender.com (Agent Card and a `message/send` reply),
so these tests exercise what an actual external agent returns rather than an
idealised version of the specification.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.external_a2a.auth import BearerTokenAdapter, NoAuthAdapter  # noqa: E402
from src.external_a2a.card import CardValidationError  # noqa: E402
from src.external_a2a.client import (  # noqa: E402
    WELL_KNOWN_PATH,
    A2AClient,
    well_known_url,
)
from src.external_a2a.errors import (  # noqa: E402
    A2AAuthError,
    A2AProtocolError,
    A2ARemoteError,
)
from src.external_a2a.net import NetPolicy  # noqa: E402

ORIGIN = "https://localhost"
ENDPOINT = f"{ORIGIN}/a2a"
OPEN = NetPolicy(allow_private_addresses=True)

# Recorded from the live agent.
LIVE_CARD = {
    "name": "Sanctum Beacon",
    "description": "A beacon for agent community discovery.",
    "version": "1.1.0",
    "protocolVersion": "0.3.0",
    "url": ENDPOINT,
    "preferredTransport": "JSONRPC",
    "capabilities": {"streaming": False, "pushNotifications": False,
                     "stateTransitionHistory": False},
    "skills": [{"id": "community-discovery", "name": "Community discovery",
                "description": "Describes the community.", "tags": ["discovery"]}],
    "documentationUrl": f"{ORIGIN}/agents.md",
    "supportsAuthenticatedExtendedCard": False,
}

# Recorded from the live agent: a direct Message, NOT a Task.
LIVE_MESSAGE_RESULT = {
    "kind": "message",
    "messageId": "f740451a-0000-4000-8000-000000000000",
    "role": "agent",
    "parts": [
        {"kind": "text", "text": "Sanctum is open to agents."},
        {"kind": "data", "data": {"community": {"agent_count": 11, "active_24h": 7}}},
    ],
}

TASK_RESULT = {
    "kind": "task",
    "id": "task-123",
    "contextId": "ctx-9",
    "status": {"state": "completed",
               "message": {"parts": [{"kind": "text", "text": "done"}]}},
    "artifacts": [{"parts": [{"kind": "text", "text": "artifact text"}]}],
}


def rpc_ok(result, req_id="x"):
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def make_client(handler, **kw) -> A2AClient:
    http = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    return A2AClient(policy=OPEN, http=http, **kw)


def default_handler(req):
    if req.url.path == WELL_KNOWN_PATH:
        return httpx.Response(200, json=LIVE_CARD)
    if req.url.path == "/a2a":
        return httpx.Response(200, json=rpc_ok(LIVE_MESSAGE_RESULT))
    return httpx.Response(404, json={})


# -- discovery ---------------------------------------------------------------
def test_well_known_url_is_the_registered_path():
    assert well_known_url("https://x.test") == f"https://x.test{WELL_KNOWN_PATH}"
    assert well_known_url("https://x.test/a2a") == f"https://x.test{WELL_KNOWN_PATH}"
    assert well_known_url("https://x.test/") == f"https://x.test{WELL_KNOWN_PATH}"


def test_discovery_fetches_and_parses_the_card():
    card, iface = make_client(default_handler).discover_agent(ORIGIN)
    assert card.name == "Sanctum Beacon"
    assert iface.url == ENDPOINT
    assert card.requires_authentication is False


def test_an_explicit_card_url_is_accepted():
    card = make_client(default_handler).get_agent_card(f"{ORIGIN}{WELL_KNOWN_PATH}")
    assert card.name == "Sanctum Beacon"


def test_missing_card_is_a_protocol_error():
    c = make_client(lambda r: httpx.Response(404, json={"error": "not found"}))
    with pytest.raises(A2AProtocolError) as exc:
        c.get_agent_card(ORIGIN)
    assert "404" in str(exc.value)


def test_card_behind_authentication_is_an_auth_error():
    c = make_client(lambda r: httpx.Response(401, json={}))
    with pytest.raises(A2AAuthError):
        c.get_agent_card(ORIGIN)


def test_html_instead_of_a_card_is_a_protocol_error():
    c = make_client(lambda r: httpx.Response(
        200, text="<html>hi</html>", headers={"Content-Type": "text/html"}))
    with pytest.raises(A2AProtocolError) as exc:
        c.get_agent_card(ORIGIN)
    assert "not JSON" in str(exc.value)


def test_malformed_card_is_rejected():
    c = make_client(lambda r: httpx.Response(200, json={"description": "no name"}))
    with pytest.raises(CardValidationError):
        c.get_agent_card(ORIGIN)


# -- request construction ----------------------------------------------------
def test_v03_request_uses_message_send_and_the_version_header():
    seen = {}

    def handler(req):
        if req.url.path == WELL_KNOWN_PATH:
            return httpx.Response(200, json=LIVE_CARD)
        seen["body"] = json.loads(req.content)
        seen["headers"] = dict(req.headers)
        return httpx.Response(200, json=rpc_ok(LIVE_MESSAGE_RESULT))

    c = make_client(handler)
    card, iface = c.discover_agent(ORIGIN)
    c.send_message(card, "hello", interface=iface)

    assert seen["body"]["jsonrpc"] == "2.0"
    assert seen["body"]["method"] == "message/send"
    assert seen["body"]["params"]["message"]["role"] == "user"
    assert seen["body"]["params"]["message"]["parts"] == [{"kind": "text", "text": "hello"}]
    assert seen["body"]["params"]["message"]["messageId"]
    assert seen["headers"]["a2a-version"] == "0.3"


def test_v10_request_uses_SendMessage():
    card_v10 = {"name": "V1", "description": "d", "version": "1.0.0",
                "supportedInterfaces": [{"url": ENDPOINT, "protocolBinding": "JSONRPC",
                                         "protocolVersion": "1.0"}]}
    seen = {}

    def handler(req):
        if req.url.path == WELL_KNOWN_PATH:
            return httpx.Response(200, json=card_v10)
        seen["body"] = json.loads(req.content)
        seen["headers"] = dict(req.headers)
        return httpx.Response(200, json=rpc_ok(LIVE_MESSAGE_RESULT))

    c = make_client(handler)
    card, iface = c.discover_agent(ORIGIN)
    c.send_message(card, "hello", interface=iface)
    assert seen["body"]["method"] == "SendMessage"
    assert seen["headers"]["a2a-version"] == "1.0"


def test_no_auth_means_no_authorization_header():
    seen = {}

    def handler(req):
        if req.url.path == WELL_KNOWN_PATH:
            return httpx.Response(200, json=LIVE_CARD)
        seen["headers"] = dict(req.headers)
        return httpx.Response(200, json=rpc_ok(LIVE_MESSAGE_RESULT))

    c = make_client(handler)
    card, iface = c.discover_agent(ORIGIN)
    c.send_message(card, "hi", interface=iface, auth=NoAuthAdapter())
    assert "authorization" not in seen["headers"]


def test_external_bearer_token_is_sent_verbatim():
    seen = {}

    def handler(req):
        if req.url.path == WELL_KNOWN_PATH:
            return httpx.Response(200, json=LIVE_CARD)
        seen["headers"] = dict(req.headers)
        return httpx.Response(200, json=rpc_ok(LIVE_MESSAGE_RESULT))

    c = make_client(handler)
    card, iface = c.discover_agent(ORIGIN)
    c.send_message(card, "hi", interface=iface, auth=BearerTokenAdapter("ext-token-1"))
    assert seen["headers"]["authorization"] == "Bearer ext-token-1"


def test_request_body_never_contains_aera_identity_material():
    """The strongest boundary assertion: inspect the actual bytes on the wire."""
    captured = {}

    def handler(req):
        if req.url.path == WELL_KNOWN_PATH:
            return httpx.Response(200, json=LIVE_CARD)
        captured["raw"] = req.content.decode() + json.dumps(dict(req.headers))
        return httpx.Response(200, json=rpc_ok(LIVE_MESSAGE_RESULT))

    c = make_client(handler)
    card, iface = c.discover_agent(ORIGIN)
    c.send_message(card, "hello", interface=iface, auth=BearerTokenAdapter("ext-token-1"))

    blob = captured["raw"].lower()
    for forbidden in ("aera-agent-api", "aera-agent-relay", "did:aera",
                      "private key", "-----begin", "agent_jwt_secret", "eyj"):
        assert forbidden not in blob, f"{forbidden!r} leaked to the external agent"


# -- response handling -------------------------------------------------------
def test_direct_message_result_is_handled():
    r = _send(default_handler)
    assert r.kind == "message"
    assert "Sanctum is open to agents." in r.text
    assert r.state is None
    assert r.request_id


def test_task_result_is_handled():
    def handler(req):
        if req.url.path == WELL_KNOWN_PATH:
            return httpx.Response(200, json=LIVE_CARD)
        return httpx.Response(200, json=rpc_ok(TASK_RESULT))

    r = _send(handler)
    assert r.kind == "task"
    assert r.task_id == "task-123"
    assert r.context_id == "ctx-9"
    assert r.state == "completed"
    assert "done" in r.text and "artifact text" in r.text


def test_jsonrpc_error_becomes_a_remote_error_with_the_code():
    def handler(req):
        if req.url.path == WELL_KNOWN_PATH:
            return httpx.Response(200, json=LIVE_CARD)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": "x", "error": {
            "code": -32001, "message": "Task not found"}})

    with pytest.raises(A2ARemoteError) as exc:
        _send(handler)
    assert exc.value.code == -32001
    assert "Task not found" in str(exc.value)


def test_401_on_the_endpoint_becomes_an_auth_error():
    def handler(req):
        if req.url.path == WELL_KNOWN_PATH:
            return httpx.Response(200, json=LIVE_CARD)
        return httpx.Response(401, json={"error": "unauthorized"})

    with pytest.raises(A2AAuthError) as exc:
        _send(handler)
    assert exc.value.status == 401


def test_response_without_result_or_error_is_a_protocol_error():
    def handler(req):
        if req.url.path == WELL_KNOWN_PATH:
            return httpx.Response(200, json=LIVE_CARD)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": "x"})

    with pytest.raises(A2AProtocolError) as exc:
        _send(handler)
    assert "neither" in str(exc.value)


def test_non_json_response_is_a_protocol_error():
    def handler(req):
        if req.url.path == WELL_KNOWN_PATH:
            return httpx.Response(200, json=LIVE_CARD)
        return httpx.Response(200, text="not json at all")

    with pytest.raises(A2AProtocolError):
        _send(handler)


def test_result_of_wrong_type_is_a_protocol_error():
    def handler(req):
        if req.url.path == WELL_KNOWN_PATH:
            return httpx.Response(200, json=LIVE_CARD)
        return httpx.Response(200, json=rpc_ok("just a string"))

    with pytest.raises(A2AProtocolError):
        _send(handler)


def test_each_request_gets_a_fresh_id():
    ids = {_send(default_handler).request_id for _ in range(5)}
    assert len(ids) == 5


def _send(handler):
    c = make_client(handler)
    card, iface = c.discover_agent(ORIGIN)
    return c.send_message(card, "community-discovery: hi", interface=iface)
