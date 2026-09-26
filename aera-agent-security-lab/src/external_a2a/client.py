"""Minimal external A2A client: discover -> validate -> authenticate -> send.

Discovery mechanism (verified against the current specification, §8.2 and the
IANA well-known registration in §14.3):

    GET https://{domain}/.well-known/agent-card.json

That is the only discovery mechanism implemented, because it is the minimal one
required for a first real interoperability test. Registries and direct
configuration are supported only in the trivial sense that an explicit card URL
may be passed in.

JSON-RPC method naming differs across protocol versions and both are live in the
wild, so the binding is chosen from the selected interface:

    0.3  ->  "message/send"
    1.0  ->  "SendMessage"
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import urlsplit, urlunsplit

import httpx

from .auth import A2AAuthAdapter, NoAuthAdapter
from .card import AgentCard, AgentInterface, normalise_version, parse_agent_card
from .errors import A2AAuthError, A2AProtocolError, A2ARemoteError
from .net import NetPolicy, decode_json, request

#: The IANA-registered well-known URI suffix for A2A discovery.
WELL_KNOWN_PATH = "/.well-known/agent-card.json"

#: Per-version JSON-RPC method names for the "send message" operation.
SEND_METHOD_BY_VERSION = {"0.3": "message/send", "1.0": "SendMessage"}


def well_known_url(agent_url: str) -> str:
    """Derive the discovery URL from any URL belonging to the agent's origin."""
    parts = urlsplit(agent_url if "://" in agent_url else f"https://{agent_url}")
    if not parts.netloc:
        raise A2AProtocolError(f"cannot derive a well-known URL from {agent_url!r}")
    return urlunsplit((parts.scheme or "https", parts.netloc, WELL_KNOWN_PATH, "", ""))


@dataclass
class A2AResponse:
    """A normalised view of whatever the external agent returned."""

    kind: str                      # "task" | "message"
    task_id: Optional[str]
    context_id: Optional[str]
    state: Optional[str]
    text: str
    raw: dict[str, Any]
    request_id: str


def _extract_text(node: Any, out: list[str], depth: int = 0) -> None:
    """Pull text parts out of a Task/Message without trusting its shape."""
    if depth > 6 or len(out) > 50:
        return
    if isinstance(node, dict):
        for key in ("text",):
            v = node.get(key)
            if isinstance(v, str) and v:
                out.append(v)
        for key in ("parts", "artifacts", "history", "status", "message", "artifact"):
            if key in node:
                _extract_text(node[key], out, depth + 1)
    elif isinstance(node, list):
        for item in node[:50]:
            _extract_text(item, out, depth + 1)


class A2AClient:
    """Smallest useful external A2A client."""

    def __init__(
        self,
        *,
        policy: Optional[NetPolicy] = None,
        auth: Optional[A2AAuthAdapter] = None,
        http: Optional[httpx.Client] = None,
    ) -> None:
        self.policy = policy or NetPolicy()
        self.auth = auth or NoAuthAdapter()
        self._http = http

    # -- discovery -----------------------------------------------------------
    def get_agent_card(self, url: str) -> AgentCard:
        """Fetch and validate an Agent Card. `url` may be an origin or a card URL."""
        card_url = url if url.rstrip("/").endswith(WELL_KNOWN_PATH) else well_known_url(url)
        status, headers, body = request(
            "GET",
            card_url,
            policy=self.policy,
            headers={"Accept": "application/json"},
            client=self._http,
        )
        if status == 401 or status == 403:
            raise A2AAuthError(
                f"Agent Card at {card_url} requires authentication (HTTP {status})",
                status=status,
            )
        if status != 200:
            raise A2AProtocolError(
                f"Agent Card fetch failed: HTTP {status} from {card_url}",
                detail=body[:400].decode("utf-8", "replace"),
            )
        ctype = headers.get("content-type", "")
        if "json" not in ctype.lower():
            raise A2AProtocolError(
                f"Agent Card at {card_url} is not JSON (content-type: {ctype!r})"
            )
        return parse_agent_card(decode_json(body, what="Agent Card"), card_url=card_url)

    def discover_agent(self, url: str) -> tuple[AgentCard, AgentInterface]:
        """Discover an agent and pick the interface we will actually use."""
        card = self.get_agent_card(url)
        return card, card.preferred_interface()

    # -- messaging -----------------------------------------------------------
    def send_message(
        self,
        card: AgentCard,
        text: str,
        *,
        interface: Optional[AgentInterface] = None,
        context_id: Optional[str] = None,
        task_id: Optional[str] = None,
        auth: Optional[A2AAuthAdapter] = None,
    ) -> A2AResponse:
        """Send one text message and return the normalised response."""
        iface = interface or card.preferred_interface()
        version = normalise_version(iface.protocol_version)
        method = SEND_METHOD_BY_VERSION.get(version)
        if method is None:
            raise A2AProtocolError(f"unsupported protocol version {iface.protocol_version!r}")

        adapter = auth or self.auth
        request_id = str(uuid.uuid4())

        message: dict[str, Any] = {
            "messageId": uuid.uuid4().hex,
            "role": "user" if version == "0.3" else "ROLE_USER",
            "parts": [{"kind": "text", "text": text}] if version == "0.3"
            else [{"text": text}],
        }
        if context_id:
            message["contextId"] = context_id
        if task_id:
            message["taskId"] = task_id

        payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": {"message": message},
        }

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "A2A-Version": version,
            **adapter.headers(),
        }

        status, resp_headers, body = request(
            "POST",
            iface.url,
            policy=self.policy,
            headers=headers,
            json_body=payload,
            client=self._http,
        )

        if status in (401, 403):
            raise A2AAuthError(
                f"external agent rejected our credentials (HTTP {status}); "
                f"auth scheme used: {adapter.describe()}",
                status=status,
                scheme=adapter.describe(),
                detail=body[:400].decode("utf-8", "replace"),
            )

        data = decode_json(body, what="A2A response")
        if not isinstance(data, dict):
            raise A2AProtocolError("A2A response is not a JSON object")

        if "error" in data and data.get("error") is not None:
            err = data["error"]
            code = err.get("code") if isinstance(err, dict) else None
            msg = err.get("message") if isinstance(err, dict) else str(err)
            raise A2ARemoteError(
                f"external agent returned an A2A error: {msg}", code=code, detail=err
            )

        if status != 200:
            raise A2AProtocolError(
                f"external agent returned HTTP {status} without a JSON-RPC error object"
            )

        if "result" not in data:
            raise A2AProtocolError("A2A response has neither 'result' nor 'error'")

        result = data["result"]
        if not isinstance(result, dict):
            raise A2AProtocolError("A2A 'result' is not a JSON object")

        texts: list[str] = []
        _extract_text(result, texts)

        # A Task and a direct Message are both legal replies (spec §3.1.1).
        task = result.get("task") if isinstance(result.get("task"), dict) else None
        node = task or result
        is_task = bool(task) or result.get("kind") == "task" or "status" in node

        state = None
        status_obj = node.get("status")
        if isinstance(status_obj, dict):
            state = status_obj.get("state")

        return A2AResponse(
            kind="task" if is_task else "message",
            task_id=node.get("id") if is_task else node.get("taskId"),
            context_id=node.get("contextId"),
            state=state if isinstance(state, str) else None,
            text="\n".join(texts).strip(),
            raw=data,
            request_id=request_id,
        )


# -- module-level convenience ------------------------------------------------
def get_agent_card(url: str, *, policy: Optional[NetPolicy] = None) -> AgentCard:
    return A2AClient(policy=policy).get_agent_card(url)


def discover_agent(
    url: str, *, policy: Optional[NetPolicy] = None
) -> tuple[AgentCard, AgentInterface]:
    return A2AClient(policy=policy).discover_agent(url)
