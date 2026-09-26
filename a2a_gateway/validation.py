"""Inbound request validation.

Every byte here is attacker-controlled. The rules are:

  * validate structure before meaning
  * no silent interpretation of unknown fields
  * no coercion -- a field of the wrong type is an error, not a cast
  * bound every length and every collection
  * a claim in the payload is a claim, never a fact

Errors are raised as `GatewayError`, which carries a JSON-RPC code and a message
that is safe to send outside.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from .constants import (
    A2A_PROTOCOL_VERSION,
    ERR_CONTENT_TYPE_NOT_SUPPORTED,
    ERR_INVALID_PARAMS,
    ERR_INVALID_REQUEST,
    ERR_METHOD_NOT_FOUND,
    ERR_UNSUPPORTED_OPERATION,
    ERR_VERSION_NOT_SUPPORTED,
    KNOWN_UNIMPLEMENTED_METHODS,
    MAX_CLOCK_SKEW_SECONDS,
    MAX_ID_LEN,
    MAX_METADATA_KEYS,
    MAX_PARTS,
    MAX_REQUEST_AGE_SECONDS,
    MAX_TEXT_LEN,
    SUPPORTED_METHODS,
    SUPPORTED_SKILLS,
    TARGET_AGENT_FIELD,
)

#: Identifiers we accept. Deliberately strict: no whitespace, no control
#: characters, no path separators, nothing that could be reflected somewhere
#: dangerous.
ID_PATTERN = re.compile(r"^[A-Za-z0-9._:\-]{1,200}$")


class GatewayError(Exception):
    """A rejection that is safe to report to the external caller."""

    def __init__(self, code: int, message: str, *, internal: str = "",
                 retry_after: int = 0) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        #: Never sent outside; for the audit log only.
        self.internal = internal or message
        #: Seconds, only set for rate-limit rejections. Surfaced to the caller
        #: because telling a well-behaved client when to come back is how you
        #: stop it from retrying in a tight loop and making things worse.
        self.retry_after = retry_after


@dataclass
class InboundRequest:
    """A validated inbound A2A request. Nothing here is trusted as identity."""

    rpc_id: Any
    method: str
    message_id: str
    role: str
    text: str
    target_agent_id: str
    skill_id: Optional[str]
    protocol_version: str
    task_id: Optional[str] = None
    context_id: Optional[str] = None
    claimed_sender: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)


# -- primitives --------------------------------------------------------------
def _require_dict(value: Any, what: str, code: int = ERR_INVALID_PARAMS) -> dict:
    if not isinstance(value, dict):
        raise GatewayError(code, f"{what} must be a JSON object")
    return value


def _require_str(obj: dict, key: str, what: str, *, required: bool = True,
                 max_len: int = MAX_TEXT_LEN) -> Optional[str]:
    if key not in obj or obj[key] is None:
        if required:
            raise GatewayError(ERR_INVALID_PARAMS, f"{what}: missing '{key}'")
        return None
    value = obj[key]
    if not isinstance(value, str):
        raise GatewayError(ERR_INVALID_PARAMS, f"{what}: '{key}' must be a string")
    if len(value) > max_len:
        raise GatewayError(ERR_INVALID_PARAMS,
                           f"{what}: '{key}' exceeds {max_len} characters")
    return value


def _require_id(obj: dict, key: str, what: str, *, required: bool = True
                ) -> Optional[str]:
    value = _require_str(obj, key, what, required=required, max_len=MAX_ID_LEN)
    if value is None:
        return None
    if not ID_PATTERN.match(value):
        raise GatewayError(ERR_INVALID_PARAMS, f"{what}: '{key}' is not a valid identifier")
    return value


def _parse_timestamp(raw: str, what: str) -> datetime:
    text = raw.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise GatewayError(ERR_INVALID_PARAMS,
                           f"{what} is not a valid ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


# -- JSON-RPC envelope -------------------------------------------------------
def validate_jsonrpc_envelope(body: Any) -> tuple[Any, str, dict]:
    """Validate the JSON-RPC 2.0 frame. Returns (id, method, params)."""
    payload = _require_dict(body, "request", code=ERR_INVALID_REQUEST)

    if payload.get("jsonrpc") != "2.0":
        raise GatewayError(ERR_INVALID_REQUEST, "jsonrpc must be exactly \"2.0\"")

    if "id" not in payload:
        raise GatewayError(ERR_INVALID_REQUEST,
                           "missing request id; notifications are not supported")
    rpc_id = payload["id"]
    if not isinstance(rpc_id, (str, int)) or isinstance(rpc_id, bool):
        raise GatewayError(ERR_INVALID_REQUEST, "request id must be a string or a number")
    if isinstance(rpc_id, str) and (not rpc_id or len(rpc_id) > MAX_ID_LEN):
        raise GatewayError(ERR_INVALID_REQUEST, "request id has an invalid length")

    method = payload.get("method")
    if not isinstance(method, str) or not method:
        raise GatewayError(ERR_INVALID_REQUEST, "method must be a non-empty string")
    if method not in SUPPORTED_METHODS:
        if method in KNOWN_UNIMPLEMENTED_METHODS:
            raise GatewayError(ERR_UNSUPPORTED_OPERATION,
                               f"method '{method}' is not implemented by this gateway")
        raise GatewayError(ERR_METHOD_NOT_FOUND, f"unknown method '{method[:64]}'")

    params = payload.get("params")
    if params is None:
        raise GatewayError(ERR_INVALID_PARAMS, "missing params")
    params = _require_dict(params, "params")

    return rpc_id, method, params


# -- A2A message -------------------------------------------------------------
def _validate_parts(raw: Any) -> str:
    if not isinstance(raw, list):
        raise GatewayError(ERR_INVALID_PARAMS, "message.parts must be an array")
    if not raw:
        raise GatewayError(ERR_INVALID_PARAMS, "message.parts must not be empty")
    if len(raw) > MAX_PARTS:
        raise GatewayError(ERR_INVALID_PARAMS,
                           f"message.parts exceeds {MAX_PARTS} entries")

    texts: list[str] = []
    for index, part in enumerate(raw):
        part = _require_dict(part, f"message.parts[{index}]")
        kind = part.get("kind", "text")
        if not isinstance(kind, str):
            raise GatewayError(ERR_INVALID_PARAMS,
                               f"message.parts[{index}].kind must be a string")
        if kind != "text":
            # Honest refusal rather than pretending to understand the content.
            raise GatewayError(
                ERR_CONTENT_TYPE_NOT_SUPPORTED,
                f"unsupported part kind '{kind[:32]}'; only text parts are accepted")
        text = _require_str(part, "text", f"message.parts[{index}]")
        texts.append(text or "")

    combined = "\n".join(texts)
    if len(combined) > MAX_TEXT_LEN:
        raise GatewayError(ERR_INVALID_PARAMS,
                           f"message text exceeds {MAX_TEXT_LEN} characters")
    return combined


def _validate_metadata(raw: Any) -> dict[str, Any]:
    if raw is None:
        return {}
    meta = _require_dict(raw, "metadata")
    if len(meta) > MAX_METADATA_KEYS:
        raise GatewayError(ERR_INVALID_PARAMS,
                           f"metadata exceeds {MAX_METADATA_KEYS} keys")
    for key in meta:
        if not isinstance(key, str) or len(key) > MAX_ID_LEN:
            raise GatewayError(ERR_INVALID_PARAMS, "metadata keys must be short strings")
    return meta


def _check_freshness(meta: dict[str, Any], now: Optional[datetime] = None) -> None:
    """Honour timestamp/expiry only if the caller supplied them."""
    current = now or datetime.now(timezone.utc)

    raw_expiry = meta.get("expiresAt") or meta.get("expires_at")
    if raw_expiry is not None:
        if not isinstance(raw_expiry, str):
            raise GatewayError(ERR_INVALID_PARAMS, "expiresAt must be a string")
        if _parse_timestamp(raw_expiry, "expiresAt") <= current:
            raise GatewayError(ERR_INVALID_REQUEST, "request has expired")

    raw_issued = meta.get("issuedAt") or meta.get("issued_at")
    if raw_issued is not None:
        if not isinstance(raw_issued, str):
            raise GatewayError(ERR_INVALID_PARAMS, "issuedAt must be a string")
        issued = _parse_timestamp(raw_issued, "issuedAt")
        age = (current - issued).total_seconds()
        if age > MAX_REQUEST_AGE_SECONDS:
            raise GatewayError(ERR_INVALID_REQUEST, "request is too old")
        if age < -MAX_CLOCK_SKEW_SECONDS:
            raise GatewayError(ERR_INVALID_REQUEST, "request issuedAt is in the future")


def validate_message_send(rpc_id: Any, method: str, params: dict,
                          *, protocol_version: str,
                          now: Optional[datetime] = None) -> InboundRequest:
    """Validate params for `message/send` and extract the routing target."""
    if protocol_version and protocol_version != A2A_PROTOCOL_VERSION:
        raise GatewayError(
            ERR_VERSION_NOT_SUPPORTED,
            f"unsupported A2A protocol version '{protocol_version[:16]}'; "
            f"this gateway speaks {A2A_PROTOCOL_VERSION}")

    message = _require_dict(params.get("message"), "params.message")

    message_id = _require_id(message, "messageId", "message")
    assert message_id is not None

    role = _require_str(message, "role", "message", max_len=32)
    if role not in ("user", "agent"):
        raise GatewayError(ERR_INVALID_PARAMS, "message.role must be 'user' or 'agent'")

    kind = message.get("kind")
    if kind is not None and kind != "message":
        raise GatewayError(ERR_INVALID_PARAMS, "message.kind must be 'message'")

    text = _validate_parts(message.get("parts"))

    metadata = _validate_metadata(message.get("metadata"))
    metadata.update(_validate_metadata(params.get("metadata")))
    _check_freshness(metadata, now=now)

    target = metadata.get(TARGET_AGENT_FIELD)
    if target is None:
        raise GatewayError(
            ERR_INVALID_PARAMS,
            f"no target AEra agent specified; set metadata.{TARGET_AGENT_FIELD}")
    if not isinstance(target, str) or not ID_PATTERN.match(target):
        raise GatewayError(ERR_INVALID_PARAMS,
                           f"metadata.{TARGET_AGENT_FIELD} is not a valid agent id")

    skill_id = _resolve_skill(metadata, text)

    claimed_sender = metadata.get("senderAgentId") or metadata.get("sender_agent_id")
    if claimed_sender is not None and not isinstance(claimed_sender, str):
        raise GatewayError(ERR_INVALID_PARAMS, "senderAgentId must be a string")

    return InboundRequest(
        rpc_id=rpc_id,
        method=method,
        message_id=message_id,
        role=role,
        text=text,
        target_agent_id=target,
        skill_id=skill_id,
        protocol_version=protocol_version or A2A_PROTOCOL_VERSION,
        task_id=_require_id(message, "taskId", "message", required=False),
        context_id=_require_id(message, "contextId", "message", required=False),
        claimed_sender=claimed_sender[:MAX_ID_LEN] if claimed_sender else None,
        metadata=metadata,
    )


def _resolve_skill(metadata: dict[str, Any], text: str) -> str:
    """Determine the requested skill explicitly; never guess from free text."""
    raw = metadata.get("skillId") or metadata.get("skill_id")
    if raw is None:
        # Accept the documented convention of naming the skill as the leading
        # token, which is how the card's own example is written.
        head = text.strip().split(":", 1)[0].strip()
        raw = head if head in SUPPORTED_SKILLS else None
    if raw is None:
        raise GatewayError(
            ERR_INVALID_PARAMS,
            "no skill requested; set metadata.skillId to one of: "
            + ", ".join(sorted(SUPPORTED_SKILLS)))
    if not isinstance(raw, str) or raw not in SUPPORTED_SKILLS:
        raise GatewayError(
            ERR_UNSUPPORTED_OPERATION,
            f"skill '{str(raw)[:64]}' is not offered by this gateway; supported: "
            + ", ".join(sorted(SUPPORTED_SKILLS)))
    return raw
