"""Typed internal representation of an external Agent Card.

Two incompatible card shapes exist in the wild and this parser handles both,
because the live register shows real agents on each:

  v0.3 (legacy)   top-level `url` + `preferredTransport`, optional
                  `additionalInterfaces`, top-level `protocolVersion`
  v1.0 (current)  `supportedInterfaces: [{url, protocolBinding, protocolVersion}]`

Everything here treats the card as UNTRUSTED input: fields are type-checked,
strings are length-capped, and no card value is ever interpolated into a prompt
or a shell command by this module.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from .errors import A2AProtocolError

#: Protocol major.minor versions this client knows how to speak.
SUPPORTED_PROTOCOL_VERSIONS = ("0.3", "1.0")

#: Protocol bindings this client implements. JSON-RPC only for the MVP.
SUPPORTED_BINDINGS = ("JSONRPC",)

MAX_STR = 4000
MAX_LIST = 200


class CardValidationError(A2AProtocolError):
    """The Agent Card is missing required fields or is malformed."""


def _str(value: Any, field_name: str, *, required: bool = False) -> str:
    if value is None:
        if required:
            raise CardValidationError(f"Agent Card: missing required field {field_name!r}")
        return ""
    if not isinstance(value, str):
        raise CardValidationError(
            f"Agent Card: field {field_name!r} must be a string, got {type(value).__name__}"
        )
    return value[:MAX_STR]


def _str_list(value: Any, field_name: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise CardValidationError(f"Agent Card: field {field_name!r} must be a list")
    return [_str(v, f"{field_name}[]") for v in value[:MAX_LIST] if isinstance(v, str)]


def normalise_version(raw: str) -> str:
    """'0.3.0' -> '0.3'. Patch versions are not part of A2A compatibility."""
    parts = [p for p in str(raw).split(".") if p != ""]
    if len(parts) >= 2:
        return f"{parts[0]}.{parts[1]}"
    return str(raw)


@dataclass(frozen=True)
class AgentSkill:
    id: str
    name: str
    description: str
    tags: tuple[str, ...] = ()
    examples: tuple[str, ...] = ()


@dataclass(frozen=True)
class AgentInterface:
    """One (url, binding, version) triple the agent claims to serve."""

    url: str
    protocol_binding: str
    protocol_version: str

    @property
    def supported(self) -> bool:
        return (
            self.protocol_binding.upper() in SUPPORTED_BINDINGS
            and normalise_version(self.protocol_version) in SUPPORTED_PROTOCOL_VERSIONS
        )


@dataclass(frozen=True)
class AgentCard:
    """What we actually need in order to talk to an external agent."""

    name: str
    description: str
    version: str
    interfaces: tuple[AgentInterface, ...]
    skills: tuple[AgentSkill, ...] = ()
    provider_organization: str = ""
    provider_url: str = ""
    documentation_url: str = ""
    capabilities: dict[str, Any] = field(default_factory=dict)
    #: Raw `securitySchemes` map, left as-is for the auth adapter to interpret.
    security_schemes: dict[str, Any] = field(default_factory=dict)
    #: Raw `security` / `securityRequirements` list.
    security_requirements: tuple[Any, ...] = ()
    card_url: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    # -- interface selection -------------------------------------------------
    def preferred_interface(self) -> AgentInterface:
        """First interface we can actually speak. Spec §8.3.2: order matters."""
        for iface in self.interfaces:
            if iface.supported:
                return iface
        claimed = ", ".join(
            f"{i.protocol_binding}/{i.protocol_version}" for i in self.interfaces
        ) or "<none>"
        raise CardValidationError(
            f"Agent Card for {self.name!r} declares no interface this client supports "
            f"(declared: {claimed}; supported: "
            f"{'/'.join(SUPPORTED_BINDINGS)} {SUPPORTED_PROTOCOL_VERSIONS})"
        )

    @property
    def requires_authentication(self) -> bool:
        """True when the card actually demands credentials.

        A `securitySchemes` map alone does NOT mean auth is required -- several
        live agents publish schemes for a separate REST API while leaving the
        A2A endpoint open. Only a non-empty requirement list obliges us.
        """
        return bool(self.security_requirements)

    def skill_ids(self) -> tuple[str, ...]:
        return tuple(s.id for s in self.skills)


def _parse_skills(raw: Any) -> tuple[AgentSkill, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise CardValidationError("Agent Card: 'skills' must be a list")
    out: list[AgentSkill] = []
    for item in raw[:MAX_LIST]:
        if not isinstance(item, dict):
            continue
        out.append(
            AgentSkill(
                id=_str(item.get("id"), "skills[].id"),
                name=_str(item.get("name"), "skills[].name"),
                description=_str(item.get("description"), "skills[].description"),
                tags=tuple(_str_list(item.get("tags"), "skills[].tags")),
                examples=tuple(_str_list(item.get("examples"), "skills[].examples")),
            )
        )
    return tuple(out)


def _parse_interfaces(card: dict[str, Any]) -> tuple[AgentInterface, ...]:
    ifaces: list[AgentInterface] = []

    # --- v1.0 shape ---
    supported = card.get("supportedInterfaces")
    if isinstance(supported, list) and supported:
        for item in supported[:MAX_LIST]:
            if not isinstance(item, dict):
                continue
            url = _str(item.get("url"), "supportedInterfaces[].url")
            if not url:
                continue
            ifaces.append(
                AgentInterface(
                    url=url,
                    protocol_binding=_str(
                        item.get("protocolBinding"), "supportedInterfaces[].protocolBinding"
                    ) or "JSONRPC",
                    protocol_version=_str(
                        item.get("protocolVersion"), "supportedInterfaces[].protocolVersion"
                    ) or "1.0",
                )
            )
        if ifaces:
            return tuple(ifaces)

    # --- v0.3 legacy shape ---
    top_version = _str(card.get("protocolVersion"), "protocolVersion") or "0.3"
    url = _str(card.get("url"), "url")
    if url:
        ifaces.append(
            AgentInterface(
                url=url,
                protocol_binding=_str(card.get("preferredTransport"), "preferredTransport")
                or "JSONRPC",
                protocol_version=top_version,
            )
        )
    extra = card.get("additionalInterfaces")
    if isinstance(extra, list):
        for item in extra[:MAX_LIST]:
            if not isinstance(item, dict):
                continue
            u = _str(item.get("url"), "additionalInterfaces[].url")
            if not u:
                continue
            ifaces.append(
                AgentInterface(
                    url=u,
                    protocol_binding=_str(
                        item.get("transport"), "additionalInterfaces[].transport"
                    ) or "JSONRPC",
                    protocol_version=top_version,
                )
            )

    if not ifaces:
        raise CardValidationError(
            "Agent Card declares no service endpoint "
            "(neither 'supportedInterfaces' nor a top-level 'url')"
        )
    return tuple(ifaces)


def parse_agent_card(raw: Any, *, card_url: str = "") -> AgentCard:
    """Validate and convert an untrusted Agent Card document."""
    if not isinstance(raw, dict):
        raise CardValidationError(
            f"Agent Card must be a JSON object, got {type(raw).__name__}"
        )

    name = _str(raw.get("name"), "name", required=True)
    if not name.strip():
        raise CardValidationError("Agent Card: 'name' must not be empty")

    provider = raw.get("provider") if isinstance(raw.get("provider"), dict) else {}
    caps = raw.get("capabilities") if isinstance(raw.get("capabilities"), dict) else {}
    schemes = raw.get("securitySchemes") if isinstance(raw.get("securitySchemes"), dict) else {}

    reqs = raw.get("securityRequirements")
    if reqs is None:
        reqs = raw.get("security")
    reqs_tuple = tuple(reqs[:MAX_LIST]) if isinstance(reqs, list) else ()

    return AgentCard(
        name=name,
        description=_str(raw.get("description"), "description"),
        version=_str(raw.get("version"), "version"),
        interfaces=_parse_interfaces(raw),
        skills=_parse_skills(raw.get("skills")),
        provider_organization=_str(provider.get("organization"), "provider.organization"),
        provider_url=_str(provider.get("url"), "provider.url"),
        documentation_url=_str(raw.get("documentationUrl"), "documentationUrl"),
        capabilities=caps,
        security_schemes=schemes,
        security_requirements=reqs_tuple,
        card_url=card_url,
        raw=raw,
    )
