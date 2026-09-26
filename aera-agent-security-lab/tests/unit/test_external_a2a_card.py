"""Agent Card parsing: both live card shapes, plus malformed input."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.external_a2a.card import (  # noqa: E402
    AgentCard,
    CardValidationError,
    normalise_version,
    parse_agent_card,
)

# Shape actually observed live at sanctum-beacon.onrender.com.
CARD_V03 = {
    "name": "Sanctum Beacon",
    "description": "Community discovery beacon.",
    "version": "1.1.0",
    "protocolVersion": "0.3.0",
    "url": "https://sanctum-beacon.onrender.com/a2a",
    "preferredTransport": "JSONRPC",
    "capabilities": {"streaming": False, "pushNotifications": False},
    "skills": [
        {"id": "community-discovery", "name": "Community discovery",
         "description": "Describes the community.", "tags": ["discovery"]},
    ],
    "documentationUrl": "https://sanctum-beacon.onrender.com/agents.md",
}

# Shape observed on v1.0 agents in the same register.
CARD_V10 = {
    "name": "Modern Agent",
    "description": "A v1.0 agent.",
    "version": "2.0.0",
    "supportedInterfaces": [
        {"url": "https://example.test/a2a", "protocolBinding": "JSONRPC",
         "protocolVersion": "1.0"},
    ],
    "skills": [],
}


def test_normalise_version_drops_patch():
    assert normalise_version("0.3.0") == "0.3"
    assert normalise_version("1.0") == "1.0"
    assert normalise_version("2") == "2"


def test_parse_v03_card_uses_top_level_url():
    card = parse_agent_card(CARD_V03, card_url="https://x.test/.well-known/agent-card.json")
    assert isinstance(card, AgentCard)
    assert card.name == "Sanctum Beacon"
    iface = card.preferred_interface()
    assert iface.url == "https://sanctum-beacon.onrender.com/a2a"
    assert iface.protocol_binding.upper() == "JSONRPC"
    assert iface.protocol_version == "0.3.0"
    assert iface.supported is True
    assert [s.id for s in card.skills] == ["community-discovery"]
    assert card.card_url.endswith("/.well-known/agent-card.json")


def test_parse_v10_card_uses_supported_interfaces():
    card = parse_agent_card(CARD_V10)
    iface = card.preferred_interface()
    assert iface.url == "https://example.test/a2a"
    assert normalise_version(iface.protocol_version) == "1.0"


def test_missing_required_field_is_rejected():
    bad = {k: v for k, v in CARD_V03.items() if k != "name"}
    with pytest.raises(CardValidationError):
        parse_agent_card(bad)


def test_card_without_any_endpoint_is_rejected():
    bad = {k: v for k, v in CARD_V03.items() if k != "url"}
    with pytest.raises(CardValidationError):
        parse_agent_card(bad)


def test_non_object_card_is_rejected():
    for bad in ("not a card", [], 42, None):
        with pytest.raises(CardValidationError):
            parse_agent_card(bad)


def test_wrong_type_field_is_rejected():
    bad = dict(CARD_V03, name=["not", "a", "string"])
    with pytest.raises(CardValidationError):
        parse_agent_card(bad)


def test_unsupported_protocol_version_has_no_usable_interface():
    card = parse_agent_card(dict(CARD_V03, protocolVersion="9.9.9"))
    assert card.preferred_interface  # attribute exists
    with pytest.raises(CardValidationError) as exc:
        card.preferred_interface()
    assert "9.9" in str(exc.value)


def test_unsupported_binding_has_no_usable_interface():
    card = parse_agent_card(dict(CARD_V03, preferredTransport="GRPC"))
    with pytest.raises(CardValidationError):
        card.preferred_interface()


def test_supported_interface_is_chosen_over_unsupported_one():
    raw = dict(CARD_V10, supportedInterfaces=[
        {"url": "https://example.test/grpc", "protocolBinding": "GRPC",
         "protocolVersion": "1.0"},
        {"url": "https://example.test/rpc", "protocolBinding": "JSONRPC",
         "protocolVersion": "1.0"},
    ])
    assert parse_agent_card(raw).preferred_interface().url == "https://example.test/rpc"


def test_security_schemes_alone_do_not_require_authentication():
    """Several live agents publish schemes for a separate REST API."""
    card = parse_agent_card(dict(CARD_V03, securitySchemes={
        "apiKey": {"type": "apiKey", "in": "header", "name": "X-API-Key"}}))
    assert card.requires_authentication is False


def test_non_empty_security_requirements_require_authentication():
    card = parse_agent_card(dict(CARD_V03, security=[{"apiKey": []}]))
    assert card.requires_authentication is True


def test_oversized_strings_are_capped():
    card = parse_agent_card(dict(CARD_V03, description="x" * 50_000))
    assert len(card.description) <= 4000


def test_raw_card_is_preserved_for_audit():
    card = parse_agent_card(CARD_V03)
    assert card.raw["name"] == "Sanctum Beacon"
