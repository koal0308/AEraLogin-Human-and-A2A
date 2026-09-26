"""The audit trail must be useful and must never contain a secret."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.external_a2a.audit import AuditLog, _scrub, build_record  # noqa: E402
from src.external_a2a.card import parse_agent_card  # noqa: E402

CARD = parse_agent_card({
    "name": "Sanctum Beacon", "description": "d", "version": "1.1.0",
    "protocolVersion": "0.3.0", "url": "https://x.test/a2a",
    "preferredTransport": "JSONRPC",
}, card_url="https://x.test/.well-known/agent-card.json")
IFACE = CARD.preferred_interface()


def test_record_captures_the_required_metadata():
    r = build_record(
        aera_agent_id="did:aera:agent:abc", card=CARD, interface=IFACE,
        skill_id="community-discovery", auth_scheme="none", http_status=200,
        request_id="req-1", task_id="task-1", success=True)
    d = r.to_dict()
    assert d["aera_agent_id"] == "did:aera:agent:abc"
    assert d["external_agent_name"] == "Sanctum Beacon"
    assert d["agent_card_url"].endswith("/.well-known/agent-card.json")
    assert d["endpoint_url"] == "https://x.test/a2a"
    assert d["protocol_version"] == "0.3.0"
    assert d["skill_id"] == "community-discovery"
    assert d["auth_scheme"] == "none"
    assert d["http_status"] == 200
    assert d["success"] is True
    assert d["timestamp"].endswith("+00:00")


def test_failure_records_the_error_category():
    r = build_record(aera_agent_id=None, card=CARD, interface=IFACE,
                     success=False, error_category="auth",
                     error_message="rejected our credentials")
    assert r.success is False and r.error_category == "auth"


def test_credential_like_values_are_redacted():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.sig"
    assert "eyJ" not in json.dumps(_scrub({"t": jwt}))
    assert "BEGIN" not in json.dumps(_scrub({"k": "-----BEGIN PRIVATE KEY-----"}))
    assert "hunter2" not in json.dumps(_scrub({"s": "AGENT_JWT_SECRET=hunter2"}))


def test_long_values_are_truncated():
    assert len(_scrub("x" * 10_000)) < 600


def test_audit_log_writes_jsonl(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append(build_record(aera_agent_id="a", card=CARD, interface=IFACE, success=True))
    log.append(build_record(aera_agent_id="b", card=CARD, interface=IFACE, success=False))
    lines = path.read_text().strip().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["aera_agent_id"] == "a"
    assert json.loads(lines[1])["success"] is False


def test_audit_log_never_persists_a_token(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append(build_record(
        aera_agent_id="a", card=CARD, interface=IFACE, success=True,
        auth_scheme="bearer",
        error_message="failed with eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.sig"))
    text = path.read_text()
    assert "eyJ" not in text
    assert '"auth_scheme": "bearer"' in text  # the scheme NAME is fine


def test_in_memory_render_matches_records():
    log = AuditLog()
    log.append(build_record(aera_agent_id="a", card=CARD, interface=IFACE, success=True))
    assert json.loads(log.render())["external_agent_name"] == "Sanctum Beacon"
