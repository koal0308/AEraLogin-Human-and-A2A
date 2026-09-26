"""Dashboard "Agents" section — API and security tests.

Covers the two new READ-ONLY dashboard endpoints plus the end-to-end owner
lifecycle they surface, and asserts that the dashboard cannot become a hole in
the Agent Identity Layer.

The mutating flows are exercised through the EXISTING /api/agents/* endpoints
(via AgentTestClient), which is exactly what the browser does.
"""
from __future__ import annotations

import json
import pathlib
import re
import shutil
import subprocess

import pytest

from agent.constants import (
    AUD_AGENT_API,
    AUD_AGENT_RELAY,
    CAPABILITY_ALLOWLIST,
    OWNER_CHALLENGE_KEYS,
    OWNER_DOMAIN,
    PROTO_OWNER_CHALLENGE,
    PROTOCOL_VERSION,
)
from agent.crypto import Ed25519Signer, canonical_json

from tests.agent.testclient import ANVIL_KEY_1, ANVIL_KEY_2, AgentTestClient

REPO = pathlib.Path(__file__).resolve().parents[2]
AGENTS_JS = REPO / "aera-agents.js"
DASHBOARD_HTML = REPO / "user-dashboard.html"

LIST_URL = "/api/dashboard/agents"


# --------------------------------------------------------------------------- #
# fixtures
# --------------------------------------------------------------------------- #
@pytest.fixture()
def alice(client, wipe_agent_tables) -> AgentTestClient:
    a = AgentTestClient(client, eth_priv=ANVIL_KEY_1)
    a.register()
    return a


@pytest.fixture()
def bob(client, wipe_agent_tables) -> AgentTestClient:
    b = AgentTestClient(client, eth_priv=ANVIL_KEY_2)
    b.register()
    return b


def session_headers(server_module, wallet: str) -> dict:
    """A real dashboard session token, minted the same way the app mints it."""
    token = server_module.generate_dashboard_jwt(wallet)
    return {"Authorization": f"Bearer {token}"}


# --------------------------------------------------------------------------- #
# Authentication
# --------------------------------------------------------------------------- #
def test_unauthenticated_user_cannot_list_agents(client, alice):
    assert client.get(LIST_URL).status_code == 401


def test_malformed_authorization_header_is_rejected(client, alice):
    for header in ("", "Bearer", "Basic abc", "Bearer not-a-jwt", "Bearer a.b.c"):
        r = client.get(LIST_URL, headers={"Authorization": header})
        assert r.status_code == 401, header


def test_token_signed_with_the_wrong_secret_is_rejected(client, alice):
    import jwt as _jwt
    forged = _jwt.encode({"address": alice.owner}, "attacker-secret", algorithm="HS256")
    r = client.get(LIST_URL, headers={"Authorization": f"Bearer {forged}"})
    assert r.status_code == 401


def test_authenticated_user_sees_own_agents(client, server_module, alice):
    r = client.get(LIST_URL, headers=session_headers(server_module, alice.owner))
    assert r.status_code == 200
    body = r.json()
    assert body["success"] is True
    assert [a["agent_id"] for a in body["agents"]] == [alice.agent_id]


def test_detail_endpoint_requires_authentication(client, alice):
    assert client.get(f"{LIST_URL}/{alice.agent_id}").status_code == 401


# --------------------------------------------------------------------------- #
# Ownership
# --------------------------------------------------------------------------- #
def test_user_a_does_not_see_user_b_agents_in_the_list(client, server_module, alice, bob):
    r = client.get(LIST_URL, headers=session_headers(server_module, alice.owner))
    ids = [a["agent_id"] for a in r.json()["agents"]]
    assert alice.agent_id in ids
    assert bob.agent_id not in ids


def test_user_a_cannot_view_user_b_agent_detail(client, server_module, alice, bob):
    r = client.get(f"{LIST_URL}/{bob.agent_id}",
                   headers=session_headers(server_module, alice.owner))
    assert r.status_code == 404
    assert bob.owner not in r.text


def test_detail_does_not_distinguish_foreign_from_missing(client, server_module, alice, bob):
    """Otherwise the endpoint becomes an agent-existence oracle."""
    foreign = client.get(f"{LIST_URL}/{bob.agent_id}",
                         headers=session_headers(server_module, alice.owner))
    missing = client.get(f"{LIST_URL}/did:aera:agent:{'0' * 32}",
                         headers=session_headers(server_module, alice.owner))
    assert foreign.status_code == missing.status_code == 404
    assert foreign.json() == missing.json()


def test_ownership_comes_from_the_token_not_from_the_request(client, server_module, alice, bob):
    """A query parameter must never be able to switch owners."""
    headers = session_headers(server_module, alice.owner)
    r = client.get(f"{LIST_URL}?owner={bob.owner}", headers=headers)
    assert r.status_code == 200
    assert [a["agent_id"] for a in r.json()["agents"]] == [alice.agent_id]


def test_user_a_cannot_revoke_user_b_agent(client, alice, bob):
    """The dashboard exposes revoke, but authority stays with the Agent layer."""
    ch = alice.owner_challenge("agent_revoke", agent_id=bob.agent_id)
    sig = alice._owner_sign(ch)
    r = client.request("DELETE", f"/api/agents/{bob.agent_id}", json={
        "owner_wallet": alice.owner,
        "owner_challenge_id": ch["challenge_id"],
        "owner_signature": sig,
        "public_key": alice.signer.public_key_encoded(),
    })
    assert r.status_code == 401
    assert client.get(f"/api/agents/{bob.agent_id}").json()["status"] == "active"


def test_user_a_cannot_modify_user_b_capabilities(client, alice, bob):
    ch = alice.owner_challenge("capabilities", agent_id=bob.agent_id)
    sig = alice._owner_sign(ch)
    r = client.patch(f"/api/agents/{bob.agent_id}/capabilities", json={
        "owner_wallet": alice.owner,
        "owner_challenge_id": ch["challenge_id"],
        "owner_signature": sig,
        "capabilities": ["agent.communicate"],
    })
    assert r.status_code == 401


def test_user_a_cannot_add_a_key_to_user_b_agent(client, alice, bob):
    ch = alice.owner_challenge("key_add", agent_id=bob.agent_id)
    sig = alice._owner_sign(ch)
    r = client.post(f"/api/agents/{bob.agent_id}/keys", json={
        "owner_wallet": alice.owner,
        "owner_challenge_id": ch["challenge_id"],
        "owner_signature": sig,
        "public_key": Ed25519Signer.generate().public_key_encoded(),
    })
    assert r.status_code == 401


# --------------------------------------------------------------------------- #
# Registration
# --------------------------------------------------------------------------- #
def test_valid_owner_authenticated_registration_succeeds(client, server_module, wipe_agent_tables):
    a = AgentTestClient(client, eth_priv=ANVIL_KEY_1)
    data = a.register(capabilities=["agent.communicate"])
    assert data["agent_id"].startswith("did:aera:agent:")
    r = client.get(LIST_URL, headers=session_headers(server_module, a.owner))
    listed = r.json()["agents"][0]
    assert listed["agent_id"] == data["agent_id"]
    assert listed["capabilities"] == ["agent.communicate"]
    assert listed["active_key_id"] == data["key_id"]


def test_registration_without_owner_signature_fails(client, wipe_agent_tables):
    a = AgentTestClient(client, eth_priv=ANVIL_KEY_1)
    ch = a.owner_challenge("register")
    r = client.post("/api/agents/register", json={
        "owner_wallet": a.owner,
        "owner_challenge_id": ch["challenge_id"],
        "owner_signature": "0x" + "00" * 65,
        "public_key": a.signer.public_key_encoded(),
    })
    assert r.status_code == 401


def test_registration_with_another_wallets_signature_fails(client, wipe_agent_tables):
    a = AgentTestClient(client, eth_priv=ANVIL_KEY_1)
    b = AgentTestClient(client, eth_priv=ANVIL_KEY_2)
    ch = a.owner_challenge("register")
    r = client.post("/api/agents/register", json={
        "owner_wallet": a.owner,
        "owner_challenge_id": ch["challenge_id"],
        "owner_signature": b._owner_sign(ch),  # signed by the wrong owner
        "public_key": a.signer.public_key_encoded(),
    })
    assert r.status_code == 401


@pytest.mark.parametrize("bad_key", [
    "", "not-a-key", "ed25519:", "ed25519:!!!!", "rsa:abcdef",
    "ed25519:" + "A" * 10,
])
def test_malformed_public_key_is_rejected(client, wipe_agent_tables, bad_key):
    a = AgentTestClient(client, eth_priv=ANVIL_KEY_1)
    ch = a.owner_challenge("register")
    r = client.post("/api/agents/register", json={
        "owner_wallet": a.owner,
        "owner_challenge_id": ch["challenge_id"],
        "owner_signature": a._owner_sign(ch),
        "public_key": bad_key,
    })
    assert r.status_code == 400


def test_unsupported_capability_is_not_granted(client, server_module, wipe_agent_tables):
    """Backend semantics: unknown capabilities are dropped, not accepted."""
    a = AgentTestClient(client, eth_priv=ANVIL_KEY_1)
    data = a.register(capabilities=["agent.communicate", "agent.root", "billing.charge"])
    assert "agent.root" not in data["capabilities"]
    assert "billing.charge" not in data["capabilities"]
    assert set(data["capabilities"]) <= set(CAPABILITY_ALLOWLIST)


def test_owner_challenge_is_single_use(client, wipe_agent_tables):
    """The dashboard cannot be tricked into replaying a registration."""
    a = AgentTestClient(client, eth_priv=ANVIL_KEY_1)
    ch = a.owner_challenge("register")
    sig = a._owner_sign(ch)
    body = {
        "owner_wallet": a.owner,
        "owner_challenge_id": ch["challenge_id"],
        "owner_signature": sig,
        "public_key": a.signer.public_key_encoded(),
    }
    assert client.post("/api/agents/register", json=body).status_code == 200
    assert client.post("/api/agents/register", json=body).status_code == 401


def test_capability_allowlist_is_reported_to_the_dashboard(client, server_module, alice):
    """The UI renders only what the backend would accept."""
    r = client.get(LIST_URL, headers=session_headers(server_module, alice.owner))
    assert sorted(r.json()["capability_allowlist"]) == sorted(CAPABILITY_ALLOWLIST)


# --------------------------------------------------------------------------- #
# Key management
# --------------------------------------------------------------------------- #
def test_authorized_key_rotation_succeeds_and_identity_is_unchanged(
        client, server_module, alice):
    headers = session_headers(server_module, alice.owner)
    before = client.get(f"{LIST_URL}/{alice.agent_id}", headers=headers).json()["agent"]

    new_signer = Ed25519Signer.generate()
    new_key_id = alice.rotate_key(new_signer, revoke=alice.key_id)

    after = client.get(f"{LIST_URL}/{alice.agent_id}", headers=headers).json()["agent"]
    assert after["agent_id"] == before["agent_id"]          # identity preserved
    assert after["owner_wallet"] == before["owner_wallet"]
    assert after["active_key_id"] == new_key_id             # only the key changed
    assert after["active_key_id"] != before["active_key_id"]


def test_unauthorized_rotation_fails(client, alice, bob):
    ch = bob.owner_challenge("key_rotate", agent_id=alice.agent_id)
    r = client.post(f"/api/agents/{alice.agent_id}/keys/rotate", json={
        "owner_wallet": bob.owner,
        "owner_challenge_id": ch["challenge_id"],
        "owner_signature": bob._owner_sign(ch),
        "new_public_key": Ed25519Signer.generate().public_key_encoded(),
        "revoke_key_id": alice.key_id,
    })
    assert r.status_code == 401


def test_key_revoke_works_and_is_reflected_in_the_dashboard(client, server_module, alice):
    headers = session_headers(server_module, alice.owner)
    second = alice.add_key(Ed25519Signer.generate())
    assert client.get(f"{LIST_URL}/{alice.agent_id}",
                      headers=headers).json()["agent"]["active_key_count"] == 2

    ch = alice.owner_challenge("key_revoke", agent_id=alice.agent_id)
    r = client.request("DELETE", f"/api/agents/{alice.agent_id}/keys/{second}", json={
        "owner_wallet": alice.owner,
        "owner_challenge_id": ch["challenge_id"],
        "owner_signature": alice._owner_sign(ch),
        "public_key": "ed25519:unused",
    })
    assert r.status_code == 200

    agent = client.get(f"{LIST_URL}/{alice.agent_id}", headers=headers).json()["agent"]
    assert agent["active_key_count"] == 1
    assert agent["agent_id"] == alice.agent_id
    revoked = [k for k in agent["keys"] if k["key_id"] == second][0]
    assert revoked["status"] == "revoked"


def test_revoked_key_cannot_authenticate(client, alice):
    second_signer = Ed25519Signer.generate()
    second = alice.add_key(second_signer)
    ch = alice.owner_challenge("key_revoke", agent_id=alice.agent_id)
    client.request("DELETE", f"/api/agents/{alice.agent_id}/keys/{second}", json={
        "owner_wallet": alice.owner,
        "owner_challenge_id": ch["challenge_id"],
        "owner_signature": alice._owner_sign(ch),
        "public_key": "ed25519:unused",
    })
    r = client.post(f"/api/agents/{alice.agent_id}/challenge",
                    json={"key_id": second, "aud": AUD_AGENT_API})
    assert r.status_code in (401, 404)


# --------------------------------------------------------------------------- #
# Agent revoke
# --------------------------------------------------------------------------- #
def test_authorized_revoke_succeeds_and_dashboard_shows_revoked(
        client, server_module, alice):
    headers = session_headers(server_module, alice.owner)
    assert alice.revoke_agent().status_code == 200

    agent = client.get(f"{LIST_URL}/{alice.agent_id}", headers=headers).json()["agent"]
    assert agent["status"] == "revoked"
    assert agent["active_key_count"] == 0
    assert agent["active_key_id"] is None
    # History is preserved, not deleted.
    assert agent["agent_id"] == alice.agent_id
    assert len(agent["keys"]) >= 1


def test_revoked_agent_still_appears_in_the_list(client, server_module, alice):
    """The owner must still see it; the UI disables actions instead of hiding."""
    alice.revoke_agent()
    r = client.get(LIST_URL, headers=session_headers(server_module, alice.owner))
    listed = r.json()["agents"]
    assert [a["agent_id"] for a in listed] == [alice.agent_id]
    assert listed[0]["status"] == "revoked"


def test_revoked_agent_cannot_authenticate(client, alice):
    alice.revoke_agent()
    r = client.post(f"/api/agents/{alice.agent_id}/challenge",
                    json={"key_id": alice.key_id, "aud": AUD_AGENT_API})
    assert r.status_code in (401, 403, 404)


def test_revoked_agent_cannot_use_a2a(client, alice, bob):
    alice.authenticate(aud=AUD_AGENT_RELAY)
    alice.revoke_agent()
    payload, _ = alice.build_message(receiver=bob.agent_id)
    r = client.post("/api/agents/messages",
                    json={"payload": payload, "signature": "AA" * 43},
                    headers=alice.auth_headers())
    assert r.status_code in (401, 403)


def test_unauthorized_revoke_fails(client, alice, bob):
    ch = bob.owner_challenge("agent_revoke", agent_id=alice.agent_id)
    r = client.request("DELETE", f"/api/agents/{alice.agent_id}", json={
        "owner_wallet": bob.owner,
        "owner_challenge_id": ch["challenge_id"],
        "owner_signature": bob._owner_sign(ch),
        "public_key": bob.signer.public_key_encoded(),
    })
    assert r.status_code == 401
    assert client.get(f"/api/agents/{alice.agent_id}").json()["status"] == "active"


# --------------------------------------------------------------------------- #
# Secret hygiene
# --------------------------------------------------------------------------- #
def test_dashboard_response_contains_no_key_material_or_tokens(
        client, server_module, alice):
    """Public keys, private keys and JWTs all stay out of the management view."""
    alice.authenticate(aud=AUD_AGENT_API)
    headers = session_headers(server_module, alice.owner)

    for url in (LIST_URL, f"{LIST_URL}/{alice.agent_id}"):
        raw = client.get(url, headers=headers).text
        assert "private" not in raw.lower()
        assert "ed25519:" not in raw            # not even the public key
        assert "public_key" not in raw
        assert alice.signer.public_key_encoded() not in raw
        assert "eyJ" not in raw                 # no JWT of any kind
        assert server_module.TOKEN_SECRET not in raw
        assert "secret" not in raw.lower()


def test_dashboard_response_exposes_no_provider_fields(client, server_module, alice):
    """The LLM provider is not part of the identity and must not appear."""
    raw = client.get(LIST_URL, headers=session_headers(server_module, alice.owner)).text.lower()
    for token in ("api_key", "apikey", "provider_key", "sk-ant", "xai-", "sk-"):
        assert token not in raw


def test_dashboard_endpoint_never_returns_agent_public_keys(client, server_module, alice):
    agent = client.get(f"{LIST_URL}/{alice.agent_id}",
                       headers=session_headers(server_module, alice.owner)).json()["agent"]
    for key in agent["keys"]:
        assert set(key) == {"key_id", "algorithm", "status", "created_at"}


def test_error_paths_do_not_leak_internals(client, server_module, alice):
    r = client.get(f"{LIST_URL}/../../etc/passwd",
                   headers=session_headers(server_module, alice.owner))
    assert r.status_code in (400, 404)
    assert "Traceback" not in r.text


# --------------------------------------------------------------------------- #
# Frontend static analysis — the browser half of the security model
# --------------------------------------------------------------------------- #
def test_frontend_never_generates_or_handles_private_keys():
    js = AGENTS_JS.read_text(encoding="utf-8")
    forbidden = [
        "generateKey", "privateKey", "private_key", "secretKey",
        "signer.sign", "nacl.sign.keyPair", "crypto.subtle.generateKey",
    ]
    for term in forbidden:
        assert term not in js, f"dashboard JS must not reference {term!r}"


def test_frontend_stores_nothing_in_browser_storage():
    """No new localStorage/sessionStorage writes: no key, no agent JWT."""
    js = AGENTS_JS.read_text(encoding="utf-8")
    assert "localStorage.setItem" not in js
    assert "sessionStorage" not in js
    assert "indexedDB" not in js


def test_frontend_never_requests_an_agent_jwt():
    """Agent authentication belongs to the Runtime, not the management UI."""
    js = AGENTS_JS.read_text(encoding="utf-8")
    assert "/authenticate" not in js
    assert "/challenge'" not in js and '"/challenge"' not in js
    assert "verify-jwt" not in js


def test_frontend_is_not_an_a2a_client():
    """M-01 separation: the dashboard must not become a messaging client."""
    js = AGENTS_JS.read_text(encoding="utf-8")
    for term in ("/messages", "inbox", "setInterval", "poll", "EventSource", "WebSocket"):
        assert term not in js, f"dashboard JS must not contain {term!r}"


def test_frontend_uses_only_existing_agent_endpoints():
    """Every /api/agents/... path used by the UI must exist in the router."""
    js = AGENTS_JS.read_text(encoding="utf-8")
    routes = (REPO / "agent" / "routes.py").read_text(encoding="utf-8")
    declared = set(re.findall(r'@router\.\w+\("([^"]+)"', routes))
    # literal path fragments the UI appends to AGENTS_API
    used = set(re.findall(r"AGENTS_API \+ '(/[a-z-]+)'", js))
    for frag in used:
        assert frag in declared, f"{frag} is not an existing agent route"


def test_frontend_escapes_untrusted_values():
    """Agent labels are user-supplied and rendered via innerHTML."""
    js = AGENTS_JS.read_text(encoding="utf-8")
    assert "function escapeHtml" in js
    assert "escapeHtml(agent.label" in js


def test_dashboard_page_loads_the_agents_module_and_section():
    html = DASHBOARD_HTML.read_text(encoding="utf-8")
    assert 'id="agentsSection"' in html
    assert 'id="myAgentsList"' in html
    assert 'id="registerAgentPublicKey"' in html
    assert "/static/aera-agents.js" in html
    assert "AEraAgents.load()" in html
    # the key-custody warning must be on the page
    assert "never upload or paste a private key here" in html.lower()


# --------------------------------------------------------------------------- #
# Python <-> JS canonical JSON parity (the owner signature depends on it)
# --------------------------------------------------------------------------- #
def test_canonical_json_js_python_parity(client, wipe_agent_tables, tmp_path):
    """If the browser serialises the challenge differently from the backend,
    every owner signature the dashboard produces would be invalid."""
    node = shutil.which("node")
    if not node:
        pytest.skip("node not available for Python<->JS byte-identity check")

    a = AgentTestClient(client, eth_priv=ANVIL_KEY_1)
    rec = a.owner_challenge("register")
    payload = {
        "protocol": PROTO_OWNER_CHALLENGE,
        "version": PROTOCOL_VERSION,
        "owner_wallet": rec["owner_wallet"],
        "agent_id": rec.get("agent_id") or "",
        "operation": rec["operation"],
        "challenge_id": rec["challenge_id"],
        "challenge": rec["challenge"],
        "expires_at": rec["expires_at"],
        "domain": OWNER_DOMAIN,
    }
    expected = canonical_json(payload, OWNER_CHALLENGE_KEYS)

    harness = tmp_path / "parity.js"
    harness.write_text(
        "global.window = {};\n"
        f"const src = {json.dumps(AGENTS_JS.read_text(encoding='utf-8'))};\n"
        "eval(src);\n"
        f"const rec = {json.dumps(rec)};\n"
        "process.stdout.write(window.AEraAgents._buildOwnerSignedPayload(rec));\n",
        encoding="utf-8",
    )
    out = subprocess.check_output([node, str(harness)])
    assert out == expected


def test_js_canonical_json_sorts_keys_and_rejects_floats(tmp_path):
    node = shutil.which("node")
    if not node:
        pytest.skip("node not available")
    harness = tmp_path / "canon.js"
    harness.write_text(
        "global.window = {};\n"
        f"eval({json.dumps(AGENTS_JS.read_text(encoding='utf-8'))});\n"
        "const c = window.AEraAgents._canonicalJson;\n"
        "const out = [];\n"
        "out.push(c({b: 'B', a: 'A'}));\n"
        "try { c({x: 1.5}); out.push('NO-THROW'); } catch (e) { out.push('throws'); }\n"
        "process.stdout.write(JSON.stringify(out));\n",
        encoding="utf-8",
    )
    result = json.loads(subprocess.check_output([node, str(harness)]))
    assert result[0] == '{"a":"A","b":"B"}'
    assert result[1] == "throws"


# --------------------------------------------------------------------------- #
# Registration UX — where the public key comes from
#
# These guard a documentation surface. The risk they address is a UX one that
# becomes a security one: if the dashboard explains key generation badly, users
# invent their own procedure and may paste private key material.
# --------------------------------------------------------------------------- #
def _keygen_snippet() -> str:
    """Extract the keygen command exactly as it is shown to the user."""
    html = DASHBOARD_HTML.read_text(encoding="utf-8")
    m = re.search(r'<pre id="agentKeygenSnippet"[^>]*>(.*?)</pre>', html, re.S)
    assert m, "keygen snippet block not found in the dashboard"
    import html as _html
    return _html.unescape(m.group(1))


def test_public_key_field_explains_where_the_key_comes_from():
    html = DASHBOARD_HTML.read_text(encoding="utf-8")
    assert "This key is generated by your <strong>Agent Runtime</strong>." in html
    assert "Your Agent Runtime keeps the private key locally." in html
    assert "Only the public key is registered with AEra." in html


def test_help_affordance_and_all_six_steps_are_present():
    html = DASHBOARD_HTML.read_text(encoding="utf-8")
    assert "How do I get a public key?" in html
    assert 'id="agentKeyHelp"' in html
    for step in [
        "Install or start your AEra Agent Runtime.",
        "The runtime generates an Ed25519 keypair.",
        "must never be uploaded",
        "Copy the generated public key.",
        "Paste the public key into the field above.",
        "Sign the owner challenge with your wallet.",
    ]:
        assert step in html, step


def test_help_shows_the_trust_boundary_and_provider_independence():
    html = DASHBOARD_HTML.read_text(encoding="utf-8")
    assert "YOUR MACHINE" in html and "Agent Runtime" in html
    assert "Private key stays here" in html
    assert "Agent identity ≠ LLM provider." in html
    # the claim that swapping models keeps the identity must be stated
    assert "agent_id</code>, <code>key_id</code> and keys stay exactly the same" in html


def test_help_does_not_promise_a_runtime_that_does_not_exist():
    """There is no packaged runtime or CLI installer. Say so."""
    html = DASHBOARD_HTML.read_text(encoding="utf-8")
    assert "AEra does not ship a packaged Agent Runtime yet." in html
    assert "no download and no CLI installer" in html


def test_help_points_at_real_files_that_exist():
    html = DASHBOARD_HTML.read_text(encoding="utf-8")
    for referenced in ("docs/AGENT_IDENTITY.md",
                       "aera-agent-security-lab/src/identity/aera_client.py"):
        assert referenced in html, f"{referenced} not referenced"
        assert (REPO / referenced).exists(), f"{referenced} referenced but missing"


def test_keygen_snippet_is_documentation_not_browser_code():
    """The snippet must never be executed by the page."""
    js = AGENTS_JS.read_text(encoding="utf-8")
    assert "eval(" not in js
    assert "new Function" not in js
    assert "innerHTML = pre" not in js
    # the module only ever reads the snippet's text in order to copy it
    assert "copyKeygenSnippet" in js
    assert "pre.textContent" in js


def test_keygen_snippet_keeps_the_private_key_local_and_prints_only_the_public_key():
    snippet = _keygen_snippet()
    # it must never post, upload or transmit anything
    for forbidden in ("requests.", "urllib", "http", "curl", "upload", "POST", "api"):
        assert forbidden not in snippet, f"snippet must not contain {forbidden!r}"
    # exactly one thing is printed, and it is the public key
    assert snippet.count("print(") == 1
    assert "base64.urlsafe_b64encode(raw_pub)" in snippet
    assert "print('ed25519:' + base64.urlsafe_b64encode(raw_pub)" in snippet
    # the private key is written locally with restrictive permissions
    assert "chmod(0o600)" in snippet


def test_keygen_snippet_actually_runs_and_produces_an_acceptable_key(tmp_path):
    """Executes the command shown in the UI verbatim and feeds the result to the
    production validator. If the documented procedure ever drifts from what the
    Agent Identity Layer accepts, this fails."""
    import subprocess as sp
    import sys as _sys

    from agent.crypto import decode_public_key

    snippet = _keygen_snippet()
    m = re.search(r'python -c "(.*)"\s*$', snippet, re.S)
    assert m, "snippet is not the documented `python -c` form"
    code = m.group(1)

    out = sp.check_output([_sys.executable, "-c", code], cwd=tmp_path, text=True).strip()
    lines = [l for l in out.splitlines() if l.strip()]
    assert len(lines) == 1, f"snippet printed more than the public key: {lines}"
    public_key = lines[0]

    assert public_key.startswith("ed25519:")
    assert len(decode_public_key(public_key)) == 32     # production validator

    # the private key stayed on disk, locked down, and is NOT what was printed
    priv = tmp_path / "agent_private_key.bin"
    assert priv.exists() and priv.stat().st_size == 32
    assert oct(priv.stat().st_mode)[-3:] == "600"
    assert priv.read_bytes().hex() not in out


def test_key_generated_by_the_documented_snippet_registers_successfully(
        client, wipe_agent_tables, server_module, tmp_path):
    """End-to-end: the documented procedure yields a key the API accepts."""
    import subprocess as sp
    import sys as _sys

    m = re.search(r'python -c "(.*)"\s*$', _keygen_snippet(), re.S)
    public_key = sp.check_output([_sys.executable, "-c", m.group(1)],
                                 cwd=tmp_path, text=True).strip()

    a = AgentTestClient(client, eth_priv=ANVIL_KEY_1)
    ch = a.owner_challenge("register")
    r = client.post("/api/agents/register", json={
        "owner_wallet": a.owner,
        "owner_challenge_id": ch["challenge_id"],
        "owner_signature": a._owner_sign(ch),
        "public_key": public_key,          # <- straight from the UI's instructions
        "label": "Runtime Agent",
    })
    assert r.status_code == 200, r.text

    listed = client.get(LIST_URL, headers=session_headers(server_module, a.owner)).json()
    assert listed["agents"][0]["label"] == "Runtime Agent"


def test_ux_change_did_not_introduce_key_generation_into_the_dashboard():
    """The whole point: better explanation, same cryptographic architecture."""
    js = AGENTS_JS.read_text(encoding="utf-8")
    for term in ("Ed25519PrivateKey", "generateKey", "privateKey",
                 "crypto.subtle", "nacl", "tweetnacl"):
        assert term not in js, f"dashboard JS must not reference {term!r}"
