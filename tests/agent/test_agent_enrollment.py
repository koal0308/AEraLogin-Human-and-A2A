"""Agent enrollment ("runtime pairing") — security and functional tests.

Every negative test here targets ONE control and would pass (i.e. the attack
would succeed) if that control were removed. The control is named in the
docstring so a failing test points straight at what regressed.
"""
from __future__ import annotations

import json
import pathlib
import re

import pytest

from agent import enrollment as enr
from agent.crypto import Ed25519Signer, b64u_encode, public_key_fingerprint

from tests.agent.testclient import ANVIL_KEY_1, ANVIL_KEY_2, AgentTestClient

REPO = pathlib.Path(__file__).resolve().parents[2]
ENROLL_JS = REPO / "aera-agent-enroll.js"
AGENTS_JS = REPO / "aera-agents.js"
DASHBOARD_HTML = REPO / "user-dashboard.html"

DASH = "/api/dashboard/agents/enrollments"
API = "/api/agents/enrollments"


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def session(server_module, wallet):
    return {"Authorization": f"Bearer {server_module.generate_dashboard_jwt(wallet)}"}


@pytest.fixture()
def owner(client, wipe_agent_tables):
    return AgentTestClient(client, eth_priv=ANVIL_KEY_1)


@pytest.fixture()
def other(client, wipe_agent_tables):
    return AgentTestClient(client, eth_priv=ANVIL_KEY_2)


def create(client, server_module, who, label="Pairing Agent", caps=None):
    r = client.post(DASH, headers=session(server_module, who.owner),
                    json={"label": label, "capabilities": caps})
    assert r.status_code == 200, r.text
    return r.json()["enrollment"]


def pop(signer, eid, public_key=None):
    pk = public_key or signer.public_key_encoded()
    return b64u_encode(signer.sign(enr.build_pop_payload(eid, pk)))


def claim(client, code, signer, *, public_key=None, sig=None):
    eid = enr.parse_code(code)[0]
    pk = public_key or signer.public_key_encoded()
    return client.post(f"{API}/claim", json={
        "enrollment_code": code, "public_key": pk,
        "signature": sig if sig is not None else pop(signer, eid, pk)})


def approve(client, who, eid, *, binding=None):
    ch = who.owner_challenge("register",
                             agent_id=binding if binding is not None
                             else enr.challenge_binding(eid))
    return client.post(f"{API}/{eid}/complete", json={
        "owner_wallet": who.owner, "owner_challenge_id": ch["challenge_id"],
        "owner_signature": who._owner_sign(ch)})


def status(client, code):
    return client.post(f"{API}/status", json={"enrollment_code": code})


def full_pairing(client, server_module, who, signer=None):
    signer = signer or Ed25519Signer.generate()
    e = create(client, server_module, who)
    assert claim(client, e["enrollment_code"], signer).status_code == 200
    r = approve(client, who, e["enrollment_id"])
    assert r.status_code == 200, r.text
    return e, signer, r.json()


# =========================================================================== #
# Happy path
# =========================================================================== #
def test_full_pairing_creates_a_working_agent(client, server_module, owner):
    e, signer, out = full_pairing(client, server_module, owner)
    assert out["agent_id"].startswith("did:aera:agent:")
    assert out["key_id"].startswith("aera-key-")

    st = status(client, e["enrollment_code"]).json()
    assert st["status"] == "completed"
    assert (st["agent_id"], st["key_id"]) == (out["agent_id"], out["key_id"])

    # The paired agent authenticates with the RUNTIME's key via the unchanged flow.
    a = AgentTestClient(client, eth_priv=ANVIL_KEY_1)
    a.signer, a.agent_id, a.key_id = signer, out["agent_id"], out["key_id"]
    assert a.authenticate().status_code == 200  # same Agent JWT flow as manual agents

    listed = client.get("/api/dashboard/agents",
                        headers=session(server_module, owner.owner)).json()
    assert listed["agents"][0]["label"] == "Pairing Agent"


def test_paired_agent_is_identical_to_a_manually_registered_one(client, server_module, owner):
    _, _, out = full_pairing(client, server_module, owner)
    manual = AgentTestClient(client, eth_priv=ANVIL_KEY_1)
    manual.register()
    detail = client.get(f"/api/agents/{out['agent_id']}").json()
    detail_m = client.get(f"/api/agents/{manual.agent_id}").json()
    assert set(detail) == set(detail_m)
    agents = {a["agent_id"]: a for a in client.get(
        "/api/dashboard/agents", headers=session(server_module, owner.owner)).json()["agents"]}
    assert agents[out["agent_id"]]["capabilities"] == agents[manual.agent_id]["capabilities"]
    assert set(agents[out["agent_id"]]) == set(agents[manual.agent_id])


def test_requested_capabilities_are_normalised(client, server_module, owner):
    e = create(client, server_module, owner,
               caps=["agent.authenticate", "root.everything"])
    assert e["capabilities"] == ["agent.authenticate"]


def test_fingerprint_is_shown_to_owner_and_matches_runtime_key(client, server_module, owner):
    signer = Ed25519Signer.generate()
    e = create(client, server_module, owner)
    r = claim(client, e["enrollment_code"], signer)
    assert r.json()["key_fingerprint"] == public_key_fingerprint(signer.public_key_encoded())
    view = client.get(f"{DASH}/{e['enrollment_id']}",
                      headers=session(server_module, owner.owner)).json()["enrollment"]
    assert view["status"] == "key_submitted"
    assert view["key_fingerprint"] == public_key_fingerprint(signer.public_key_encoded())


# =========================================================================== #
# Secret handling
# =========================================================================== #
def test_enrollment_secret_is_stored_only_as_hash(client, server_module, owner):
    """Control: secret_hash. Removing hashing would put a live secret in the DB."""
    e = create(client, server_module, owner)
    secret = e["enrollment_code"].split(".", 1)[1]
    from agent import repository
    conn = repository.get_connection()
    try:
        dump = "\n".join(str(tuple(r)) for r in conn.execute("SELECT * FROM agent_enrollments"))
        audit = "\n".join(str(tuple(r)) for r in conn.execute("SELECT * FROM agent_audit_log"))
    finally:
        conn.close()
    assert secret not in dump
    assert secret not in audit


def test_code_is_returned_once_never_by_views(client, server_module, owner):
    e = create(client, server_module, owner)
    secret = e["enrollment_code"].split(".", 1)[1]
    view = client.get(f"{DASH}/{e['enrollment_id']}",
                      headers=session(server_module, owner.owner))
    assert secret not in view.text and "secret_hash" not in view.text
    assert secret not in status(client, e["enrollment_code"]).text


def test_wrong_secret_is_rejected_like_unknown_id(client, server_module, owner):
    """Control: constant-time secret check + uniform error (no id oracle)."""
    e = create(client, server_module, owner)
    eid = e["enrollment_id"]
    wrong = f"aera-enroll-{eid}.{'A' * 32}"
    unknown = f"aera-enroll-{'0' * 16}.{'A' * 32}"
    signer = Ed25519Signer.generate()
    r1, r2 = claim(client, wrong, signer), claim(client, unknown, signer)
    assert r1.status_code == r2.status_code == 404
    assert r1.json() == r2.json()
    assert status(client, wrong).json() == status(client, unknown).json()


@pytest.mark.parametrize("bad", ["", "aera-enroll-xyz", "aera-enroll-" + "0" * 16,
                                 "../../etc", "aera-enroll-" + "0" * 16 + "." + "A" * 31])
def test_malformed_codes_are_rejected(client, owner, bad):
    r = client.post(f"{API}/claim", json={
        "enrollment_code": bad,
        "public_key": Ed25519Signer.generate().public_key_encoded(),
        "signature": "x"})
    assert r.status_code == 400
    assert r.json()["detail"]["agent_error"] == "invalid_enrollment_code"


# =========================================================================== #
# Proof of possession
# =========================================================================== #
def test_claim_without_valid_pop_is_rejected(client, server_module, owner):
    """Control: PoP signature. Without it, anyone holding the code could
    enroll a public key they do not control."""
    e = create(client, server_module, owner)
    victim = Ed25519Signer.generate()
    attacker = Ed25519Signer.generate()
    eid = e["enrollment_id"]
    # attacker signs, but submits the victim's public key
    r = claim(client, e["enrollment_code"], attacker,
              public_key=victim.public_key_encoded(),
              sig=pop(attacker, eid, victim.public_key_encoded()))
    assert r.status_code == 401
    assert r.json()["detail"]["agent_error"] == "invalid_proof_of_possession"


def test_pop_is_bound_to_the_enrollment_id(client, server_module, owner):
    """Control: enrollment_id inside the PoP payload (no cross-enrollment replay)."""
    e1 = create(client, server_module, owner)
    e2 = create(client, server_module, owner)
    s = Ed25519Signer.generate()
    r = claim(client, e2["enrollment_code"], s, sig=pop(s, e1["enrollment_id"]))
    assert r.status_code == 401


def test_pop_uses_its_own_protocol_domain():
    """An agent-auth or message signature must never double as a PoP."""
    payload = enr.build_pop_payload("0" * 16, "ed25519:" + "A" * 43)
    assert b'"protocol":"aera-agent-enroll"' in payload
    assert b"aera-agent-auth" not in payload and b"aera-agent-message" not in payload


def test_invalid_public_key_is_rejected(client, server_module, owner):
    e = create(client, server_module, owner)
    r = client.post(f"{API}/claim", json={"enrollment_code": e["enrollment_code"],
                                          "public_key": "ed25519:short", "signature": "x"})
    assert r.status_code == 400


def test_already_registered_key_cannot_be_enrolled(client, server_module, owner):
    """Control: one active key -> one agent."""
    _, signer, _ = full_pairing(client, server_module, owner)
    e = create(client, server_module, owner)
    r = claim(client, e["enrollment_code"], signer)
    assert r.status_code == 409
    assert r.json()["detail"]["agent_error"] == "key_already_registered"


# =========================================================================== #
# Single-use / state machine
# =========================================================================== #
def test_enrollment_can_be_claimed_only_once(client, server_module, owner):
    """Control: status=pending guard. Otherwise a second runtime (attacker)
    could overwrite the key after the owner saw the first fingerprint."""
    e = create(client, server_module, owner)
    assert claim(client, e["enrollment_code"], Ed25519Signer.generate()).status_code == 200
    r = claim(client, e["enrollment_code"], Ed25519Signer.generate())
    assert r.status_code == 409


def test_enrollment_can_be_completed_only_once(client, server_module, owner):
    e, _, _ = full_pairing(client, server_module, owner)
    r = approve(client, owner, e["enrollment_id"])
    assert r.status_code == 409
    agents = client.get("/api/dashboard/agents",
                        headers=session(server_module, owner.owner)).json()["agents"]
    assert len(agents) == 1


def test_unclaimed_enrollment_cannot_be_completed(client, server_module, owner):
    e = create(client, server_module, owner)
    r = approve(client, owner, e["enrollment_id"])
    assert r.status_code == 409
    assert r.json()["detail"]["agent_error"] == "enrollment_not_claimed"


def test_expired_enrollment_cannot_be_claimed_or_completed(client, server_module, owner):
    """Control: expires_at check."""
    e = create(client, server_module, owner)
    signer = Ed25519Signer.generate()
    assert claim(client, e["enrollment_code"], signer).status_code == 200
    from agent import repository
    conn = repository.get_connection()
    conn.execute("UPDATE agent_enrollments SET expires_at='2000-01-01T00:00:00Z'")
    conn.commit()
    conn.close()
    assert approve(client, owner, e["enrollment_id"]).status_code == 410
    assert status(client, e["enrollment_code"]).json()["status"] == "expired"
    e2 = create(client, server_module, owner)
    conn = repository.get_connection()
    conn.execute("UPDATE agent_enrollments SET expires_at='2000-01-01T00:00:00Z' "
                 "WHERE enrollment_id=?", (e2["enrollment_id"],))
    conn.commit()
    conn.close()
    assert claim(client, e2["enrollment_code"], Ed25519Signer.generate()).status_code == 410


def test_cancelled_enrollment_is_dead(client, server_module, owner):
    e = create(client, server_module, owner)
    r = client.delete(f"{DASH}/{e['enrollment_id']}", headers=session(server_module, owner.owner))
    assert r.status_code == 200
    assert claim(client, e["enrollment_code"], Ed25519Signer.generate()).status_code == 409
    assert status(client, e["enrollment_code"]).json()["status"] == "cancelled"


def test_open_enrollments_per_owner_are_capped(client, server_module, owner):
    for i in range(5):
        create(client, server_module, owner, label=f"Agent {i}")
    r = client.post(DASH, headers=session(server_module, owner.owner),
                    json={"label": "one too many"})
    assert r.status_code == 429


# =========================================================================== #
# Owner binding
# =========================================================================== #
def test_creation_requires_a_dashboard_session(client, owner):
    assert client.post(DASH, json={"label": "x" * 5}).status_code == 401
    import jwt as _jwt
    forged = _jwt.encode({"address": owner.owner}, "attacker", algorithm="HS256")
    assert client.post(DASH, json={"label": "abcde"},
                       headers={"Authorization": f"Bearer {forged}"}).status_code == 401


def test_owner_is_taken_from_session_not_body(client, server_module, owner, other):
    r = client.post(DASH, headers=session(server_module, other.owner),
                    json={"label": "Sneaky", "owner_wallet": owner.owner})
    eid = r.json()["enrollment"]["enrollment_id"]
    # it belongs to `other`, not to the wallet named in the body
    assert client.get(f"{DASH}/{eid}", headers=session(server_module, owner.owner)).status_code == 404
    assert client.get(f"{DASH}/{eid}", headers=session(server_module, other.owner)).status_code == 200


def test_other_owner_cannot_view_or_cancel(client, server_module, owner, other):
    e = create(client, server_module, owner)
    h = session(server_module, other.owner)
    foreign = client.get(f"{DASH}/{e['enrollment_id']}", headers=h)
    missing = client.get(f"{DASH}/{'0' * 16}", headers=h)
    assert foreign.status_code == missing.status_code == 404
    assert foreign.json() == missing.json()
    assert client.delete(f"{DASH}/{e['enrollment_id']}", headers=h).status_code == 404


def test_other_owner_cannot_complete_even_with_own_valid_signature(client, server_module,
                                                                  owner, other):
    """Control: enrollment.owner_wallet == signing wallet."""
    e = create(client, server_module, owner)
    claim(client, e["enrollment_code"], Ed25519Signer.generate())
    r = approve(client, other, e["enrollment_id"])
    assert r.status_code == 404
    assert client.get("/api/dashboard/agents",
                      headers=session(server_module, other.owner)).json()["agents"] == []


def test_completion_without_owner_signature_fails(client, server_module, owner):
    e = create(client, server_module, owner)
    claim(client, e["enrollment_code"], Ed25519Signer.generate())
    ch = owner.owner_challenge("register", agent_id=enr.challenge_binding(e["enrollment_id"]))
    r = client.post(f"{API}/{e['enrollment_id']}/complete", json={
        "owner_wallet": owner.owner, "owner_challenge_id": ch["challenge_id"],
        "owner_signature": "0x" + "00" * 65})
    assert r.status_code == 401


def test_plain_register_challenge_cannot_complete_an_enrollment(client, server_module, owner):
    """Control: challenge binding agent_id='enrollment:<id>'."""
    e = create(client, server_module, owner)
    claim(client, e["enrollment_code"], Ed25519Signer.generate())
    r = approve(client, owner, e["enrollment_id"], binding="")
    assert r.status_code == 401


def test_challenge_for_one_enrollment_cannot_complete_another(client, server_module, owner):
    e1 = create(client, server_module, owner)
    e2 = create(client, server_module, owner)
    claim(client, e2["enrollment_code"], Ed25519Signer.generate())
    ch = owner.owner_challenge("register", agent_id=enr.challenge_binding(e1["enrollment_id"]))
    r = client.post(f"{API}/{e2['enrollment_id']}/complete", json={
        "owner_wallet": owner.owner, "owner_challenge_id": ch["challenge_id"],
        "owner_signature": owner._owner_sign(ch)})
    assert r.status_code == 401


def test_enrollment_challenge_cannot_be_used_on_plain_register(client, server_module, owner):
    """The reverse direction: /register still requires agent_id NULL."""
    e = create(client, server_module, owner)
    ch = owner.owner_challenge("register", agent_id=enr.challenge_binding(e["enrollment_id"]))
    r = client.post("/api/agents/register", json={
        "owner_wallet": owner.owner, "owner_challenge_id": ch["challenge_id"],
        "owner_signature": owner._owner_sign(ch),
        "public_key": Ed25519Signer.generate().public_key_encoded(), "label": "x"})
    assert r.status_code == 401


# =========================================================================== #
# Compatibility
# =========================================================================== #
def test_manual_registration_still_works(client, owner):
    owner.register()
    assert owner.agent_id and owner.authenticate().status_code == 200


def test_paired_agent_supports_rotation_and_revocation(client, server_module, owner):
    _, signer, out = full_pairing(client, server_module, owner)
    a = AgentTestClient(client, eth_priv=ANVIL_KEY_1)
    a.signer, a.agent_id, a.key_id = signer, out["agent_id"], out["key_id"]
    new = Ed25519Signer.generate()
    new_kid = a.rotate_key(new, revoke=out["key_id"])
    assert new_kid != out["key_id"]
    a.signer, a.key_id = new, new_kid
    assert a.authenticate().status_code == 200
    assert a.revoke_agent().status_code == 200
    detail = client.get(f"/api/agents/{out['agent_id']}").json()
    assert detail["status"] == "revoked"


# =========================================================================== #
# Runtime `enroll` command, end to end against the real app
# =========================================================================== #
def test_runtime_enroll_generates_key_locally_and_stores_identity(
        client, server_module, owner, tmp_path):
    from agent_runtime.config import identity_path_for, load_identity_file
    from agent_runtime.enroll import enroll
    from agent_runtime.keystore import LocalKeyStore

    e = create(client, server_module, owner)
    lines: list[str] = []
    approved = {"done": False}

    def owner_approves_while_runtime_waits(_seconds):
        if not approved["done"]:
            assert approve(client, owner, e["enrollment_id"]).status_code == 200
            approved["done"] = True

    key_path = tmp_path / "agent_key.json"
    out = enroll(code=e["enrollment_code"], base_url="http://testserver",
                 key_path=key_path, http=client, out=lines.append,
                 sleep=owner_approves_while_runtime_waits, timeout=30)

    # identity file: public ids only, 0600
    ident = identity_path_for(key_path)
    assert load_identity_file(ident) == (out["agent_id"], out["key_id"])
    assert oct(ident.stat().st_mode)[-3:] == "600"
    assert oct(key_path.stat().st_mode)[-3:] == "600"

    # the key AEra registered is the one on disk; the private part never printed
    store = LocalKeyStore(key_path).load()
    assert out["fingerprint"] == public_key_fingerprint(store.public_key)
    raw_priv = json.loads(key_path.read_text())["key"]
    printed = "\n".join(lines)
    assert raw_priv not in printed
    assert raw_priv not in ident.read_text()
    assert out["fingerprint"] in printed

    # the runtime config picks the identity up with no env vars
    import os
    from agent_runtime.config import RuntimeConfig
    old = {k: os.environ.pop(k, None) for k in ("AERA_RUNTIME_AGENT_ID", "AERA_RUNTIME_KEY_ID")}
    os.environ["AERA_RUNTIME_KEY_PATH"] = str(key_path)
    try:
        cfg = RuntimeConfig.from_env()
        assert (cfg.agent_id, cfg.key_id) == (out["agent_id"], out["key_id"])
    finally:
        os.environ.pop("AERA_RUNTIME_KEY_PATH", None)
        for k, v in old.items():
            if v is not None:
                os.environ[k] = v


def test_runtime_enroll_refuses_to_overwrite_an_existing_key(tmp_path, client):
    from agent_runtime.enroll import EnrollError, enroll
    from agent_runtime.keystore import LocalKeyStore

    key_path = tmp_path / "agent_key.json"
    LocalKeyStore(key_path).create()
    before = key_path.read_bytes()
    with pytest.raises(EnrollError):
        enroll(code="aera-enroll-" + "0" * 16 + "." + "A" * 32, base_url="http://testserver",
               key_path=key_path, http=client, out=lambda _l: None)
    assert key_path.read_bytes() == before


def test_runtime_enroll_refuses_when_already_bound(tmp_path, client):
    from agent_runtime.config import identity_path_for
    from agent_runtime.enroll import EnrollError, enroll

    key_path = tmp_path / "agent_key.json"
    identity_path_for(key_path).write_text('{"agent_id":"a","key_id":"k"}')
    with pytest.raises(EnrollError):
        enroll(code="aera-enroll-" + "0" * 16 + "." + "A" * 32, base_url="http://testserver",
               key_path=key_path, http=client, out=lambda _l: None)
    assert not key_path.exists()


def test_env_identity_still_wins_over_identity_file(tmp_path, monkeypatch):
    from agent_runtime.config import RuntimeConfig, identity_path_for

    key_path = tmp_path / "agent_key.json"
    identity_path_for(key_path).write_text('{"agent_id":"file-a","key_id":"file-k"}')
    monkeypatch.setenv("AERA_RUNTIME_KEY_PATH", str(key_path))
    monkeypatch.setenv("AERA_RUNTIME_AGENT_ID", "env-a")
    monkeypatch.setenv("AERA_RUNTIME_KEY_ID", "env-k")
    cfg = RuntimeConfig.from_env()
    assert (cfg.agent_id, cfg.key_id) == ("env-a", "env-k")


# =========================================================================== #
# Frontend static analysis — the browser never touches key material
# =========================================================================== #
def test_enroll_js_never_handles_key_material():
    js = ENROLL_JS.read_text(encoding="utf-8")
    for term in ("generateKey", "privateKey", "private_key", "secretKey", "crypto.subtle",
                 "nacl", "Ed25519PrivateKey", "exportKey", "importKey"):
        assert term not in js, term


def test_enroll_js_persists_nothing():
    js = ENROLL_JS.read_text(encoding="utf-8")
    for term in ("localStorage", "sessionStorage", "indexedDB", "document.cookie",
                 "history.pushState", "history.replaceState", "location.hash",
                 "console.log", "console.info", "console.debug", "plausible", "gtag"):
        assert term not in js, term


def test_enroll_js_is_not_an_agent_or_a2a_client():
    js = ENROLL_JS.read_text(encoding="utf-8")
    for term in ("/authenticate", "verify-jwt", "/messages", "/api/a2a",
                 "EventSource", "WebSocket", "setInterval"):
        assert term not in js, term


def test_enroll_js_only_talks_to_enrollment_endpoints():
    js = ENROLL_JS.read_text(encoding="utf-8")
    urls = set(re.findall(r"'(/api/[^']+)'", js))
    assert urls == {"/api/dashboard/agents/enrollments", "/api/agents/enrollments"}
    routes = (REPO / "agent" / "routes.py").read_text(encoding="utf-8")
    assert '@router.post("/enrollments/{enrollment_id}/complete"' in routes
    server = (REPO / "server.py").read_text(encoding="utf-8")
    assert '@app.post("/api/dashboard/agents/enrollments")' in server


def test_enroll_js_reuses_the_existing_owner_signing_flow():
    js = ENROLL_JS.read_text(encoding="utf-8")
    assert "_authorizeOwnerOperation('register', 'enrollment:' + id)" in js
    assert "personal_sign" not in js and "robustWalletSign" not in js
    assert "_authorizeOwnerOperation: authorizeOwnerOperation" in AGENTS_JS.read_text()


def test_enroll_js_escapes_rendered_values():
    js = ENROLL_JS.read_text(encoding="utf-8")
    assert "esc(view.key_fingerprint)" in js
    assert "esc(commandText())" in js
    assert "esc(agentId" in js


def test_dashboard_offers_pairing_first_and_manual_as_advanced():
    html = DASHBOARD_HTML.read_text(encoding="utf-8")
    assert "/static/aera-agent-enroll.js" in html
    assert "AEraAgentEnroll.start()" in html
    assert 'id="agentEnrollPanel"' in html
    pairing = html.index("AEraAgentEnroll.start()")
    advanced = html.index('id="agentManualRegister"')
    manual_field = html.index('id="registerAgentPublicKey"')
    assert pairing < advanced < manual_field
    assert "Advanced / Developer setup" in html
