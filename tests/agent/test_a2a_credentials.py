"""External A2A peer credentials -- tests organised by trust boundary.

Each test states the property it defends, not the line it covers. A test that
merely re-executes the implementation proves nothing; these are written so that
breaking the property breaks the test.

Boundaries under test:
  A. Credential format and secrecy
  B. Verification (who is calling)
  C. Authorisation (what may they do) -- deliberately separate from B
  D. Revocation and expiry
  E. Trust-level separation (AEra JWT != peer credential)
  F. Enumeration and information leakage
  G. Policy (optional vs required)
  H. Rate limiting
  I. Issuance authority (owner only)
  J. The Agent Identity Layer is untouched
"""
from __future__ import annotations

import ast
import inspect
import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from a2a_gateway import auth as gw_auth
from a2a_gateway import credentials as gw_cred
from a2a_gateway import peer as gw_peer
from a2a_gateway.constants import (
    CREDENTIAL_AUDIENCE,
    CREDENTIAL_ISSUER,
    CREDENTIAL_PREFIX,
    GATEWAY_PATH,
    SKILL_COMMUNICATE,
    SKILL_READ_PROFILE,
    WELL_KNOWN_PATH,
)

GATEWAY_DIR = Path(__file__).resolve().parents[2] / "a2a_gateway"


# --------------------------------------------------------------------------- #
# fixtures
# --------------------------------------------------------------------------- #
@pytest.fixture
def store():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    gw_cred.init_schema(conn)
    conn.execute("CREATE TABLE agents (agent_id TEXT, owner_wallet TEXT)")
    conn.execute("INSERT INTO agents VALUES ('agent-a', '0xOwner')")
    conn.execute("INSERT INTO agents VALUES ('agent-b', '0xOwner')")
    conn.execute("INSERT INTO agents VALUES ('agent-x', '0xStranger')")
    conn.commit()
    yield conn
    conn.close()


@pytest.fixture
def issued(store):
    return gw_cred.issue_credential(store, owner_address="0xowner")


@pytest.fixture(autouse=True)
def _default_policy(monkeypatch):
    """Every test states its own policy; default is the shipped one."""
    monkeypatch.delenv("AERA_A2A_AUTH_POLICY", raising=False)


def _headers(credential):
    return {"authorization": f"Bearer {credential}"}


def rpc(target="agent-a", skill=SKILL_READ_PROFILE, mid="m-1"):
    return {
        "jsonrpc": "2.0", "id": 1, "method": "message/send",
        "params": {"message": {
            "messageId": mid, "role": "user",
            "parts": [{"kind": "text", "text": "hi"}],
            "metadata": {"aera_target_agent": target, "skillId": skill},
        }},
    }


# =========================================================================== #
# A. Credential format and secrecy
# =========================================================================== #
def test_01_plaintext_is_never_stored(store, issued):
    """The database must not contain the credential in any recoverable form."""
    blob = json.dumps([dict(r) for r in store.execute(
        f"SELECT * FROM {gw_cred.TABLE}")])
    secret = issued.plaintext.rsplit("_", 1)[1]
    assert issued.plaintext not in blob
    assert secret not in blob
    # What IS stored must be the hash, and must actually match.
    row = store.execute(f"SELECT secret_hash FROM {gw_cred.TABLE}").fetchone()
    assert row["secret_hash"] == gw_cred.hash_secret(secret)


def test_02_secret_has_256_bits_of_entropy(store):
    """A guessable credential is not a credential."""
    secrets_seen = set()
    for _ in range(25):
        issued = gw_cred.issue_credential(store, owner_address="0xowner")
        cred_id, secret = gw_cred.parse_credential(issued.plaintext)
        assert len(secret) == 64, "expected 32 bytes hex-encoded = 256 bits"
        secrets_seen.add(secret)
    assert len(secrets_seen) == 25, "secrets repeated -- generator is not random"


def test_03_credential_is_greppable(issued):
    """A leaked credential must be findable by a secret scanner."""
    assert issued.plaintext.startswith(CREDENTIAL_PREFIX)


def test_04_record_repr_never_exposes_a_secret(store, issued):
    """Tracebacks and logs print reprs. They must be safe."""
    record = gw_cred.verify_credential(store, issued.plaintext)
    assert issued.plaintext not in repr(record)
    assert not hasattr(record, "secret_hash")
    assert "secret" not in repr(record).lower()


def test_05_issue_response_warns_that_it_is_shown_once(issued):
    payload = issued.to_issue_response()
    assert payload["credential"] == issued.plaintext
    assert "only time" in payload["warning"]
    # to_owner_dict is the LISTING shape and must never carry the plaintext.
    assert "credential" not in issued.record.to_owner_dict()


# =========================================================================== #
# B. Verification
# =========================================================================== #
def test_06_valid_credential_authenticates(store, issued):
    record = gw_cred.verify_credential(store, issued.plaintext)
    assert record.peer_id == issued.record.peer_id
    assert record.cred_id == issued.record.cred_id


def test_07_wrong_secret_is_refused(store, issued):
    """Same cred_id, different secret. The id alone must prove nothing."""
    cred_id, _ = gw_cred.parse_credential(issued.plaintext)
    forged = gw_cred.build_credential(cred_id, "a" * 64)
    with pytest.raises(gw_cred.CredentialError):
        gw_cred.verify_credential(store, forged)


def test_08_unknown_credential_is_refused(store):
    with pytest.raises(gw_cred.CredentialError):
        gw_cred.verify_credential(store, gw_cred.build_credential("b" * 32, "c" * 64))


@pytest.mark.parametrize("bad", [
    "", "   ", "not-a-credential", "aera_a2a_", "aera_a2a_xyz",
    "aera_a2a_" + "b" * 32, "bearer aera_a2a_x_y", None, 12345,
    "aera_a2a_" + "b" * 32 + "_short",
    "aera_a2a_" + "Z" * 32 + "_" + "c" * 64,      # non-hex id
    "aera_a2a_" + "b" * 32 + "_" + "Z" * 64,      # non-hex secret
])
def test_09_malformed_credentials_are_refused(store, bad):
    """No malformed input may be treated as valid, or crash the parser."""
    with pytest.raises(gw_cred.CredentialError):
        gw_cred.verify_credential(store, bad)


def test_10_verification_uses_constant_time_comparison():
    """A byte-wise early exit leaks the secret through response timing."""
    source = inspect.getsource(gw_cred.verify_credential)
    assert "compare_digest" in source
    assert "stored_hash ==" not in source


class _SpyConn:
    """Records every query. `sqlite3.Connection.execute` is read-only, so the
    only way to observe database access is to wrap the connection."""

    def __init__(self, conn):
        self._conn = conn
        self.queries: list[str] = []

    def execute(self, sql, *args, **kwargs):
        self.queries.append(sql)
        return self._conn.execute(sql, *args, **kwargs)

    def commit(self):
        return self._conn.commit()


def test_11_malformed_credentials_never_touch_the_database(store):
    """Junk must cost no I/O, or the parser becomes a DoS amplifier."""
    spy = _SpyConn(store)
    for bad in ("nonsense", "aera_a2a_short", "", "aera_a2a_" + "z" * 32):
        with pytest.raises(gw_cred.CredentialError):
            gw_cred.verify_credential(spy, bad)
    assert spy.queries == [], f"database was queried for malformed input: {spy.queries}"


def test_11b_a_well_formed_credential_does_reach_the_database(store, issued):
    """Control for test_11: proves the spy would have noticed a query."""
    spy = _SpyConn(store)
    gw_cred.verify_credential(spy, issued.plaintext)
    assert spy.queries, "the spy observes nothing -- test_11 would pass vacuously"


def test_12_a_broken_store_denies_access(monkeypatch):
    """Fail closed. An unavailable store must never mean 'assume valid'."""
    class Broken:
        def execute(self, *a, **k):
            raise sqlite3.OperationalError("database is locked")

    valid_shape = gw_cred.build_credential("a" * 32, "b" * 64)
    with pytest.raises(gw_auth.InboundAuthError):
        gw_auth.authenticate_request(_headers(valid_shape), conn=Broken())


def test_13_audience_and_issuer_are_enforced(store, issued):
    """A credential minted for another audience must not work here."""
    store.execute(f"UPDATE {gw_cred.TABLE} SET audience = 'aera-agent-api'")
    with pytest.raises(gw_cred.CredentialError) as exc:
        gw_cred.verify_credential(store, issued.plaintext)
    assert exc.value.reason == "wrong_audience"

    store.execute(f"UPDATE {gw_cred.TABLE} SET audience = ?, issuer = 'evil.example'",
                  (CREDENTIAL_AUDIENCE,))
    with pytest.raises(gw_cred.CredentialError) as exc:
        gw_cred.verify_credential(store, issued.plaintext)
    assert exc.value.reason == "wrong_issuer"


# =========================================================================== #
# C. Authorisation -- a separate question from authentication
# =========================================================================== #
def test_14_scoped_credential_reaches_only_its_agents(store):
    issued = gw_cred.issue_credential(store, owner_address="0xowner",
                                      scoped_agents=["agent-a"])
    record = gw_cred.verify_credential(store, issued.plaintext)
    assert gw_cred.authorize_request(record, target_agent_id="agent-a", skill_id=None)
    assert not gw_cred.authorize_request(record, target_agent_id="agent-b",
                                         skill_id=None)


def test_15_scoped_credential_is_limited_to_its_skills(store):
    issued = gw_cred.issue_credential(store, owner_address="0xowner",
                                      scoped_skills=[SKILL_READ_PROFILE])
    record = gw_cred.verify_credential(store, issued.plaintext)
    assert gw_cred.authorize_request(record, target_agent_id="agent-a",
                                     skill_id=SKILL_READ_PROFILE)
    assert not gw_cred.authorize_request(record, target_agent_id="agent-a",
                                         skill_id=SKILL_COMMUNICATE)


def test_16_authentication_does_not_imply_authorisation(store):
    """The whole point: a perfectly valid credential can still be refused."""
    issued = gw_cred.issue_credential(store, owner_address="0xowner",
                                      scoped_agents=["agent-a"])
    record = gw_cred.verify_credential(store, issued.plaintext)  # authenticates
    assert record.peer_id
    assert not gw_cred.authorize_request(record, target_agent_id="agent-b",
                                         skill_id=None)  # but is not authorised


def test_17_authorisation_is_a_separate_function_from_authentication():
    """Structural: fusing them would make a future bypass a one-line mistake."""
    assert gw_cred.authorize_request is not gw_cred.verify_credential
    source = inspect.getsource(gw_cred.verify_credential)
    assert "authorize_request" not in source, \
        "verification must not decide permissions"


def test_18_unscoped_credential_is_not_accidentally_scoped(store, issued):
    """Empty scope means unrestricted -- it must not silently deny everything."""
    record = gw_cred.verify_credential(store, issued.plaintext)
    assert record.scoped_agents == ()
    assert gw_cred.authorize_request(record, target_agent_id="anything",
                                     skill_id=SKILL_COMMUNICATE)


# =========================================================================== #
# D. Revocation and expiry
# =========================================================================== #
def test_19_revocation_is_immediate(store, issued):
    assert gw_cred.verify_credential(store, issued.plaintext)
    assert gw_cred.revoke_credential(store, cred_id=issued.record.cred_id,
                                     owner_address="0xowner")
    with pytest.raises(gw_cred.CredentialError) as exc:
        gw_cred.verify_credential(store, issued.plaintext)
    assert exc.value.reason == "revoked"


def test_20_expired_credential_is_refused(store, issued):
    future = datetime.now(timezone.utc) + timedelta(days=9999)
    with pytest.raises(gw_cred.CredentialError) as exc:
        gw_cred.verify_credential(store, issued.plaintext, now=future)
    assert exc.value.reason == "expired"


def test_21_expiry_boundary_is_exclusive(store, issued):
    """At exactly expires_at the credential is already dead, not still alive."""
    expires = datetime.strptime(issued.record.expires_at,
                                "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    with pytest.raises(gw_cred.CredentialError):
        gw_cred.verify_credential(store, issued.plaintext, now=expires)
    assert gw_cred.verify_credential(store, issued.plaintext,
                                     now=expires - timedelta(seconds=1))


def test_22_a_credential_with_no_expiry_is_refused(store, issued):
    """A missing or unparsable expiry must fail closed, not mean 'forever'.

    Two independent defences, both asserted: the schema forbids NULL outright,
    and anything unparsable is treated as already expired.
    """
    with pytest.raises(sqlite3.IntegrityError):
        store.execute(f"UPDATE {gw_cred.TABLE} SET expires_at = NULL")

    for broken in ("", "not-a-date", "2026-13-45", "99999999"):
        store.execute(f"UPDATE {gw_cred.TABLE} SET expires_at = ?", (broken,))
        with pytest.raises(gw_cred.CredentialError) as exc:
            gw_cred.verify_credential(store, issued.plaintext)
        assert exc.value.reason == "expired", broken


def test_23_revocation_preserves_the_audit_trail(store, issued):
    gw_cred.revoke_credential(store, cred_id=issued.record.cred_id,
                              owner_address="0xowner", reason="key leaked")
    row = store.execute(f"SELECT * FROM {gw_cred.TABLE} WHERE cred_id = ?",
                        (issued.record.cred_id,)).fetchone()
    assert row is not None, "the row was deleted -- audit history destroyed"
    assert row["status"] == gw_cred.STATUS_REVOKED
    assert row["revoked_reason"] == "key leaked"
    assert row["revoked_at"]


def test_24_one_peer_cannot_revoke_another_owners_credential(store, issued):
    assert not gw_cred.revoke_credential(store, cred_id=issued.record.cred_id,
                                         owner_address="0xstranger")
    assert gw_cred.verify_credential(store, issued.plaintext)


def test_25_rotation_does_not_break_the_old_credential_until_revoked(store, issued):
    """Issue new, hand over, then revoke old. No implicit invalidation."""
    replacement = gw_cred.issue_credential(store, owner_address="0xowner",
                                           peer_id=issued.record.peer_id)
    assert gw_cred.verify_credential(store, issued.plaintext)
    assert gw_cred.verify_credential(store, replacement.plaintext)
    gw_cred.revoke_credential(store, cred_id=issued.record.cred_id,
                              owner_address="0xowner")
    with pytest.raises(gw_cred.CredentialError):
        gw_cred.verify_credential(store, issued.plaintext)
    assert gw_cred.verify_credential(store, replacement.plaintext).peer_id \
        == issued.record.peer_id


# =========================================================================== #
# E. Trust-level separation
# =========================================================================== #
def test_26_aera_agent_jwt_is_still_refused(store):
    """The LEVEL 2 / LEVEL 3 boundary. Regression guard from the prior phase."""
    fake_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZ2VudCJ9.c2ln"
    with pytest.raises(gw_auth.InboundAuthError) as exc:
        gw_auth.authenticate_request(_headers(fake_jwt), conn=store)
    assert "JWT" in str(exc.value)


def test_27_jwt_is_rejected_before_any_store_lookup(store):
    """An AEra token must never reach the credential store at all."""
    spy = _SpyConn(store)
    with pytest.raises(gw_auth.InboundAuthError):
        gw_auth.authenticate_request(
            _headers("eyJhbGciOiJIUzI1NiJ9.eyJhIjoxfQ.sig"), conn=spy)
    assert spy.queries == []


def test_28_peer_credential_audience_is_not_an_agent_audience():
    """Disjoint audiences are what keep the two token types from crossing."""
    from agent.constants import AUDIENCE_ALLOWLIST

    assert CREDENTIAL_AUDIENCE not in AUDIENCE_ALLOWLIST


def test_29_authenticated_peer_is_still_not_an_aera_agent(store, issued):
    record = gw_cred.verify_credential(store, issued.plaintext)
    peer = gw_peer.authenticated_peer(record)
    assert peer.is_authenticated
    assert peer.is_trusted_aera_agent is False, \
        "an external peer must never become an AEra agent"


def test_30_a_peer_cannot_name_its_own_identity(store):
    """peer_id is minted by AEra. A caller-supplied claim must not become it."""
    issued = gw_cred.issue_credential(store, owner_address="0xowner")
    record = gw_cred.verify_credential(store, issued.plaintext)
    peer = gw_peer.authenticated_peer(record, claimed_id="did:aera:agent:admin")
    assert peer.authenticated_principal == record.peer_id
    assert peer.external_agent_id == "did:aera:agent:admin"  # kept, untrusted
    assert peer.authenticated_principal != peer.external_agent_id


def test_31_only_a_verified_record_can_produce_an_authenticated_peer():
    """Structural: STATUS_AUTHENTICATED must have exactly one source."""
    source = (GATEWAY_DIR / "peer.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    setters = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg == "authentication_status":
                    setters.append(getattr(kw.value, "id", "?"))
    assert setters.count("STATUS_AUTHENTICATED") == 1, \
        f"more than one constructor grants authentication: {setters}"


# =========================================================================== #
# F. Enumeration and leakage
# =========================================================================== #
def test_32_all_failure_modes_share_one_message(store, issued):
    """Unknown, wrong-secret, revoked and expired must be indistinguishable."""
    cred_id, _ = gw_cred.parse_credential(issued.plaintext)
    messages = set()

    for candidate in (gw_cred.build_credential("f" * 32, "e" * 64),
                      gw_cred.build_credential(cred_id, "a" * 64)):
        with pytest.raises(gw_cred.CredentialError) as exc:
            gw_cred.verify_credential(store, candidate)
        messages.add(exc.value.message)

    with pytest.raises(gw_cred.CredentialError) as exc:
        gw_cred.verify_credential(store, issued.plaintext,
                                  now=datetime.now(timezone.utc) + timedelta(days=9999))
    messages.add(exc.value.message)

    gw_cred.revoke_credential(store, cred_id=cred_id, owner_address="0xowner")
    with pytest.raises(gw_cred.CredentialError) as exc:
        gw_cred.verify_credential(store, issued.plaintext)
    messages.add(exc.value.message)

    assert messages == {gw_cred.OPAQUE_AUTH_FAILURE}, \
        f"failure modes are distinguishable: {messages}"


def test_33_the_reason_is_kept_internally_for_audit(store):
    """Opaque outward, precise inward. Operators still need to diagnose."""
    with pytest.raises(gw_cred.CredentialError) as exc:
        gw_cred.verify_credential(store, gw_cred.build_credential("a" * 32, "b" * 64))
    assert exc.value.reason == "unknown_credential"
    assert exc.value.reason != exc.value.message


def test_34_out_of_scope_target_looks_like_an_unknown_target():
    """Authorisation failure must not confirm that an agent exists."""
    from a2a_gateway.routing import _OPAQUE_UNKNOWN

    handler_src = (GATEWAY_DIR / "handler.py").read_text(encoding="utf-8")
    assert f'"{_OPAQUE_UNKNOWN}"' in handler_src, \
        "the forbidden response must reuse the opaque unknown-target wording"


# =========================================================================== #
# G. Policy
# =========================================================================== #
def test_35_default_policy_keeps_anonymous_access(monkeypatch):
    """Deploying this phase must not break existing anonymous peers."""
    monkeypatch.delenv("AERA_A2A_AUTH_POLICY", raising=False)
    assert not gw_auth.authentication_required()
    peer = gw_auth.authenticate_request({})
    assert peer.authentication_status == gw_peer.STATUS_ANONYMOUS


def test_36_required_policy_rejects_anonymous(monkeypatch):
    monkeypatch.setenv("AERA_A2A_AUTH_POLICY", "required")
    with pytest.raises(gw_auth.InboundAuthError):
        gw_auth.authenticate_request({})


def test_37_required_policy_admits_a_valid_credential(monkeypatch, store, issued):
    monkeypatch.setenv("AERA_A2A_AUTH_POLICY", "required")
    peer = gw_auth.authenticate_request(_headers(issued.plaintext), conn=store)
    assert peer.is_authenticated
    assert peer.peer_id == issued.record.peer_id


def test_38_an_unrecognised_policy_does_not_silently_enable_enforcement(monkeypatch):
    """A typo must not lock everyone out, and must not look like 'required'."""
    for value in ("REQUIRE", "yes", "true", "optional", "", "requiredd"):
        monkeypatch.setenv("AERA_A2A_AUTH_POLICY", value)
        assert not gw_auth.authentication_required(), value
    monkeypatch.setenv("AERA_A2A_AUTH_POLICY", "REQUIRED")
    assert gw_auth.authentication_required(), "case-insensitive match expected"


def test_39_api_key_is_not_a_substitute_under_required(monkeypatch):
    monkeypatch.setenv("AERA_A2A_AUTH_POLICY", "required")
    with pytest.raises(gw_auth.InboundAuthError):
        gw_auth.authenticate_request({"x-api-key": "anything"})


# =========================================================================== #
# H. Rate limiting
# =========================================================================== #
def test_40_credential_scope_exists_and_is_additional():
    from a2a_gateway.ratelimit import (
        SCOPE_AGENT, SCOPE_CREDENTIAL, SCOPE_GLOBAL, SCOPE_PEER, load_limits,
    )

    limits = load_limits()
    # Removing any of the pre-existing dimensions would let a credential
    # bypass the protection of the service as a whole.
    for scope in (SCOPE_GLOBAL, SCOPE_PEER, SCOPE_AGENT, SCOPE_CREDENTIAL):
        assert scope in limits
    assert limits[SCOPE_CREDENTIAL].rate > 0


def test_41_authenticated_callers_do_not_bypass_the_global_limit():
    """Structural: routes.py charges global/peer before authentication runs."""
    routes_src = (GATEWAY_DIR / "routes.py").read_text(encoding="utf-8")
    assert "SCOPE_GLOBAL" in routes_src and "SCOPE_PEER" in routes_src
    handler_src = (GATEWAY_DIR / "handler.py").read_text(encoding="utf-8")
    assert "is_authenticated" not in routes_src, \
        "routes.py must not make rate limiting conditional on authentication"
    assert "SCOPE_CREDENTIAL" in handler_src


def test_42_credential_limit_is_enforced_per_credential():
    from a2a_gateway.ratelimit import SCOPE_CREDENTIAL, reset_limiter, get_limiter

    reset_limiter()
    limiter = get_limiter()
    burst = int(limiter.limits[SCOPE_CREDENTIAL].burst)
    for _ in range(burst):
        assert limiter.check(SCOPE_CREDENTIAL, "cred-1").allowed
    assert not limiter.check(SCOPE_CREDENTIAL, "cred-1").allowed
    # A different credential has its own bucket and is unaffected.
    assert limiter.check(SCOPE_CREDENTIAL, "cred-2").allowed
    reset_limiter()


# =========================================================================== #
# I. Issuance authority
# =========================================================================== #
def test_43_cannot_scope_to_another_owners_agent(store):
    not_owned = gw_cred.verify_owns_agents(store, "0xowner", ["agent-a", "agent-x"])
    assert not_owned == ["agent-x"]


def test_44_ownership_check_is_case_insensitive(store):
    assert gw_cred.verify_owns_agents(store, "0xOWNER", ["agent-a"]) == []


def test_45_owner_is_never_taken_from_the_request_body():
    """Structural: a body-supplied owner would be trivial impersonation."""
    import server

    for func in (server.issue_a2a_credential, server.revoke_a2a_credential,
                 server.list_a2a_credentials):
        source = inspect.getsource(func)
        assert "_dashboard_owner_from_request(req)" in source
        assert 'body.get("owner' not in source
        assert 'body.get("peer_id' not in source, \
            "the caller must not choose its own peer identity"


def test_46_listing_never_returns_a_secret(store):
    gw_cred.issue_credential(store, owner_address="0xowner")
    records = gw_cred.list_for_owner(store, "0xowner")
    blob = json.dumps([r.to_owner_dict() for r in records])
    assert "secret" not in blob.lower()
    assert CREDENTIAL_PREFIX not in blob


def test_47_owners_only_see_their_own_credentials(store):
    gw_cred.issue_credential(store, owner_address="0xowner")
    gw_cred.issue_credential(store, owner_address="0xstranger")
    assert len(gw_cred.list_for_owner(store, "0xowner")) == 1
    assert len(gw_cred.list_for_owner(store, "0xstranger")) == 1


def test_48_no_self_service_registration_endpoint():
    """An external party must not be able to obtain a credential by asking."""
    import server

    paths = [getattr(r, "path", "") for r in server.app.routes]
    credential_paths = [p for p in paths if "a2a-credential" in p]
    assert credential_paths, "issuance endpoints are missing"
    for path in credential_paths:
        assert path.startswith("/api/dashboard/"), \
            f"{path} is not behind the owner dashboard"


def test_49_issued_credential_carries_the_gateway_audience(store, issued):
    assert issued.record.audience == CREDENTIAL_AUDIENCE
    assert issued.record.issuer == CREDENTIAL_ISSUER


def test_50_ttl_is_bounded_and_configurable(monkeypatch, store):
    monkeypatch.setenv("AERA_A2A_CREDENTIAL_TTL_DAYS", "7")
    issued = gw_cred.issue_credential(store, owner_address="0xowner")
    issued_at = datetime.strptime(issued.record.issued_at, "%Y-%m-%dT%H:%M:%SZ")
    expires = datetime.strptime(issued.record.expires_at, "%Y-%m-%dT%H:%M:%SZ")
    assert (expires - issued_at).days == 7
    # A nonsensical value must not mean "never expires".
    for bad in ("0", "-5", "abc", ""):
        monkeypatch.setenv("AERA_A2A_CREDENTIAL_TTL_DAYS", bad)
        assert gw_cred.credential_ttl_days() > 0


# =========================================================================== #
# J. The Agent Identity Layer is untouched
# =========================================================================== #
def test_51_gateway_never_imports_agent_token_machinery():
    """The gateway must not be able to mint or verify an AEra agent token."""
    for path in GATEWAY_DIR.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and (node.module or "").endswith(
                    "agent.tokens"):
                pytest.fail(f"{path.name} imports agent.tokens")
            if isinstance(node, ast.Attribute) and node.attr in {"issue", "get_secret"}:
                parent = getattr(node.value, "id", "")
                assert parent != "tokens", f"{path.name} calls tokens.{node.attr}"


def test_52_gateway_never_reads_the_agent_jwt_secret():
    """No gateway module may READ a signing secret from the environment.

    Deliberately an AST check for actual reads, not a text search. `card.py`
    legitimately contains the string "AGENT_JWT_SECRET" inside
    FORBIDDEN_CARD_SUBSTRINGS -- that is a denylist protecting the public card,
    and a text scan would flag the defence as if it were the offence.
    """
    forbidden = {"AGENT_JWT_SECRET", "OAUTH_JWT_SECRET", "TOKEN_SECRET"}
    for path in GATEWAY_DIR.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            target = node.func
            name = getattr(target, "attr", None) or getattr(target, "id", None)
            if name not in {"getenv", "environ", "get"}:
                continue
            for arg in node.args:
                if isinstance(arg, ast.Constant) and arg.value in forbidden:
                    pytest.fail(f"{path.name} reads {arg.value}")
        # os.environ["X"] subscript form
        for node in ast.walk(tree):
            if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant):
                if node.slice.value in forbidden:
                    pytest.fail(f"{path.name} reads {node.slice.value}")


def test_53_owner_ops_is_not_extended_for_peers():
    """Issuance uses the dashboard session, not an agent-token capability."""
    from agent.constants import OWNER_OPS

    for op in OWNER_OPS:
        assert "a2a" not in op.lower() and "peer" not in op.lower(), \
            f"OWNER_OPS was extended with {op}"


def test_54_credential_table_is_separate_from_agent_tables(store):
    """A peer credential must not live in, or alter, the agent key store."""
    assert gw_cred.TABLE == "a2a_peer_credentials"
    schema = (GATEWAY_DIR / "credentials.py").read_text(encoding="utf-8")
    for table in ("agent_keys", "agent_jti", "oauth_token_jti"):
        assert f"INSERT INTO {table}" not in schema
        assert f"UPDATE {table}" not in schema


# =========================================================================== #
# K. Agent Card honesty
# =========================================================================== #
def test_55_card_declares_the_actual_policy(monkeypatch):
    from a2a_gateway.card import SECURITY_SCHEME_NAME, build_agent_card

    monkeypatch.delenv("AERA_A2A_AUTH_POLICY", raising=False)
    open_card = build_agent_card("https://aeralogin.com")
    assert open_card["security"] == [], "an open gateway must not imply protection"
    assert SECURITY_SCHEME_NAME in open_card["securitySchemes"]

    monkeypatch.setenv("AERA_A2A_AUTH_POLICY", "required")
    closed_card = build_agent_card("https://aeralogin.com")
    assert closed_card["security"] == [{SECURITY_SCHEME_NAME: []}]


def test_56_card_still_passes_its_publication_self_check(monkeypatch):
    from a2a_gateway.card import build_agent_card, card_is_safe_to_publish

    for policy in ("optional", "required"):
        monkeypatch.setenv("AERA_A2A_AUTH_POLICY", policy)
        safe, leaked = card_is_safe_to_publish(
            build_agent_card("https://aeralogin.com"))
        assert safe, leaked


def test_57_card_does_not_advertise_self_service_issuance(monkeypatch):
    from a2a_gateway.card import build_agent_card

    monkeypatch.setenv("AERA_A2A_AUTH_POLICY", "required")
    blob = json.dumps(build_agent_card("https://aeralogin.com"))
    assert "/api/dashboard" not in blob
    assert CREDENTIAL_PREFIX not in blob


# =========================================================================== #
# L. Wired end-to-end over real HTTP
#
# Everything above tests the building blocks. These tests drive the actual
# FastAPI app, because a correct component that was never connected -- or was
# connected behind `if False` -- still leaves the system unprotected. The
# mutation proof found exactly that gap, so these exist to close it.
# =========================================================================== #
from tests.agent.testclient import ANVIL_KEY_1, ANVIL_KEY_2, AgentTestClient  # noqa: E402

CRED_URL = "/api/dashboard/a2a-credentials"


@pytest.fixture()
def clean_credentials(wipe_agent_tables):
    """Clear the credential table between tests.

    `wipe_agent_tables` predates this phase and does not know about
    `a2a_peer_credentials`, so without this a credential issued by one test
    would still be listed in the next one. Depends on the existing fixture so
    both wipes happen exactly once per test.
    """
    from agent.repository import get_connection

    conn = get_connection()
    try:
        gw_cred.init_schema(conn)
        conn.execute(f"DELETE FROM {gw_cred.TABLE}")
        conn.commit()
    finally:
        conn.close()
    return True


@pytest.fixture()
def alice(client, clean_credentials):
    a = AgentTestClient(client, eth_priv=ANVIL_KEY_1)
    a.register()
    return a


@pytest.fixture()
def bob(client, clean_credentials):
    b = AgentTestClient(client, eth_priv=ANVIL_KEY_2)
    b.register()
    return b


def session_headers(server_module, wallet: str) -> dict:
    return {"Authorization": f"Bearer {server_module.generate_dashboard_jwt(wallet)}"}


def _issue(client, server_module, owner, **body):
    return client.post(CRED_URL, json=body,
                       headers=session_headers(server_module, owner))


@pytest.fixture(autouse=True)
def _reset_limits():
    from a2a_gateway.ratelimit import reset_limiter

    reset_limiter()
    yield
    reset_limiter()


def test_58_issuance_requires_an_authenticated_owner(client):
    """No dashboard session, no credential. Anonymous issuance would be fatal."""
    r = client.post(CRED_URL, json={})
    assert r.status_code == 401
    assert CREDENTIAL_PREFIX not in r.text


def test_59_owner_can_issue_and_the_secret_appears_exactly_once(
        client, server_module, alice):
    r = _issue(client, server_module, alice.owner, peer_label="Sanctum Beacon")
    assert r.status_code == 200, r.text
    body = r.json()
    credential = body["credential"]
    assert credential.startswith(CREDENTIAL_PREFIX)

    listing = client.get(CRED_URL, headers=session_headers(server_module, alice.owner))
    assert listing.status_code == 200
    assert credential not in listing.text, "the plaintext was shown a second time"
    assert CREDENTIAL_PREFIX not in listing.text
    assert listing.json()["credentials"][0]["cred_id"] == body["cred_id"]


def test_60_body_supplied_owner_is_ignored(client, server_module, alice, bob):
    """Impersonation attempt: Alice's session, Bob named in the body."""
    r = client.post(CRED_URL,
                    json={"owner": bob.owner, "owner_address": bob.owner,
                          "peer_id": "peer_attacker_chosen"},
                    headers=session_headers(server_module, alice.owner))
    assert r.status_code == 200, r.text
    assert r.json()["peer_id"] != "peer_attacker_chosen", \
        "the caller chose its own peer identity"

    # The credential must belong to Alice, and Bob must not see it.
    bob_list = client.get(CRED_URL, headers=session_headers(server_module, bob.owner))
    assert bob_list.json()["credentials"] == []
    alice_list = client.get(CRED_URL,
                            headers=session_headers(server_module, alice.owner))
    assert len(alice_list.json()["credentials"]) == 1


def test_61_cannot_scope_a_credential_to_another_owners_agent(
        client, server_module, alice, bob):
    r = _issue(client, server_module, alice.owner, scoped_agents=[bob.agent_id])
    assert r.status_code == 403, r.text
    assert r.json()["error"] == "not_your_agent"
    assert CREDENTIAL_PREFIX not in r.text, "a credential was minted anyway"


def test_62_credential_authenticates_over_the_gateway(client, server_module, alice):
    credential = _issue(client, server_module, alice.owner).json()["credential"]
    r = client.post(GATEWAY_PATH, json=rpc(target=alice.agent_id),
                    headers={"Authorization": f"Bearer {credential}"})
    assert r.status_code == 200, r.text
    assert "error" not in r.json(), r.text


def test_63_scoped_credential_is_refused_for_another_agent_over_http(
        client, server_module, alice, bob):
    """The gap the mutation proof exposed: authorisation must be WIRED IN.

    The out-of-scope target must be a REAL, reachable agent. An earlier version
    of this test aimed at a non-existent agent id, so the opaque
    "unknown target" response made it pass even with the authorisation check
    deleted -- it was green for the wrong reason. Bob's agent genuinely exists
    and genuinely answers, so the only thing that can refuse it is scoping.
    """
    scoped = _issue(client, server_module, alice.owner,
                    scoped_agents=[alice.agent_id]).json()["credential"]

    # Control: the in-scope agent works, so a failure below is about scope.
    allowed = client.post(GATEWAY_PATH, json=rpc(target=alice.agent_id, mid="ok-1"),
                          headers={"Authorization": f"Bearer {scoped}"})
    assert allowed.status_code == 200, allowed.text
    assert "error" not in allowed.json(), allowed.text

    # Control: Bob's agent is reachable for an unscoped caller.
    anon = client.post(GATEWAY_PATH, json=rpc(target=bob.agent_id, mid="anon-b"))
    assert anon.status_code == 200 and "error" not in anon.json(), anon.text

    denied = client.post(GATEWAY_PATH, json=rpc(target=bob.agent_id, mid="no-1"),
                         headers={"Authorization": f"Bearer {scoped}"})
    assert denied.status_code == 403, \
        f"an out-of-scope but existing agent was reachable: {denied.text}"
    assert "error" in denied.json()
    # The refusal must not confirm anything about the agent or the scope.
    assert "scope" not in denied.text.lower()
    assert "not available" in denied.text


def test_64_revoked_credential_stops_working_over_http(client, server_module, alice):
    issued = _issue(client, server_module, alice.owner).json()
    credential, cred_id = issued["credential"], issued["cred_id"]

    first = client.post(GATEWAY_PATH, json=rpc(target=alice.agent_id, mid="pre-1"),
                        headers={"Authorization": f"Bearer {credential}"})
    assert first.status_code == 200

    revoke = client.post(f"{CRED_URL}/{cred_id}/revoke", json={"reason": "leaked"},
                         headers=session_headers(server_module, alice.owner))
    assert revoke.status_code == 200, revoke.text

    after = client.post(GATEWAY_PATH, json=rpc(target=alice.agent_id, mid="post-1"),
                        headers={"Authorization": f"Bearer {credential}"})
    assert after.status_code == 401, "revocation was not immediate"


def test_65_one_owner_cannot_revoke_anothers_credential(
        client, server_module, alice, bob):
    cred_id = _issue(client, server_module, alice.owner).json()["cred_id"]
    r = client.post(f"{CRED_URL}/{cred_id}/revoke", json={},
                    headers=session_headers(server_module, bob.owner))
    assert r.status_code == 404, r.text  # same as 'does not exist'
    assert r.json()["error"] == "unknown_credential"


def test_66_credential_rate_limit_is_enforced_over_http(
        client, server_module, alice, monkeypatch):
    """A compromised credential must not get unlimited throughput."""
    from a2a_gateway.ratelimit import reset_limiter

    monkeypatch.setenv("AERA_A2A_CREDENTIAL_RATE", "0.01")
    monkeypatch.setenv("AERA_A2A_CREDENTIAL_BURST", "3")
    # Keep the anonymous buckets wide so this test can only fail on the
    # credential dimension -- otherwise it would pass for the wrong reason.
    monkeypatch.setenv("AERA_A2A_GLOBAL_BURST", "10000")
    monkeypatch.setenv("AERA_A2A_PEER_BURST", "10000")
    monkeypatch.setenv("AERA_A2A_AGENT_BURST", "10000")
    credential = _issue(client, server_module, alice.owner).json()["credential"]
    reset_limiter()

    statuses = [
        client.post(GATEWAY_PATH, json=rpc(target=alice.agent_id, mid=f"rl-{i}"),
                    headers={"Authorization": f"Bearer {credential}"}).status_code
        for i in range(8)
    ]
    assert 429 in statuses, f"credential limit never triggered: {statuses}"


def test_67_authenticated_caller_still_obeys_the_global_limit(
        client, server_module, alice, monkeypatch):
    """Authentication must not be a way around service-wide protection."""
    from a2a_gateway.ratelimit import reset_limiter

    monkeypatch.setenv("AERA_A2A_GLOBAL_RATE", "0.01")
    monkeypatch.setenv("AERA_A2A_GLOBAL_BURST", "2")
    monkeypatch.setenv("AERA_A2A_CREDENTIAL_BURST", "10000")
    credential = _issue(client, server_module, alice.owner).json()["credential"]
    reset_limiter()

    statuses = [
        client.post(GATEWAY_PATH, json=rpc(target=alice.agent_id, mid=f"g-{i}"),
                    headers={"Authorization": f"Bearer {credential}"}).status_code
        for i in range(6)
    ]
    assert 429 in statuses, f"global limit was bypassed by authenticating: {statuses}"


def test_68_invalid_credential_is_refused_over_http(client, server_module, alice):
    for bad in ("aera_a2a_" + "a" * 32 + "_" + "b" * 64, "garbage",
                "eyJhbGciOiJIUzI1NiJ9.eyJhIjoxfQ.sig"):
        r = client.post(GATEWAY_PATH, json=rpc(target=alice.agent_id),
                        headers={"Authorization": f"Bearer {bad}"})
        assert r.status_code == 401, f"{bad!r} -> {r.status_code}"


def test_69_anonymous_access_still_works_by_default(client, alice):
    """The compatibility promise: deploying this phase breaks no existing peer."""
    r = client.post(GATEWAY_PATH, json=rpc(target=alice.agent_id, mid="anon-1"))
    assert r.status_code == 200, r.text
    assert "error" not in r.json(), r.text


def test_70_issuance_response_never_leaks_into_the_server_log(
        client, server_module, alice, caplog):
    import logging

    with caplog.at_level(logging.DEBUG):
        credential = _issue(client, server_module, alice.owner).json()["credential"]
    assert credential not in caplog.text
    secret = credential.rsplit("_", 1)[1]
    assert secret not in caplog.text
