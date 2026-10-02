"""Human Identity layer — unit, negative and migration tests (in-memory DB)."""
from __future__ import annotations

import re
import sqlite3

import pytest

from identity import authorization as auth
from identity import migration
from identity import repository as repo
from identity.providers import FUTURE_PROVIDERS, ProviderError, WALLET, wallet_subject

W1 = "0x" + "a1" * 20
W2 = "0x" + "b2" * 20
HUMAN_RE = re.compile(r"^did:aera:human:[0-9a-f]{32}$")


@pytest.fixture()
def conn():
    c = sqlite3.connect(":memory:")
    c.execute("PRAGMA foreign_keys=ON")
    c.execute("""CREATE TABLE agents (agent_id TEXT PRIMARY KEY,
                 owner_wallet TEXT NOT NULL, status TEXT DEFAULT 'active')""")
    migration.init(c)
    yield c
    c.close()


def _count(c, table):
    return c.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


# ----------------------------------------------------------------- wallet provider
def test_wallet_subject_is_lowercase_address():
    assert wallet_subject(W1.upper().replace("0X", "0x")) == W1


@pytest.mark.parametrize("bad", ["", None, "0x123", "a1" * 20, "0x" + "zz" * 20,
                                 W1 + "00", " 0x", "0x" + "a1" * 19 + "g1"])
def test_invalid_wallet_rejected(bad):
    with pytest.raises(ProviderError) as e:
        wallet_subject(bad)
    assert e.value.code == "invalid_wallet_address"


@pytest.mark.parametrize("p", sorted(FUTURE_PROVIDERS) + ["webauthn", "", "WALLET"])
def test_unimplemented_providers_refused(conn, p):
    with pytest.raises(ProviderError):
        repo.resolve_or_create(conn, p, "someone")
    assert _count(conn, "human_identities") == 0


# ----------------------------------------------------------------- identity model
def test_first_login_creates_one_human_and_binding(conn):
    h = repo.resolve_or_create_wallet(conn, W1)
    assert HUMAN_RE.match(h.human_id) and h.is_active
    # random, not derived from the wallet
    assert h.human_id.split(":")[-1][:8] not in W1
    b = repo.find_binding(conn, WALLET, W1)
    assert b.human_id == h.human_id and b.provider_subject == W1


def test_repeat_resolution_is_idempotent_and_case_insensitive(conn):
    h1 = repo.resolve_or_create_wallet(conn, W1)
    h2 = repo.resolve_or_create_wallet(conn, W1.upper().replace("0X", "0x"))
    assert h1.human_id == h2.human_id
    assert _count(conn, "human_identities") == 1
    assert _count(conn, "human_identity_providers") == 1


def test_different_wallets_get_different_humans(conn):
    assert (repo.resolve_or_create_wallet(conn, W1).human_id
            != repo.resolve_or_create_wallet(conn, W2).human_id)


def test_duplicate_binding_is_impossible_at_db_level(conn):
    h = repo.resolve_or_create_wallet(conn, W1)
    other = repo.resolve_or_create_wallet(conn, W2)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO human_identity_providers(human_id, provider, "
                     "provider_subject, created_at) VALUES (?, 'wallet', ?, 'x')",
                     (other.human_id, W1))
    assert repo.find_binding(conn, WALLET, W1).human_id == h.human_id


def test_race_loser_leaves_no_orphan_human(conn, monkeypatch):
    winner = repo.resolve_or_create_wallet(conn, W1)
    # Simulate a concurrent writer: the pre-check misses, the insert collides.
    real = repo.resolve
    calls = {"n": 0}

    def flaky(c, p, s):
        calls["n"] += 1
        return None if calls["n"] == 1 else real(c, p, s)

    monkeypatch.setattr(repo, "resolve", flaky)
    got = repo.resolve_or_create_wallet(conn, W1)
    assert got.human_id == winner.human_id
    assert _count(conn, "human_identities") == 1


def test_resolve_never_creates(conn):
    assert repo.resolve_wallet(conn, W1) is None
    assert _count(conn, "human_identities") == 0


def test_touch_login_updates_only_that_binding(conn):
    repo.resolve_or_create_wallet(conn, W1)
    repo.resolve_or_create_wallet(conn, W2)
    repo.touch_login(conn, WALLET, W1)
    assert repo.find_binding(conn, WALLET, W1).last_login_at is not None
    assert repo.find_binding(conn, WALLET, W2).last_login_at is None


def test_disabled_human_gets_no_authorization(conn):
    h = repo.resolve_or_create_wallet(conn, W1)
    conn.execute("UPDATE human_identities SET status='disabled' WHERE human_id=?",
                 (h.human_id,))
    assert auth.human_for_verified_wallet(conn, W1) is None


# ----------------------------------------------------------------- authorization
def _agent(conn, aid, wallet, owner_id=None):
    conn.execute("INSERT INTO agents(agent_id, owner_wallet, owner_id) VALUES (?,?,?)",
                 (aid, wallet, owner_id))


def test_owns_agent_requires_wallet_and_human(conn):
    h1 = repo.resolve_or_create_wallet(conn, W1).human_id
    h2 = repo.resolve_or_create_wallet(conn, W2).human_id
    _agent(conn, "a1", W1, h1)
    assert auth.owns_agent(conn, h1, W1, "a1")
    assert not auth.owns_agent(conn, h2, W2, "a1")   # other human + wallet
    assert not auth.owns_agent(conn, h2, W1, "a1")   # forged owner_id, right wallet
    assert not auth.owns_agent(conn, h1, W2, "a1")   # right human, wrong wallet
    assert not auth.owns_agent(conn, "", W1, "a1")
    assert not auth.owns_agent(conn, h1, "", "a1")
    assert not auth.owns_agent(conn, h1, W1, "missing")


def test_unlinked_legacy_agent_falls_back_to_wallet_rule_only(conn):
    h1 = repo.resolve_or_create_wallet(conn, W1).human_id
    h2 = repo.resolve_or_create_wallet(conn, W2).human_id
    _agent(conn, "legacy", W1, None)
    assert auth.owns_agent(conn, h1, W1, "legacy")
    assert not auth.owns_agent(conn, h2, W2, "legacy")


def test_invalid_wallet_yields_no_human(conn):
    assert auth.human_for_verified_wallet(conn, "not-a-wallet") is None


# ----------------------------------------------------------------- migration
def _legacy_db():
    c = sqlite3.connect(":memory:")
    c.execute("""CREATE TABLE agents (agent_id TEXT PRIMARY KEY,
                 owner_wallet TEXT NOT NULL, label TEXT)""")
    c.execute("CREATE TABLE agent_enrollments (id TEXT, owner_wallet TEXT)")
    c.execute("CREATE TABLE users (address TEXT PRIMARY KEY)")
    c.executemany("INSERT INTO agents VALUES (?,?,?)", [
        ("a1", W1, "x"), ("a2", W1.upper().replace("0X", "0x"), "y"),
        ("a3", W2, None), ("bad", "garbage", None)])
    c.execute("INSERT INTO agent_enrollments VALUES ('e1', ?)", ("0x" + "c3" * 20,))
    c.executemany("INSERT INTO users VALUES (?)", [(W1,), ("0x" + "d4" * 20,)])
    return c


def test_migration_links_every_valid_owner_once():
    c = _legacy_db()
    before = c.execute("SELECT agent_id, owner_wallet, label FROM agents "
                       "ORDER BY agent_id").fetchall()
    s = migration.migrate_existing_wallets(c)
    assert s["wallets_seen"] == 4 and s["humans_created"] == 4
    assert s["invalid_skipped"] == 1 and s["agents_linked"] == 3
    rows = dict(c.execute("SELECT agent_id, owner_id FROM agents").fetchall())
    assert rows["a1"] == rows["a2"] != rows["a3"]
    assert rows["bad"] is None
    # Nothing pre-existing was rewritten.
    assert c.execute("SELECT agent_id, owner_wallet, label FROM agents "
                     "ORDER BY agent_id").fetchall() == before


def test_migration_is_idempotent():
    c = _legacy_db()
    migration.migrate_existing_wallets(c)
    snap = (c.execute("SELECT * FROM human_identities ORDER BY 1").fetchall(),
            c.execute("SELECT agent_id, owner_id FROM agents ORDER BY 1").fetchall())
    s2 = migration.migrate_existing_wallets(c)
    assert s2["humans_created"] == 0 and s2["agents_linked"] == 0
    assert (c.execute("SELECT * FROM human_identities ORDER BY 1").fetchall(),
            c.execute("SELECT agent_id, owner_id FROM agents ORDER BY 1").fetchall()) == snap


def test_migration_never_overwrites_existing_owner_id():
    c = _legacy_db()
    migration.init(c)
    c.execute("UPDATE agents SET owner_id='did:aera:human:keep' WHERE agent_id='a1'")
    migration.migrate_existing_wallets(c)
    assert c.execute("SELECT owner_id FROM agents WHERE agent_id='a1'").fetchone()[0] \
        == "did:aera:human:keep"


def test_migration_on_fresh_and_minimal_databases():
    empty = sqlite3.connect(":memory:")
    assert migration.migrate_existing_wallets(empty)["wallets_seen"] == 0
    tiny = sqlite3.connect(":memory:")
    tiny.execute("CREATE TABLE agents (agent_id TEXT, owner_wallet TEXT)")
    tiny.execute("INSERT INTO agents VALUES ('agent-a', '0xOwner')")  # test-style row
    s = migration.migrate_existing_wallets(tiny)
    assert s["invalid_skipped"] == 1 and s["agents_linked"] == 0
