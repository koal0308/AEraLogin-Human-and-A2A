"""
Isolated Test Environment – AEraLogIn Authentication Baseline
==============================================================

This conftest guarantees:
  * NO production DB (`aera.db`) is used – ephemeral SQLite per session.
  * NO real Web3 / Base Mainnet / Alchemy connection – heavy modules are
    replaced by pure-python stubs BEFORE `server` is imported.
  * NO real Telegram / Discord / Gate bots – stubbed.
  * Deterministic, test-only secrets injected via env vars.

Nothing in the production tree is edited. All isolation happens through
`sys.modules` injection performed here.
"""
from __future__ import annotations

import os
import sys
import types
import asyncio
import tempfile
import pathlib
from unittest.mock import AsyncMock, MagicMock

import pytest

# ---------------------------------------------------------------------------
# 1) Test-only secrets & config MUST be set before `server` loads.
# ---------------------------------------------------------------------------
_REPO_DIR = pathlib.Path(__file__).resolve().parent.parent
_TMP_DB = tempfile.NamedTemporaryFile(
    prefix="test_aera_", suffix=".db", delete=False, dir=str(_REPO_DIR)
)
_TMP_DB.close()
_TMP_DB_PATH = pathlib.Path(_TMP_DB.name)

os.environ["DATABASE_PATH"] = _TMP_DB_PATH.name  # server strips "./" and joins
# Test-only secrets. Must satisfy the production fail-fast policy in server.py
# (>= 32 chars, no placeholder value, all three secrets mutually distinct).
os.environ["TOKEN_SECRET"] = "TEST-ONLY-token-secret-do-not-use-in-prod"
os.environ["OAUTH_JWT_SECRET"] = "TEST-ONLY-oauth-secret-do-not-use-in-prod"
os.environ["OAUTH_ADMIN_KEY"] = "TEST-ONLY-oauth-admin-key-do-not-use-in-prod"
os.environ["TOKEN_EXPIRY_MINUTES"] = "2"
os.environ["OAUTH_TOKEN_EXPIRY_HOURS"] = "1"
os.environ["ADMIN_WALLET"] = ""              # disables real airdrops
os.environ["ADMIN_PRIVATE_KEY"] = ""
os.environ["BACKEND_PRIVATE_KEY"] = ""
os.environ["PRIVATE_KEY"] = ""
os.environ["BASE_RPC_URL"] = "http://127.0.0.1:1/mock"   # unreachable on purpose
os.environ["BASE_ALCHEMY_API_URL"] = ""
os.environ["IDENTITY_NFT_ADDRESS"] = "0x0000000000000000000000000000000000000001"
os.environ["RESONANCE_SCORE_ADDRESS"] = "0x0000000000000000000000000000000000000002"
os.environ["RESONANCE_REGISTRY_ADDRESS"] = "0x0000000000000000000000000000000000000003"
os.environ["CORS_ORIGINS"] = "*"
os.environ["PUBLIC_URL"] = "http://testserver"
os.environ["TELEGRAM_BOT_TOKEN"] = ""


# ---------------------------------------------------------------------------
# 2) Stub heavy production modules BEFORE `import server`.
# ---------------------------------------------------------------------------
def _make_web3_service_stub() -> types.ModuleType:
    mod = types.ModuleType("web3_service")

    calls: dict[str, list] = {
        "has_identity_nft": [],
        "get_identity_token_id": [],
        "mint_identity_nft": [],
        "record_interaction": [],
        "get_blockchain_score": [],
        "get_user_interactions": [],
        "get_profile_data": [],
        "has_profile_nft": [],
        "mint_profile_nft": [],
        "set_profile_visibility": [],
        "burn_profile_nft": [],
        "increment_metadata_nonce": [],
        "get_profile_total_supply": [],
        "is_backend_delegate": [],
    }

    class _Web3ServiceStub:
        MOCK = True

        def __init__(self) -> None:
            self.resonance_registry = MagicMock(name="resonance_registry_MOCK")
            self.resonance_score = MagicMock(name="resonance_score_MOCK")
            self.identity_nft = MagicMock(name="identity_nft_MOCK")
            self.account = None
            self.calls = calls

        async def has_identity_nft(self, address):
            calls["has_identity_nft"].append(address)
            return False  # default: user has no NFT on-chain

        async def get_identity_token_id(self, address):
            calls["get_identity_token_id"].append(address)
            return None

        async def mint_identity_nft(self, address):
            calls["mint_identity_nft"].append(address)
            return True, {"tx_hash": "0xMOCK_MINT_TX", "status": "success"}

        async def record_interaction(self, initiator, responder,
                                     interaction_type, metadata=""):
            calls["record_interaction"].append(
                dict(initiator=initiator, responder=responder,
                     interaction_type=interaction_type, metadata=metadata)
            )
            return True, {"tx_hash": "0xMOCK_INTERACTION_TX",
                          "status": "success", "block_number": 1,
                          "gas_used": 21000,
                          "basescan_url": "mock://tx/0xMOCK_INTERACTION_TX"}

        async def get_blockchain_score(self, address):
            calls["get_blockchain_score"].append(address)
            return 50

        async def get_user_interactions(self, address, offset=0, limit=10):
            calls["get_user_interactions"].append((address, offset, limit))
            return []

        async def get_profile_data(self, address):
            calls["get_profile_data"].append(address); return None

        async def has_profile_nft(self, address):
            calls["has_profile_nft"].append(address); return False

        async def mint_profile_nft(self, address):
            calls["mint_profile_nft"].append(address)
            return True, {"tx_hash": "0xMOCK_PROFILE_MINT", "status": "success"}

        async def set_profile_visibility(self, token_id, is_public):
            calls["set_profile_visibility"].append((token_id, is_public))
            return True, {"tx_hash": "0xMOCK"}

        async def burn_profile_nft(self, token_id):
            calls["burn_profile_nft"].append(token_id)
            return True, {"tx_hash": "0xMOCK"}

        async def increment_metadata_nonce(self, token_id):
            calls["increment_metadata_nonce"].append(token_id)
            return True, {"tx_hash": "0xMOCK"}

        async def get_profile_total_supply(self):
            calls["get_profile_total_supply"].append(True); return 0

        async def is_backend_delegate(self, token_id):
            calls["is_backend_delegate"].append(token_id); return False

    mod.web3_service = _Web3ServiceStub()
    mod.Web3Service = _Web3ServiceStub
    mod._MOCK_CALLS = calls
    return mod


def _make_blockchain_sync_stub() -> types.ModuleType:
    mod = types.ModuleType("blockchain_sync")

    async def sync_score_after_update(address, score, conn=None):  # noqa: D401
        return {"synced": False, "mock": True}

    async def force_sync_on_login(address, score):
        return {"synced": False, "mock": True}

    async def start_sync_queue_processor():
        return None

    async def add_to_sync_queue(*a, **kw):
        return None

    def should_sync_score(*a, **kw):
        return False

    mod.sync_score_after_update = sync_score_after_update
    mod.force_sync_on_login = force_sync_on_login
    mod.start_sync_queue_processor = start_sync_queue_processor
    mod.add_to_sync_queue = add_to_sync_queue
    mod.should_sync_score = should_sync_score
    mod.sync_queue = []
    return mod


def _make_telegram_stub() -> types.ModuleType:
    mod = types.ModuleType("telegram_bot_service")
    tb = MagicMock(name="telegram_bot_MOCK")
    tb.is_configured = False
    mod.telegram_bot = tb
    mod.create_one_time_telegram_invite = AsyncMock(
        return_value=(False, "mock: disabled"))
    mod.check_bot_setup = AsyncMock(
        return_value={"configured": False, "mock": True})
    mod.create_one_time_telegram_invite_with_capabilities = AsyncMock(
        return_value=(False, "mock: disabled"))
    return mod


def _make_discord_stub() -> types.ModuleType:
    mod = types.ModuleType("discord_bot_service")
    mod.discord_bot = MagicMock(name="discord_bot_MOCK")
    mod.create_one_time_discord_invite = AsyncMock(
        return_value=(False, "mock: disabled"))
    mod.check_discord_bot_setup = AsyncMock(
        return_value={"configured": False, "mock": True})
    return mod


def _make_gate_stub() -> types.ModuleType:
    mod = types.ModuleType("gate_service")
    mod.init_gate_service = lambda *_a, **_kw: None
    mod.get_gate_service = lambda: None

    class GateService:  # noqa: D401
        pass
    mod.GateService = GateService
    return mod


# ---------------------------------------------------------------------------
# 3) Inject stubs before importing server.  The order matters!
# ---------------------------------------------------------------------------
sys.modules["web3_service"] = _make_web3_service_stub()
sys.modules["blockchain_sync"] = _make_blockchain_sync_stub()
sys.modules["telegram_bot_service"] = _make_telegram_stub()
sys.modules["discord_bot_service"] = _make_discord_stub()
sys.modules["gate_service"] = _make_gate_stub()

# Make `aeralogin` package importable via sys.path
sys.path.insert(0, str(_REPO_DIR))

# Now safe to import the production `server` module.
import server as _server  # noqa: E402


# ---------------------------------------------------------------------------
# 4) One-time DB migration: add columns not created by init_db but referenced
#    later in production (identity_status, identity_nft_token_id,
#    pending_bonus, ...). Production DB has them added by external migration
#    scripts; the fresh test DB must match the runtime schema.
# ---------------------------------------------------------------------------
def _augment_schema() -> None:
    conn = _server.get_db_connection()
    cur = conn.cursor()
    for col, ddl in [
        ("identity_status", "TEXT DEFAULT 'pending'"),
        ("identity_nft_token_id", "INTEGER"),
        ("identity_mint_tx_hash", "TEXT"),
        ("identity_minted_at", "TEXT"),
        ("pending_bonus", "INTEGER DEFAULT 0"),
    ]:
        try:
            cur.execute(f"ALTER TABLE users ADD COLUMN {col} {ddl}")
        except Exception:
            pass  # already present
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# 5) Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def server_module():
    """Return the imported production server module (with mocks in place)."""
    _server.init_db()
    _augment_schema()
    return _server


@pytest.fixture()
def client(server_module):
    """FastAPI TestClient bound to the (mocked) production app."""
    from fastapi.testclient import TestClient
    with TestClient(server_module.app) as tc:
        yield tc


@pytest.fixture()
def db(server_module):
    """Fresh cursor per test; wipes user/oauth tables between tests."""
    conn = server_module.get_db_connection()
    cur = conn.cursor()
    for table in ("users", "events", "airdrops", "followers",
                  "oauth_codes", "oauth_sessions", "oauth_clients",
                  "telegram_invites", "community_redirect_tokens"):
        try:
            cur.execute(f"DELETE FROM {table}")
        except Exception:
            pass
    conn.commit()
    yield conn
    conn.close()


@pytest.fixture()
def eth_test_account():
    """Deterministic EOA for signing tests. Test-only key, obviously."""
    from eth_account import Account
    # Well-known Anvil/Hardhat test key #0 – funded on no real chain.
    priv = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    acct = Account.from_key(priv)
    return acct


@pytest.fixture()
def eth_second_account():
    from eth_account import Account
    priv = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
    return Account.from_key(priv)


# ---------------------------------------------------------------------------
# 6) Cleanup
# ---------------------------------------------------------------------------
def pytest_sessionfinish(session, exitstatus):  # noqa: D401
    try:
        _TMP_DB_PATH.unlink(missing_ok=True)
    except Exception:
        pass
