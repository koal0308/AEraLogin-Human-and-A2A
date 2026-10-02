"""Agent Layer test env – enables the layer and provides fixtures.

Runs after root conftest. Reuses the shared `client` fixture, but ensures
the agent router is mounted (server.py's startup only mounts when the
env flag is true; we set it here BEFORE the app boots by loading conftest
early through pytest's plugin order – tests/conftest.py sets DATABASE_PATH).
"""
from __future__ import annotations

import os
import secrets

# Set env flags BEFORE server has its startup called.
os.environ.setdefault("AGENT_LAYER_ENABLED", "true")
os.environ.setdefault("AGENT_JWT_SECRET",
                      "TEST-ONLY-agent-secret-" + secrets.token_hex(24))

import pytest


@pytest.fixture(scope="session", autouse=True)
def _init_agent_schema(server_module):
    """Ensure agent tables + router exist even if startup ran before flag was set."""
    from agent import repository as _repo
    from agent import routes as _routes
    _repo.init_schema()
    if not any(getattr(r, "path", "").startswith("/api/agents")
               for r in server_module.app.routes):
        server_module.app.include_router(_routes.router)
    yield


@pytest.fixture()
def wipe_agent_tables(server_module):
    """Truncate agent tables before each test."""
    from agent import repository as _repo
    conn = _repo.get_connection()
    try:
        for t in ("agent_audit_log", "agent_interactions", "agent_message_ids",
                  "agent_jti", "owner_challenges", "agent_challenges",
                  "agent_keys", "agents", "agent_rate_limits", "agent_enrollments",
                  "human_identity_providers", "human_identities"):
            try:
                conn.execute(f"DELETE FROM {t}")
            except Exception:
                pass
        conn.commit()
    finally:
        conn.close()
    yield
