"""Offline fixtures: a fake AEra directory service so that phases 1-4 run
without touching production."""
from __future__ import annotations

import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.identity.aera_client import AeraIdentityClient  # noqa: E402


class FakeDirectory:
    """Minimal stand-in for `GET /api/agents/{agent_id}` only.

    Nothing security relevant is faked: signature verification, canonical JSON
    and content hashing all use the real production primitives. This fixture
    exists purely so the offline phases do not need network access.
    """

    def __init__(self) -> None:
        self.agents: dict[str, dict] = {}

    def add(self, ident: AeraIdentityClient, *, status: str = "active",
            key_status: str = "active") -> None:
        self.agents[ident.agent_id] = {
            "agent_id": ident.agent_id,
            "owner_wallet": ident.owner_wallet,
            "status": status,
            "label": None,
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
            "keys": [{"key_id": ident.key_id, "algorithm": "Ed25519",
                      "public_key": ident.public_key, "status": key_status}],
        }

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.startswith("/api/agents/"):
            agent_id = path[len("/api/agents/"):]
            data = self.agents.get(agent_id)
            if data is None:
                return httpx.Response(404, json={"detail": {"agent_error": "unknown_agent"}})
            return httpx.Response(200, json=data)
        return httpx.Response(404, json={"detail": {"agent_error": "unknown_agent"}})


@pytest.fixture
def directory() -> FakeDirectory:
    return FakeDirectory()


@pytest.fixture
def http(directory: FakeDirectory) -> httpx.Client:
    return httpx.Client(base_url="https://fake.invalid",
                        transport=httpx.MockTransport(directory.handler))


def _make(http: httpx.Client, directory: FakeDirectory, name: str, n: int) -> AeraIdentityClient:
    ident = AeraIdentityClient(http, name=name)
    ident.agent_id = f"did:aera:agent:{str(n) * 32}"
    ident.key_id = f"aera-key-{str(n) * 24}"
    ident.capabilities = ["agent.authenticate", "agent.communicate"]
    directory.add(ident)
    return ident


@pytest.fixture
def ident_a(http, directory) -> AeraIdentityClient:
    return _make(http, directory, "AgentA", 1)


@pytest.fixture
def ident_b(http, directory) -> AeraIdentityClient:
    return _make(http, directory, "AgentB", 2)


@pytest.fixture
def ident_c(http, directory) -> AeraIdentityClient:
    return _make(http, directory, "AgentC", 3)
