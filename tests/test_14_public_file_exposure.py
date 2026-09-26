"""Regression: /static and /docs serve explicit allowlists only.

`/static` used to mount the whole project directory (.env, aera.db, sources).
"""
from __future__ import annotations

import pytest

FORBIDDEN = [
    "/static/.env", "/static/aera.db", "/static/server.py",
    "/static/agent/tokens.py", "/static/requirements.txt", "/static/.git/config",
    "/static/%2e%2e/.env", "/static/..%2f.env",
    "/docs/SYSTEM_ANALYSIS.md", "/docs/SDK_BUTTON_LINK.md",
    "/docs/../.env", "/docs/..%2f.env", "/docs/%2e%2e/server.py",
    "/docs/assets/../../.env", "/docs/assets/../SYSTEM_ANALYSIS.md",
    "/docs/sub/dir/x.html",
]

ALLOWED = [
    "/static/aera-agents.js", "/static/aera-agent-enroll.js",
    "/docs/agent-api.html", "/docs/a2a.html", "/docs/assets/docs.css",
    "/docs/AGENT_IDENTITY.md", "/docs/A2A_PEER_CREDENTIALS.md",
]


@pytest.mark.parametrize("path", FORBIDDEN)
def test_private_files_are_not_served(client, path):
    r = client.get(path)
    assert r.status_code == 404, f"{path} -> {r.status_code}"
    assert "SECRET" not in r.text and "PRIVATE_KEY" not in r.text


@pytest.mark.parametrize("path", ALLOWED)
def test_public_files_are_served(client, path):
    r = client.get(path)
    assert r.status_code == 200, f"{path} -> {r.status_code}"
