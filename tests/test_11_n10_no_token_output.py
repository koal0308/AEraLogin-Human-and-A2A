"""
N10 - no OAuth access-token material on stdout / stderr / journal.

Historically /oauth/token printed a debug block containing the first 30
characters of the issued JWT (header + start of payload) plus every response
field. systemd captured that in the journal.

These tests capture stdout AND stderr around a real token issuance and assert
that no credential material appears - while proving the endpoint still works
exactly as before.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
import time
from datetime import datetime, timezone

import jwt
import pytest
from eth_account import Account
from eth_account.messages import encode_defunct

from _utils import build_siwe_message


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _register_client(server_module):
    conn = server_module.get_db_connection()
    cur = conn.cursor()
    cid = "n10_client_" + secrets.token_hex(4)
    csec = "n10_secret_" + secrets.token_hex(8)
    cur.execute(
        """
        INSERT INTO oauth_clients
            (client_id, client_secret_hash, client_name, redirect_uris,
             allowed_origins, min_score, require_nft, created_at, is_active,
             owner_address, website_url, description)
        VALUES (?, ?, ?, ?, ?, 0, 0, ?, 1, NULL, NULL, NULL)
        """,
        (cid, hashlib.sha256(csec.encode()).hexdigest(), "N10 Test App",
         json.dumps(["http://testserver/callback"]),
         json.dumps(["http://testserver"]),
         datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()
    conn.close()
    return cid, csec


def _issue_code(client, server_module, cid):
    """Drive authorize -> complete via the REAL flow and return (code, addr).

    Mirrors tests/test_04_oauth_flow.py::_do_oauth_signature_flow so this
    suite exercises exactly the production path.
    """
    acct = Account.create()
    addr = acct.address.lower()

    conn = server_module.get_db_connection()
    cur = conn.cursor()
    ts = int(time.time())
    cur.execute(
        """INSERT OR REPLACE INTO users
           (address, first_seen, last_login, score, login_count, created_at,
            identity_status, identity_nft_token_id)
           VALUES (?, ?, ?, 60, 1, ?, 'active', 1)""",
        (addr, ts, ts, datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()
    conn.close()

    r = client.get("/oauth/authorize", params={
        "client_id": cid,
        "redirect_uri": "http://testserver/callback",
        "state": "n10-state",
        "response_type": "code",
    })
    assert r.status_code == 200
    m = re.search(r"oauthNonce = '([a-f0-9]+)'", r.text)
    assert m, "authorize HTML must embed oauth_nonce"
    oauth_nonce = m.group(1)

    nonce = client.post("/api/nonce", json={"address": addr}).json()["nonce"]
    msg = build_siwe_message(addr, nonce)
    sighex = acct.sign_message(encode_defunct(text=msg)).signature.hex()
    sig = sighex if sighex.startswith("0x") else "0x" + sighex

    body = client.post("/oauth/complete", json={
        "oauth_nonce": oauth_nonce, "address": addr,
        "nonce": nonce, "message": msg, "signature": sig,
    }).json()
    assert body.get("success") is True, body
    return body["code"], addr


_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{8,}")


def _scan(captured_out, captured_err, *forbidden):
    """Return every credential-ish hit found in captured output."""
    blob = (captured_out or "") + "\n" + (captured_err or "")
    hits = []
    if "eyJ" in blob:
        hits.append("jwt-prefix 'eyJ'")
    if _JWT_RE.search(blob):
        hits.append("jwt-like token")
    if "Bearer " in blob:
        hits.append("'Bearer '")
    for f in forbidden:
        if f and f in blob:
            hits.append("literal credential")
        # also catch truncated echoes like value[:30]
        if f and len(f) >= 30 and f[:30] in blob:
            hits.append("credential prefix (30 chars)")
    return hits


# ==========================================================================
# 1-4: success path
# ==========================================================================
def test_oauth_token_success_emits_no_credential_output(
    client, server_module, capfd
):
    cid, csec = _register_client(server_module)
    code, addr = _issue_code(client, server_module, cid)
    capfd.readouterr()  # drop setup noise

    r = client.post("/oauth/token", json={
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": "http://testserver/callback",
        "client_id": cid,
        "client_secret": csec,
    })
    out, err = capfd.readouterr()
    body = r.json()

    # (2) issuance still works
    token = body.get("access_token")
    assert token, body
    assert body.get("token_type") == "Bearer"
    assert body.get("expires_in") == server_module.OAUTH_TOKEN_EXPIRY_HOURS * 3600
    assert body.get("wallet", "").lower() == addr.lower()

    # (1)(6)(7) nothing sensitive on stdout/stderr
    assert _scan(out, err, token, code, csec) == [], (
        f"credential material leaked to stdout/stderr: {_scan(out, err, token, code, csec)}"
    )


def test_issued_token_still_verifies(client, server_module):
    """(3)(4) response contract and verification are unchanged."""
    cid, csec = _register_client(server_module)
    code, addr = _issue_code(client, server_module, cid)

    body = client.post("/oauth/token", json={
        "grant_type": "authorization_code", "code": code,
        "redirect_uri": "http://testserver/callback",
        "client_id": cid, "client_secret": csec,
    }).json()
    token = body["access_token"]

    payload = jwt.decode(token, server_module.OAUTH_JWT_SECRET,
                         algorithms=["HS256"], audience=cid)
    assert payload["iss"] == server_module.OAUTH_EXPECTED_ISSUER
    assert payload["aud"] == cid
    assert payload["sub"].lower() == addr.lower()

    v = client.post("/api/v1/verify",
                    headers={"Authorization": f"Bearer {token}"}).json()
    assert v.get("valid") is True
    assert v.get("wallet", "").lower() == addr.lower()


def test_response_field_set_unchanged(client, server_module):
    """(3) removing the debug block must not alter the response body."""
    cid, csec = _register_client(server_module)
    code, _ = _issue_code(client, server_module, cid)
    body = client.post("/oauth/token", json={
        "grant_type": "authorization_code", "code": code,
        "redirect_uri": "http://testserver/callback",
        "client_id": cid, "client_secret": csec,
    }).json()
    assert set(body) == {"access_token", "token_type", "expires_in",
                         "wallet", "score", "has_nft"}


# ==========================================================================
# 5: failure paths
# ==========================================================================
@pytest.mark.parametrize("broken", ["secret", "code", "redirect"])
def test_oauth_token_failure_paths_emit_no_credentials(
    client, server_module, capfd, broken
):
    cid, csec = _register_client(server_module)
    code, _ = _issue_code(client, server_module, cid)
    capfd.readouterr()

    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": "http://testserver/callback",
        "client_id": cid,
        "client_secret": csec,
    }
    if broken == "secret":
        form["client_secret"] = "wrong-secret-value"
    elif broken == "code":
        form["code"] = "definitely-not-a-valid-code"
    else:
        form["redirect_uri"] = "http://evil.example/callback"

    r = client.post("/oauth/token", json=form)
    out, err = capfd.readouterr()

    assert "access_token" not in r.json()
    assert _scan(out, err, code, csec) == []


# ==========================================================================
# 6-7: explicit stdout/stderr scan
# ==========================================================================
def test_no_jwt_prefix_or_code_on_stdout_during_full_flow(
    client, server_module, capfd
):
    cid, csec = _register_client(server_module)
    capfd.readouterr()
    code, _ = _issue_code(client, server_module, cid)
    token = client.post("/oauth/token", json={
        "grant_type": "authorization_code", "code": code,
        "redirect_uri": "http://testserver/callback",
        "client_id": cid, "client_secret": csec,
    }).json()["access_token"]
    client.post("/api/v1/verify", headers={"Authorization": f"Bearer {token}"})
    out, err = capfd.readouterr()

    blob = out + err
    assert "eyJ" not in blob, "JWT prefix reached stdout/stderr"
    assert code not in blob, "authorization code reached stdout/stderr"
    assert csec not in blob, "client secret reached stdout/stderr"
    assert "Bearer " not in blob


# ==========================================================================
# source-level regression guard
# ==========================================================================
def test_source_has_no_token_printing():
    """Guard against a future debug block re-appearing."""
    import pathlib

    src = pathlib.Path(__file__).resolve().parent.parent / "server.py"
    text = src.read_text(encoding="utf-8")

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("print("):
            continue
        lowered = stripped.lower()
        for bad in ("access_token", "token_response", "client_secret",
                    "bearer", "authorization"):
            assert bad not in lowered, f"suspicious print(): {stripped[:80]}"

    assert "/oauth/token RESPONSE" not in text, (
        "the N10 debug block has been re-introduced"
    )
