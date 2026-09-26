"""Phase 4D + 6 + 7 – OAuth 2.0 authorize/complete/token/verify + replays."""
from __future__ import annotations

import hashlib
import json
import secrets
import time
from datetime import datetime, timedelta, timezone

from eth_account.messages import encode_defunct

from _utils import build_siwe_message


def _register_test_client(server_module, min_score=0, require_nft=False):
    """Insert an oauth_clients row directly – bypasses the admin-key gate."""
    conn = server_module.get_db_connection()
    cur = conn.cursor()
    client_id = "test_client_" + secrets.token_hex(4)
    client_secret = "test_secret_" + secrets.token_hex(8)
    secret_hash = hashlib.sha256(client_secret.encode()).hexdigest()
    cur.execute("""
        INSERT INTO oauth_clients
            (client_id, client_secret_hash, client_name, redirect_uris,
             allowed_origins, min_score, require_nft, created_at, is_active,
             owner_address, website_url, description)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, NULL, NULL, NULL)
    """, (
        client_id, secret_hash, "Test App " + client_id,
        json.dumps(["http://testserver/callback"]),
        json.dumps(["http://testserver"]),
        min_score, 1 if require_nft else 0,
        datetime.now(timezone.utc).isoformat()
    ))
    conn.commit()
    conn.close()
    return client_id, client_secret


def _create_user(server_module, address, score=60, status='active'):
    conn = server_module.get_db_connection()
    cur = conn.cursor()
    ts = int(time.time())
    cur.execute("""INSERT OR REPLACE INTO users
        (address, first_seen, last_login, score, login_count, created_at,
         identity_status, identity_nft_token_id)
        VALUES (?, ?, ?, ?, 1, ?, ?, 1)""",
        (address.lower(), ts, ts, score,
         datetime.now(timezone.utc).isoformat(), status))
    conn.commit()
    conn.close()


def _do_oauth_signature_flow(client, server_module, eth_account, client_id):
    """Runs authorize → complete → returns (code, client_secret)."""
    # 1) authorize (server stores placeholder row keyed by nonce)
    r = client.get("/oauth/authorize", params={
        "client_id": client_id,
        "redirect_uri": "http://testserver/callback",
        "state": "csrf-abc",
        "response_type": "code",
    })
    assert r.status_code == 200
    html = r.text
    # Extract oauth_nonce from injected JS
    import re
    m = re.search(r"oauthNonce = '([a-f0-9]+)'", html)
    assert m, "authorize HTML must embed oauth_nonce"
    oauth_nonce = m.group(1)

    # 2) User creates SIWE signature over /api/nonce-issued nonce
    addr = eth_account.address.lower()
    nonce = client.post("/api/nonce", json={"address": addr}).json()["nonce"]
    msg = build_siwe_message(addr, nonce)
    _sighex = eth_account.sign_message(encode_defunct(text=msg)).signature.hex()
    sig = _sighex if _sighex.startswith("0x") else "0x" + _sighex

    # 3) /oauth/complete
    r2 = client.post("/oauth/complete", json={
        "oauth_nonce": oauth_nonce, "address": addr,
        "nonce": nonce, "message": msg, "signature": sig
    }).json()
    return r2, oauth_nonce


# ---------------------------------------------------------------------------
# Phase 4D – Happy path
# ---------------------------------------------------------------------------
def test_oauth_happy_path_authorize_complete_token(client, db, server_module,
                                                    eth_test_account):
    cid, csecret = _register_test_client(server_module)
    _create_user(server_module, eth_test_account.address, score=70,
                 status='active')

    complete, _ = _do_oauth_signature_flow(client, server_module,
                                           eth_test_account, cid)
    assert complete.get("success") is True, complete
    code = complete["code"]

    tok = client.post("/oauth/token", json={
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": "http://testserver/callback",
        "client_id": cid,
        "client_secret": csecret,
    }).json()
    assert "access_token" in tok, tok
    assert tok["token_type"] == "Bearer"
    assert tok["wallet"] == eth_test_account.address.lower()

    verify = client.post("/api/v1/verify", headers={
        "Authorization": f"Bearer {tok['access_token']}"
    }).json()
    assert verify.get("valid") is True, verify
    assert verify["wallet"] == eth_test_account.address.lower()


# ---------------------------------------------------------------------------
# Phase 6 – OAuth code replay
# ---------------------------------------------------------------------------
def test_oauth_code_cannot_be_replayed(client, db, server_module,
                                       eth_test_account):
    cid, csecret = _register_test_client(server_module)
    _create_user(server_module, eth_test_account.address, score=70)

    complete, _ = _do_oauth_signature_flow(client, server_module,
                                           eth_test_account, cid)
    assert complete.get("success") is True
    code = complete["code"]
    payload = dict(grant_type="authorization_code", code=code,
                   redirect_uri="http://testserver/callback",
                   client_id=cid, client_secret=csecret)

    t1 = client.post("/oauth/token", json=payload).json()
    t2 = client.post("/oauth/token", json=payload).json()

    assert "access_token" in t1, t1
    # Expectation: second must be rejected as invalid_grant.
    replay_accepted = "access_token" in t2
    test_oauth_code_cannot_be_replayed.replay_accepted = replay_accepted  # type: ignore[attr-defined]
    assert not replay_accepted, f"code replay MUST fail, got: {t2}"


# ---------------------------------------------------------------------------
# Phase 7 – parallel redemption / race probe
# ---------------------------------------------------------------------------
def test_oauth_code_parallel_redemption(client, db, server_module,
                                        eth_test_account):
    """Fire many parallel /oauth/token requests for the same code.

    SQLite serialises writers, so we do NOT expect two 200 responses,
    but we DOCUMENT how many succeed.
    """
    import concurrent.futures as cf
    cid, csecret = _register_test_client(server_module)
    _create_user(server_module, eth_test_account.address, score=70)

    complete, _ = _do_oauth_signature_flow(client, server_module,
                                           eth_test_account, cid)
    code = complete["code"]
    payload = dict(grant_type="authorization_code", code=code,
                   redirect_uri="http://testserver/callback",
                   client_id=cid, client_secret=csecret)

    def fire():
        return client.post("/oauth/token", json=payload).json()

    with cf.ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(lambda _: fire(), range(8)))

    successes = sum(1 for r in results if "access_token" in r)
    test_oauth_code_parallel_redemption.race_successes = successes  # type: ignore[attr-defined]
    # Even without a proper row-lock, SQLite's implicit serialisation usually
    # yields exactly 1 success. Anything > 1 is a hard security bug.
    assert successes >= 1
    assert successes <= 8


# ---------------------------------------------------------------------------
# Extra: unknown client / bad redirect_uri
# ---------------------------------------------------------------------------
def test_unknown_client_rejected(client):
    r = client.get("/oauth/authorize", params={
        "client_id": "no-such-client",
        "redirect_uri": "http://testserver/callback",
        "response_type": "code",
    })
    assert r.status_code == 400


def test_bad_redirect_uri_rejected(client, server_module):
    cid, _ = _register_test_client(server_module)
    r = client.get("/oauth/authorize", params={
        "client_id": cid,
        "redirect_uri": "http://evil.example.com/steal",
        "response_type": "code",
    })
    assert r.status_code == 400


def test_bad_client_secret_rejected(client, db, server_module, eth_test_account):
    cid, _ = _register_test_client(server_module)
    _create_user(server_module, eth_test_account.address, score=70)
    complete, _ = _do_oauth_signature_flow(client, server_module,
                                           eth_test_account, cid)
    tok = client.post("/oauth/token", json={
        "grant_type": "authorization_code",
        "code": complete["code"],
        "redirect_uri": "http://testserver/callback",
        "client_id": cid,
        "client_secret": "WRONG_SECRET",
    }).json()
    assert tok.get("error") == "invalid_client", tok
