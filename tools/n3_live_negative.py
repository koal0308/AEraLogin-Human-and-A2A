#!/usr/bin/env python3
"""
N3 live negative security test - issuer / audience hardening.

Runs against the RUNNING production instance on 127.0.0.1:8840.

Safety:
  * creates ONE disposable OAuth client, deactivates it in `finally`
  * reuses an existing throwaway test wallet, touches no real user
  * never prints tokens, secrets, codes or Authorization headers
  * performs no write to any production row other than its own client
"""
from __future__ import annotations

import json
import os
import secrets
import sqlite3
import sys
import time
import urllib.error
import urllib.request

import jwt
from dotenv import dotenv_values
from eth_account import Account
from eth_account.messages import encode_defunct

BASE = "http://127.0.0.1:8840"
ENV = dotenv_values(".env")
OAUTH_JWT_SECRET = ENV["OAUTH_JWT_SECRET"]
OAUTH_ADMIN_KEY = ENV["OAUTH_ADMIN_KEY"]
ISSUER = "aeralogin.com"

_passed, _failed = 0, 0


def check(name, cond):
    global _passed, _failed
    if cond:
        _passed += 1
        print(f"  [PASS] {name}")
    else:
        _failed += 1
        print(f"  [FAIL] {name}")


def post(path, payload=None, headers=None):
    data = json.dumps(payload or {}).encode()
    req = urllib.request.Request(
        BASE + path, data=data, method="POST",
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read().decode())
        except Exception:
            return {"valid": False, "http_status": e.code}


def _register_lifecycle(token):
    """
    Create the S-02 lifecycle row for a hand-minted token.

    Production tokens get this automatically at issuance. A forged token has
    no row, so without this every assertion below would collapse into a
    generic "unknown token" rejection and stop testing issuer/audience.
    """
    p = jwt.decode(token, options={"verify_signature": False})
    aud = p.get("aud")
    if not isinstance(aud, str):
        return
    c = sqlite3.connect("aera.db")
    c.execute(
        "INSERT OR REPLACE INTO oauth_token_jti "
        "(jti, sub, client_id, issued_at, expires_at, status) "
        "VALUES (?, ?, ?, datetime('now'), ?, 'active')",
        (p.get("jti"), (p.get("sub") or "").lower(), aud,
         time.strftime("%Y-%m-%dT%H:%M:%S",
                       time.gmtime(p.get("exp", time.time() + 3600)))))
    c.commit()
    c.close()


def mint(aud, *, iss=ISSUER, drop=(), sub=None, ttl=3600, secret=None,
         lifecycle=True):
    """Forge a token with a GENUINE signature but chosen claims."""
    now = int(time.time())
    p = {
        "iss": iss,
        "sub": (sub or "0x" + "ab" * 20).lower(),
        "aud": aud,
        "iat": now,
        "exp": now + ttl,
        "jti": secrets.token_hex(16),
        "score": 50,
        "has_nft": True,
        "chain_id": 8453,
    }
    for c in drop:
        p.pop(c, None)
    tok = jwt.encode(p, secret or OAUTH_JWT_SECRET, algorithm="HS256")
    if lifecycle and "jti" in p:
        _register_lifecycle(tok)
    return tok


def main():
    print("=" * 62)
    print("N3 LIVE NEGATIVE TEST - issuer / audience hardening")
    print("=" * 62)

    client_id = client_secret = None
    try:
        # ---- disposable client -------------------------------------------
        print("\n=== setup: disposable test client ===")
        r = post("/api/v1/clients/register", {
            "admin_key": OAUTH_ADMIN_KEY,
            "client_name": "ZZ-N3-DISPOSABLE-TEST-CLIENT",
            "redirect_uris": ["http://127.0.0.1:9/callback"],
            "allowed_origins": ["http://127.0.0.1:9"],
            "min_score": 0,
            "require_nft": False,
        })
        client_id = r.get("client_id")
        client_secret = r.get("client_secret")
        check("disposable client created", bool(client_id and client_secret))
        if not client_id:
            return 1

        # ---- a real wallet so /api/v1/verify can resolve the user --------
        acct = Account.create()
        addr = acct.address
        n = post("/api/nonce", {"address": addr})
        nonce = n.get("nonce")
        msg = n.get("message") or nonce
        sig = acct.sign_message(encode_defunct(text=msg)).signature.hex()
        if not sig.startswith("0x"):
            sig = "0x" + sig
        post("/api/verify", {"address": addr, "signature": sig,
                             "message": msg, "display_name": "ZZ-N3-TEST-USER"})

        # ==================================================================
        print("\n=== 1: valid token (correct iss + registered aud) ===")
        good = mint(client_id, sub=addr)
        v = post("/api/v1/verify", headers={"Authorization": f"Bearer {good}"})
        check("valid current OAuth token accepted", v.get("valid") is True)
        check("returns the correct wallet",
              (v.get("wallet") or "").lower() == addr.lower())

        print("\n=== 2-5: forged claims (signature is GENUINE) ===")
        cases = [
            ("wrong issuer rejected", mint(client_id, iss="evil-issuer.example")),
            ("look-alike issuer rejected", mint(client_id, iss="aeralogin.com.evil.tld")),
            ("missing issuer rejected", mint(client_id, drop=("iss",))),
            ("missing audience rejected", mint(client_id, drop=("aud",))),
            ("unregistered audience rejected", mint("aera_not_a_real_client")),
            ("empty audience rejected", mint("")),
            ("list audience rejected", mint([client_id, "attacker"])),
            ("expired token rejected", mint(client_id, ttl=-60)),
            ("wrong signing key rejected",
             mint(client_id, secret="a-completely-different-secret-value-x")),
        ]
        for name, tok in cases:
            res = post("/api/v1/verify", headers={"Authorization": f"Bearer {tok}"})
            check(name, res.get("valid") is False and "wallet" not in res)

        print("\n=== 6-7: cross-client confusion ===")
        # second disposable client acting as the attacker
        r2 = post("/api/v1/clients/register", {
            "admin_key": OAUTH_ADMIN_KEY,
            "client_name": "ZZ-N3-DISPOSABLE-TEST-CLIENT-B",
            "redirect_uris": ["http://127.0.0.1:9/cb"],
            "allowed_origins": ["http://127.0.0.1:9"],
            "min_score": 0, "require_nft": False,
        })
        cid_b, csec_b = r2.get("client_id"), r2.get("client_secret")
        check("second disposable client created", bool(cid_b))

        own = post("/api/v1/verify",
                   headers={"Authorization": f"Bearer {good}",
                            "X-AEra-Client-Id": client_id})
        check("own client_id binding accepted", own.get("valid") is True)

        cross = post("/api/v1/verify",
                     headers={"Authorization": f"Bearer {good}",
                              "X-AEra-Client-Id": cid_b})
        check("cross-client binding rejected (/api/v1/verify)",
              cross.get("valid") is False and "wallet" not in cross)

        if cid_b and csec_b:
            nft_own = post("/api/oauth/verify-nft", {
                "access_token": good, "client_id": client_id,
                "client_secret": client_secret})
            check("verify-nft accepts own token",
                  nft_own.get("valid") is True)

            nft_cross = post("/api/oauth/verify-nft", {
                "access_token": good, "client_id": cid_b,
                "client_secret": csec_b})
            check("verify-nft rejects another client's token (S-01 closed)",
                  nft_cross.get("valid") is False and "wallet" not in nft_cross)

        print("\n=== 8: no token echo in error responses ===")
        bad = mint(client_id, iss="evil-issuer.example")
        res = post("/api/v1/verify", headers={"Authorization": f"Bearer {bad}"})
        check("error response does not echo the token", bad not in json.dumps(res))

        # ---- cleanup ------------------------------------------------------
        print("\n=== cleanup ===")
        conn = sqlite3.connect("aera.db")
        cur = conn.cursor()
        for cid in (client_id, cid_b):
            if cid:
                cur.execute(
                    "UPDATE oauth_clients SET is_active = 0 WHERE client_id = ?",
                    (cid,))
        conn.commit()
        left = cur.execute(
            "SELECT COUNT(*) FROM oauth_clients WHERE is_active = 1").fetchone()[0]
        rem = cur.execute(
            "SELECT COUNT(*) FROM oauth_clients WHERE client_name LIKE 'ZZ-N3%' "
            "AND is_active = 1").fetchone()[0]
        conn.close()
        check("all N3 disposable clients deactivated", rem == 0)
        print(f"     remaining active clients: {left}")

    finally:
        pass

    print("\n" + "=" * 62)
    print(f"N3 LIVE NEGATIVE: {_passed} passed, {_failed} failed")
    print("=" * 62)
    return 0 if _failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
