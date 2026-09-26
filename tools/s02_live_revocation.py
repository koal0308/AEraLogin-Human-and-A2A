#!/usr/bin/env python3
"""
S-02 live revocation test against the RUNNING production instance.

Safety:
  * one disposable OAuth client + one throwaway wallet, both cleaned up
  * only touches lifecycle rows belonging to its own token
  * never prints tokens, secrets, codes or Authorization headers
"""
from __future__ import annotations

import json
import sqlite3
import sys
import urllib.error
import urllib.request

import jwt
from dotenv import dotenv_values
from eth_account import Account
from eth_account.messages import encode_defunct

BASE = "http://127.0.0.1:8840"
ENV = dotenv_values(".env")
ADMIN = ENV["OAUTH_ADMIN_KEY"]

_p, _f = 0, 0


def check(name, cond):
    global _p, _f
    if cond:
        _p += 1
        print(f"  [PASS] {name}")
    else:
        _f += 1
        print(f"  [FAIL] {name}")


def post(path, payload=None, headers=None):
    req = urllib.request.Request(
        BASE + path, data=json.dumps(payload or {}).encode(), method="POST",
        headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read().decode())
        except Exception:
            return {"valid": False}


def get_text(path, params):
    q = urllib.parse.urlencode(params)
    with urllib.request.urlopen(BASE + path + "?" + q, timeout=15) as r:
        return r.read().decode()


def db(write=False):
    return sqlite3.connect("aera.db" if write else "file:aera.db?mode=ro",
                           uri=not write)


def main():
    import re
    import urllib.parse as _up
    globals()["urllib"].parse = _up

    print("=" * 62)
    print("S-02 LIVE REVOCATION TEST")
    print("=" * 62)

    cid = None
    try:
        r = post("/api/v1/clients/register", {
            "admin_key": ADMIN,
            "client_name": "ZZ-S02-DISPOSABLE-TEST-CLIENT",
            "redirect_uris": ["http://127.0.0.1:9/cb"],
            "allowed_origins": ["http://127.0.0.1:9"],
            "min_score": 0, "require_nft": False})
        cid, csec = r.get("client_id"), r.get("client_secret")
        check("disposable client created", bool(cid))
        if not cid:
            return 1

        # wallet
        acct = Account.create()
        addr = acct.address
        n = post("/api/nonce", {"address": addr})
        msg = n.get("message") or n.get("nonce")
        sig = acct.sign_message(encode_defunct(text=msg)).signature.hex()
        sig = sig if sig.startswith("0x") else "0x" + sig
        reg = post("/api/verify", {
            "address": addr, "nonce": n.get("nonce", ""),
            "message": msg, "signature": sig,
            "display_name": "ZZ-S02-TEST-USER"})
        check("test wallet registered via regular wallet flow",
              reg.get("is_human") is True)

        # authorize -> complete -> token (same path as tools/oauth_e2e_smoke.py)
        get_text("/oauth/authorize", {
            "client_id": cid, "redirect_uri": "http://127.0.0.1:9/cb",
            "state": "s02", "response_type": "code"})
        c = db()
        row = c.execute("SELECT nonce FROM oauth_codes WHERE client_id=? "
                        "ORDER BY id DESC LIMIT 1", (cid,)).fetchone()
        c.close()
        check("pending authorization row created", row is not None)
        oauth_nonce = row[0] if row else ""

        n2 = post("/api/nonce", {"address": addr})
        msg2 = n2.get("message") or n2.get("nonce")
        sig2 = acct.sign_message(encode_defunct(text=msg2)).signature.hex()
        sig2 = sig2 if sig2.startswith("0x") else "0x" + sig2
        comp = post("/oauth/complete", {
            "oauth_nonce": oauth_nonce, "address": addr,
            "nonce": n2.get("nonce"), "message": msg2, "signature": sig2})
        check("authorization code issued", comp.get("success") is True)
        if not comp.get("success"):
            print("     debug:", str(comp)[:200])

        tok = post("/oauth/token", {
            "grant_type": "authorization_code", "code": comp.get("code"),
            "redirect_uri": "http://127.0.0.1:9/cb",
            "client_id": cid, "client_secret": csec})
        token = tok.get("access_token")
        check("access token issued", bool(token))
        if not token:
            return 1

        jti = jwt.decode(token, options={"verify_signature": False})["jti"]

        # lifecycle row exists
        c = db()
        row = c.execute("SELECT sub, client_id, status FROM oauth_token_jti "
                        "WHERE jti = ?", (jti,)).fetchone()
        c.close()
        check("lifecycle row persisted on issuance", row is not None)
        check("lifecycle row bound to correct client", row and row[1] == cid)
        check("lifecycle row bound to correct wallet",
              row and row[0] == addr.lower())
        check("lifecycle row is active", row and row[2] == "active")

        # token works, repeatedly
        v1 = post("/api/v1/verify", headers={"Authorization": f"Bearer {token}"})
        v2 = post("/api/v1/verify", headers={"Authorization": f"Bearer {token}"})
        check("valid token accepted", v1.get("valid") is True)
        check("token reusable before expiry (not a nonce)", v2.get("valid") is True)
        check("correct wallet returned",
              (v1.get("wallet") or "").lower() == addr.lower())

        # revoke
        c = db(write=True)
        c.execute("UPDATE oauth_token_jti SET status='revoked', "
                  "revoked_at=datetime('now'), revocation_reason='live-test' "
                  "WHERE jti = ?", (jti,))
        c.commit()
        c.close()

        v3 = post("/api/v1/verify", headers={"Authorization": f"Bearer {token}"})
        check("REVOKED token rejected", v3.get("valid") is False)
        check("revoked response leaks no wallet", "wallet" not in v3)

        nft = post("/api/oauth/verify-nft", {
            "access_token": token, "client_id": cid, "client_secret": csec})
        check("revoked token rejected on verify-nft too",
              nft.get("valid") is False)

        # unknown jti
        c = db(write=True)
        c.execute("DELETE FROM oauth_token_jti WHERE jti = ?", (jti,))
        c.commit()
        c.close()
        v4 = post("/api/v1/verify", headers={"Authorization": f"Bearer {token}"})
        check("UNKNOWN jti rejected", v4.get("valid") is False)

    finally:
        # Runs on EVERY exit path, including early returns and exceptions,
        # so a failed run can never leave an active test client behind.
        try:
            c = db(write=True)
            c.execute("UPDATE oauth_clients SET is_active = 0 "
                      "WHERE client_name LIKE 'ZZ-S02-%' AND is_active = 1")
            c.commit()
            left = c.execute("SELECT COUNT(*) FROM oauth_clients "
                             "WHERE is_active = 1").fetchone()[0]
            stray = c.execute("SELECT COUNT(*) FROM oauth_clients "
                              "WHERE client_name LIKE 'ZZ-%' "
                              "AND is_active = 1").fetchone()[0]
            c.close()
            print("\n=== cleanup ===")
            print(f"  [{'PASS' if stray == 0 else 'FAIL'}] no active test clients left")
            print(f"     remaining active clients: {left}")
        except Exception as exc:
            print(f"  [FAIL] cleanup error: {exc}")

    print("\n" + "=" * 62)
    print(f"S-02 LIVE REVOCATION: {_p} passed, {_f} failed")
    print("=" * 62)
    return 0 if _f == 0 else 1


if __name__ == "__main__":
    import urllib.parse  # noqa: F401
    sys.exit(main())
