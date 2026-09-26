"""N5 - real production OAuth Authorization-Code end-to-end smoke test.

Creates a DEDICATED DISPOSABLE test client via the official admin endpoint
(/api/v1/clients/register), runs the full flow, then deactivates the client.

No existing client is touched, guessed or modified.
Never prints: client_secret, authorization code, JWT, Authorization header.

Run:  ./venv/bin/python tools/oauth_e2e_smoke.py
"""
from __future__ import annotations

import secrets
import sqlite3
import sys
import time

import httpx
from dotenv import dotenv_values
from eth_account import Account
from eth_account.messages import encode_defunct

sys.path.insert(0, ".")

BASE = "http://127.0.0.1:8840"
REDIRECT_URI = "https://aeralogin-n5-test.invalid/callback"

ok: list[str] = []
fail: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
          f"{('  <- ' + str(detail)[:200]) if detail and not cond else ''}")


def main() -> int:
    env = dotenv_values(".env")
    admin_key = env["OAUTH_ADMIN_KEY"]          # never printed
    http = httpx.Client(base_url=BASE, timeout=30.0, follow_redirects=False)

    print("\n=== PHASE 7: create dedicated disposable test client ===")
    reg = http.post("/api/v1/clients/register", json={
        "admin_key": admin_key,
        "client_name": "ZZ-N5-DISPOSABLE-TEST-CLIENT (auto-created, safe to delete)",
        "redirect_uris": [REDIRECT_URI],
        "allowed_origins": ["https://aeralogin-n5-test.invalid"],
        "min_score": 0,
        "require_nft": False,
    })
    rb = reg.json()
    check("test client created via official admin endpoint",
          rb.get("success") is True, str(rb)[:200])
    if not rb.get("success"):
        print("\nABORT: cannot create disposable client")
        return 1
    client_id = rb["client_id"]
    client_secret = rb["client_secret"]          # never printed
    print(f"     client_id: {client_id[:16]}... (secret redacted)")

    # wrong admin key must not create anything
    bad = http.post("/api/v1/clients/register", json={
        "admin_key": env["TOKEN_SECRET"],
        "client_name": "MUST-NOT-EXIST",
        "redirect_uris": [REDIRECT_URI]}).json()
    check("TOKEN_SECRET rejected as admin key (N1 fallback gone)",
          bad.get("success") is False, str(bad)[:150])

    try:
        print("\n=== PHASE 8.1: /oauth/authorize ===")
        a = http.get("/oauth/authorize", params={
            "client_id": client_id, "redirect_uri": REDIRECT_URI,
            "response_type": "code", "state": "n5-state"})
        check("/oauth/authorize accepts the test client", a.status_code == 200,
              str(a.status_code))

        # The consent page is wallet-driven; extract the pending oauth_nonce
        # the server created for this authorize request.
        conn = sqlite3.connect("file:./aera.db?mode=ro", uri=True)
        row = conn.execute(
            "SELECT nonce FROM oauth_codes WHERE client_id=? "
            "ORDER BY id DESC LIMIT 1", (client_id,)).fetchone()
        conn.close()
        check("pending authorization row created", row is not None)
        oauth_nonce = row[0] if row else ""

        print("\n=== PHASE 8.2-8.4: wallet authorization -> code ===")
        acct = Account.from_key("0x" + secrets.token_hex(32))
        addr = acct.address.lower()

        # The OAuth consent flow requires an existing AEraLogIn user, so run
        # the regular wallet registration first (this is the real production
        # path a new user would take).
        n0 = http.post("/api/nonce", json={"address": addr}).json()
        m0 = n0.get("message") or n0.get("nonce", "")
        s0 = acct.sign_message(encode_defunct(text=m0)).signature.hex()
        if not s0.startswith("0x"):
            s0 = "0x" + s0
        reg_user = http.post("/api/verify", json={
            "address": addr, "nonce": n0.get("nonce", ""),
            "message": m0, "signature": s0,
            "display_name": "ZZ-N5-TEST-USER"}).json()
        check("test wallet registered via regular wallet flow",
              reg_user.get("is_human") is True, str(reg_user)[:200])

        n = http.post("/api/nonce", json={"address": addr}).json()
        msg = n.get("message") or n.get("nonce", "")
        sig = acct.sign_message(encode_defunct(text=msg)).signature.hex()
        if not sig.startswith("0x"):
            sig = "0x" + sig
        comp = http.post("/oauth/complete", json={
            "oauth_nonce": oauth_nonce, "address": addr,
            "nonce": n.get("nonce", ""), "message": msg, "signature": sig})
        cb = comp.json()
        check("authorization code issued after wallet signature",
              cb.get("success") is True and bool(cb.get("code")), str(cb)[:220])
        code = cb.get("code", "")
        if not code:
            return 1
        print("     authorization code received (redacted)")

        print("\n=== PHASE 8.5-8.7: /oauth/token ===")
        # wrong client_secret
        w1 = http.post("/oauth/token", json={
            "grant_type": "authorization_code", "code": code,
            "redirect_uri": REDIRECT_URI, "client_id": client_id,
            "client_secret": "wrong-" + secrets.token_urlsafe(16)}).json()
        check("wrong client_secret rejected",
              "access_token" not in w1 and "error" in w1, str(w1)[:150])

        # wrong redirect_uri
        w2 = http.post("/oauth/token", json={
            "grant_type": "authorization_code", "code": code,
            "redirect_uri": "https://evil.invalid/cb", "client_id": client_id,
            "client_secret": client_secret}).json()
        check("wrong redirect_uri rejected",
              "access_token" not in w2 and "error" in w2, str(w2)[:150])

        # invalid code
        w3 = http.post("/oauth/token", json={
            "grant_type": "authorization_code", "code": "invalid-" + secrets.token_urlsafe(8),
            "redirect_uri": REDIRECT_URI, "client_id": client_id,
            "client_secret": client_secret}).json()
        check("invalid code rejected", "access_token" not in w3, str(w3)[:150])

        # correct exchange
        t = http.post("/oauth/token", json={
            "grant_type": "authorization_code", "code": code,
            "redirect_uri": REDIRECT_URI, "client_id": client_id,
            "client_secret": client_secret})
        tb = t.json()
        check("access token issued for valid exchange",
              bool(tb.get("access_token")), str(tb)[:200])
        token = tb.get("access_token", "")

        print("\n=== PHASE 8: code single-use ===")
        again = http.post("/oauth/token", json={
            "grant_type": "authorization_code", "code": code,
            "redirect_uri": REDIRECT_URI, "client_id": client_id,
            "client_secret": client_secret}).json()
        check("authorization code accepted exactly once (replay rejected)",
              "access_token" not in again, str(again)[:150])

        print("\n=== PHASE 8.8: /api/v1/verify ===")
        if token:
            import jwt as pyjwt
            claims = pyjwt.decode(token, env["OAUTH_JWT_SECRET"],
                                  algorithms=["HS256"],
                                  options={"verify_aud": False})
            check("token signature valid under CURRENT OAUTH_JWT_SECRET",
                  claims.get("sub", "").lower() == addr or
                  claims.get("address", "").lower() == addr, "claims mismatch")
            try:
                pyjwt.decode(token, "aera-secret-key-change-in-production-oauth",
                             algorithms=["HS256"], options={"verify_aud": False})
                check("token NOT verifiable with OLD leaked secret", False,
                      "old secret still verifies!")
            except Exception:
                check("token NOT verifiable with OLD leaked secret", True)

            v = http.post("/api/v1/verify",
                          headers={"Authorization": f"Bearer {token}"}).json()
            check("/api/v1/verify accepts the issued token",
                  v.get("valid") is True, str(v)[:200])
            check("/api/v1/verify returns the correct wallet",
                  str(v.get("wallet", "")).lower() == addr, str(v)[:200])

        print("\n=== expired code ===")
        a2 = http.get("/oauth/authorize", params={
            "client_id": client_id, "redirect_uri": REDIRECT_URI,
            "response_type": "code", "state": "n5-exp"})
        conn = sqlite3.connect("./aera.db")
        r2 = conn.execute("SELECT nonce FROM oauth_codes WHERE client_id=? "
                          "ORDER BY id DESC LIMIT 1", (client_id,)).fetchone()
        if r2:
            # force expiry on this pending row only (test client only)
            conn.execute("UPDATE oauth_codes SET expires_at=datetime('now','-1 hour') "
                         "WHERE nonce=? AND client_id=?", (r2[0], client_id))
            conn.commit()
        conn.close()
        n2 = http.post("/api/nonce", json={"address": addr}).json()
        m2 = n2.get("message") or n2.get("nonce", "")
        s2 = acct.sign_message(encode_defunct(text=m2)).signature.hex()
        if not s2.startswith("0x"):
            s2 = "0x" + s2
        exp = http.post("/oauth/complete", json={
            "oauth_nonce": r2[0] if r2 else "", "address": addr,
            "nonce": n2.get("nonce", ""), "message": m2, "signature": s2}).json()
        check("expired pending authorization rejected",
              exp.get("success") is not True, str(exp)[:150])

    finally:
        print("\n=== PHASE 15: cleanup - deactivate disposable client ===")
        conn = sqlite3.connect("./aera.db")
        conn.execute("UPDATE oauth_clients SET is_active=0 WHERE client_id=?",
                     (client_id,))
        conn.commit()
        state = conn.execute("SELECT is_active FROM oauth_clients WHERE client_id=?",
                             (client_id,)).fetchone()
        total = conn.execute("SELECT count(*) FROM oauth_clients").fetchone()[0]
        others = conn.execute("SELECT count(*) FROM oauth_clients "
                              "WHERE is_active=1 AND client_id!=?",
                              (client_id,)).fetchone()[0]
        conn.close()
        check("disposable test client deactivated", state and state[0] == 0)
        print(f"     oauth_clients total={total}, other active clients={others}")

    print("\n" + "=" * 62)
    print(f"OAUTH E2E (N5): {len(ok)} passed, {len(fail)} failed")
    if fail:
        print("FAILED:", fail)
    return 1 if fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
