"""Live legacy wallet + OAuth regression after secret rotation.

Uses a dedicated throwaway wallet identity. Never prints tokens or secrets.

Run:  ./venv/bin/python tools/legacy_live_regression.py
"""
from __future__ import annotations

import hashlib
import secrets
import sys
from datetime import datetime, timedelta, timezone

import httpx
from eth_account import Account
from eth_account.messages import encode_defunct

sys.path.insert(0, ".")

BASE = "http://127.0.0.1:8840"

ok: list[str] = []
fail: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
          f"{('  <- ' + str(detail)[:180]) if detail and not cond else ''}")


def main() -> int:
    http = httpx.Client(base_url=BASE, timeout=30.0)
    acct = Account.from_key("0x" + secrets.token_hex(32))
    addr = acct.address.lower()

    print("\n=== /api/nonce ===")
    r = http.post("/api/nonce", json={"address": addr})
    check("nonce endpoint reachable", r.status_code == 200, r.text)
    body = r.json()
    check("nonce issued", body.get("success") is True and bool(body.get("nonce")),
          str(body)[:200])
    nonce = body.get("nonce", "")

    print("\n=== EIP-191 wallet signature (/api/verify) ===")
    msg = body.get("message") or nonce
    signed = acct.sign_message(encode_defunct(text=msg))
    sig = signed.signature.hex()
    if not sig.startswith("0x"):
        sig = "0x" + sig
    v = http.post("/api/verify", json={"address": addr, "nonce": nonce,
                                       "signature": sig, "message": msg})
    check("/api/verify responds", v.status_code == 200, v.text)
    vb = v.json() if v.status_code == 200 else {}
    check("EIP-191 signature accepted (is_human)", vb.get("is_human") is True,
          str(vb)[:250])
    token = vb.get("token") or vb.get("session_token") or ""
    check("session token issued under NEW TOKEN_SECRET", bool(token),
          "keys=" + str(list(vb))[:200])

    print("\n=== session token verification (/api/verify-token) ===")
    if token:
        # This endpoint additionally requires a fresh MetaMask signature
        # (pre-existing auto-login hardening), so we supply one.
        n2 = http.post("/api/nonce", json={"address": addr}).json()
        m2 = n2.get("message") or n2.get("nonce", "")
        s2 = acct.sign_message(encode_defunct(text=m2)).signature.hex()
        if not s2.startswith("0x"):
            s2 = "0x" + s2
        t = http.post("/api/verify-token",
                      json={"token": token, "address": addr,
                            "signature": s2, "message": m2,
                            "nonce": n2.get("nonce", "")})
        tb = t.json() if t.status_code == 200 else {}
        check("newly issued session token verifies under NEW secret",
              tb.get("valid") is True, str(tb)[:220])

        # tamper: same token with a flipped signature segment must fail
        parts = token.split(":")
        if len(parts) == 3:
            bad = f"{parts[0]}:{parts[1]}:{'0' * len(parts[2])}"
            tb2 = http.post("/api/verify-token",
                            json={"token": bad, "address": addr,
                                  "signature": s2, "message": m2,
                                  "nonce": n2.get("nonce", "")}).json()
            check("tampered session token rejected", tb2.get("valid") is False,
                  str(tb2)[:200])

    print("\n=== wrong-signature rejection ===")
    other = Account.from_key("0x" + secrets.token_hex(32))
    bad_sig = other.sign_message(encode_defunct(text=msg)).signature.hex()
    if not bad_sig.startswith("0x"):
        bad_sig = "0x" + bad_sig
    r2 = http.post("/api/nonce", json={"address": addr}).json()
    wrong = http.post("/api/verify", json={"address": addr,
                                           "nonce": r2.get("nonce", ""),
                                           "signature": bad_sig,
                                           "message": r2.get("message") or r2.get("nonce", "")})
    wb = wrong.json() if wrong.status_code == 200 else {}
    check("foreign-wallet signature rejected", wb.get("is_human") is not True,
          str(wb)[:200])

    print("\n=== OAuth endpoints ===")
    a = http.get("/oauth/authorize", follow_redirects=False)
    check("/oauth/authorize reachable (no 5xx)", a.status_code < 500, str(a.status_code))
    t = http.post("/oauth/token", data={"grant_type": "authorization_code",
                                        "code": "definitely-invalid",
                                        "client_id": "nonexistent"})
    tj = {}
    try:
        tj = t.json()
    except Exception:
        pass
    # Pre-existing API style: OAuth errors are returned as HTTP 200 with an
    # error body. What matters for security is that NO token is issued.
    check("/oauth/token issues no token for an invalid code",
          t.status_code < 500 and "access_token" not in tj and "error" in tj,
          f"{t.status_code} {str(tj)[:150]}")
    vv = http.post("/api/v1/verify")
    check("/api/v1/verify requires Authorization",
          vv.json().get("valid") is False, str(vv.json())[:150])

    print("\n=== OAuth client registry intact ===")
    import sqlite3
    c = sqlite3.connect("file:./aera.db?mode=ro", uri=True)
    n_clients = c.execute("SELECT count(*) FROM oauth_clients").fetchone()[0]
    n_sessions = c.execute("SELECT count(*) FROM oauth_sessions").fetchone()[0]
    n_users = c.execute("SELECT count(*) FROM users").fetchone()[0]
    c.close()
    # N3/N5 add disposable, immediately-deactivated test clients, so the
    # row count only ever grows. What matters is that nothing was purged.
    check("oauth_clients preserved", n_clients >= 10, f"{n_clients}")
    check("oauth_sessions preserved (not purged)", n_sessions >= 234, f"{n_sessions}")
    check("users preserved", n_users >= 92, f"{n_users}")

    print("\n" + "=" * 62)
    print(f"LEGACY LIVE REGRESSION: {len(ok)} passed, {len(fail)} failed")
    if fail:
        print("FAILED:", fail)
    return 1 if fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
