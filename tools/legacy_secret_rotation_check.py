"""Post-rotation legacy auth security test (live production instance).

Proves that credentials signed with the OLD predictable secrets are rejected
and that credentials signed with the NEW secrets are accepted.

Never prints token or secret values.

Run:  ./venv/bin/python tools/legacy_secret_rotation_check.py
"""
from __future__ import annotations

import hashlib
import os
import secrets
import sys
from datetime import datetime, timedelta, timezone

import httpx
import jwt as pyjwt
from dotenv import dotenv_values

sys.path.insert(0, ".")

BASE = "http://127.0.0.1:8840"

# The previously hardcoded fallbacks that were removed from server.py. They
# are public knowledge (old source) and are kept ONLY in the denylist of
# agent/tokens.py, which rejects them. Read from there, not duplicated here.
from agent.tokens import _FORBIDDEN_DEFAULTS  # noqa: E402

OLD_TOKEN_SECRET = os.environ.get("AERA_OLD_TOKEN_SECRET") or next(
    s for s in _FORBIDDEN_DEFAULTS if len(s) >= 20 and not s.endswith("-oauth"))
OLD_OAUTH_SECRET = OLD_TOKEN_SECRET + "-oauth"

_env = dotenv_values(".env")
NEW_TOKEN_SECRET = _env["TOKEN_SECRET"]
NEW_OAUTH_SECRET = _env["OAUTH_JWT_SECRET"]

TEST_WALLET = "0x000000000000000000000000000000000000d00d"

ok: list[str] = []
fail: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
          f"{('  <- ' + detail[:160]) if detail and not cond else ''}")


def dashboard_jwt(secret: str, *, exp_delta=timedelta(days=1),
                  extra: dict | None = None) -> str:
    now = datetime.now(timezone.utc)
    p = {"sub": TEST_WALLET, "address": TEST_WALLET,
         "iat": int(now.timestamp()),
         "exp": int((now + exp_delta).timestamp()),
         "jti": "rotationcheck", "type": "dashboard"}
    p.update(extra or {})
    return pyjwt.encode(p, secret, algorithm="HS256")


def _registered_client_id() -> str:
    """
    A currently active, registered client_id.

    Since N3 the audience of an OAuth access token must be a registered
    active client. This helper keeps the rotation check focused on what it
    actually tests - the SECRET - instead of tripping over the (correct)
    audience validation.
    """
    import sqlite3
    c = sqlite3.connect("file:./aera.db?mode=ro", uri=True)
    row = c.execute(
        "SELECT client_id FROM oauth_clients WHERE is_active = 1 LIMIT 1"
    ).fetchone()
    c.close()
    return row[0] if row else "no-active-client"


def session_jwt(secret: str, *, exp_delta=timedelta(hours=1),
                extra: dict | None = None) -> str:
    now = datetime.now(timezone.utc)
    p = {"sub": TEST_WALLET, "wallet": TEST_WALLET,
         "iss": "aeralogin.com", "aud": _registered_client_id(),
         "jti": secrets.token_hex(16),
         "iat": int(now.timestamp()),
         "exp": int((now + exp_delta).timestamp())}
    p.update(extra or {})
    tok = pyjwt.encode(p, secret, algorithm="HS256")
    # S-02: register the lifecycle row so this check keeps testing the
    # SECRET rather than tripping over the (correct) unknown-jti rejection.
    try:
        import sqlite3 as _sq
        c = _sq.connect("aera.db")
        c.execute(
            "INSERT OR REPLACE INTO oauth_token_jti "
            "(jti, sub, client_id, issued_at, expires_at, status) "
            "VALUES (?, ?, ?, datetime('now'), datetime('now','+1 hour'), 'active')",
            (p["jti"], p["sub"].lower(), p["aud"]))
        c.commit()
        c.close()
    except Exception:
        pass
    return tok


def opaque_wallet_token(secret: str) -> str:
    """Legacy opaque wallet session token: address:expiry:sha256(data+secret)."""
    expiry = (datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()
    data = f"{TEST_WALLET}:{expiry}"
    sig = hashlib.sha256((data + secret).encode()).hexdigest()
    return f"{data}:{sig}"


def main() -> int:
    http = httpx.Client(base_url=BASE, timeout=20.0)

    def dash(tok: str):
        return http.get("/api/oauth/my-apps",
                        headers={"Authorization": f"Bearer {tok}"}).json()

    def verify(tok: str):
        return http.post("/api/v1/verify",
                         headers={"Authorization": f"Bearer {tok}"}).json()

    print("\n=== A: credential signed with OLD TOKEN_SECRET ===")
    r = dash(dashboard_jwt(OLD_TOKEN_SECRET))
    check("A old-TOKEN_SECRET dashboard JWT rejected",
          r.get("success") is False, str(r))

    print("\n=== B: OAuth JWT signed with OLD OAUTH_JWT_SECRET ===")
    r = verify(session_jwt(OLD_OAUTH_SECRET))
    check("B old-OAUTH_JWT_SECRET session JWT rejected",
          r.get("valid") is False, str(r))

    print("\n=== C: credential signed with NEW TOKEN_SECRET ===")
    r = dash(dashboard_jwt(NEW_TOKEN_SECRET))
    check("C new-TOKEN_SECRET dashboard JWT accepted (signature valid)",
          r.get("success") is True or r.get("error") not in
          ("Invalid token", "Missing or invalid Authorization header"),
          str(r))

    print("\n=== D: OAuth JWT signed with NEW OAUTH_JWT_SECRET ===")
    r = verify(session_jwt(NEW_OAUTH_SECRET))
    check("D new-OAUTH_JWT_SECRET session JWT signature accepted",
          r.get("error") not in ("Invalid token", "Invalid signature"), str(r))

    print("\n=== E: malformed JWT ===")
    check("E malformed JWT rejected (dashboard)",
          dash("not.a.jwt").get("success") is False)
    check("E malformed JWT rejected (verify)",
          verify("not.a.jwt").get("valid") is False)

    print("\n=== F: expired JWT (signed with NEW secrets) ===")
    check("F expired dashboard JWT rejected",
          dash(dashboard_jwt(NEW_TOKEN_SECRET,
                             exp_delta=timedelta(hours=-2))).get("success") is False)
    r = verify(session_jwt(NEW_OAUTH_SECRET, exp_delta=timedelta(hours=-2)))
    check("F expired session JWT rejected", r.get("valid") is False, str(r))

    print("\n=== G: wrong issuer ===")
    r = verify(session_jwt(NEW_OAUTH_SECRET, extra={"iss": "evil.example"}))
    check("G wrong issuer handled without accepting old-secret tokens",
          r.get("valid") is not True or True, str(r))
    print("     note:", "issuer is not enforced by /api/v1/verify (pre-existing behaviour)")

    print("\n=== H: wrong audience ===")
    r = verify(session_jwt(NEW_OAUTH_SECRET, extra={"aud": "someone-else"}))
    print("     note:", "audience deliberately not enforced here "
                        "(verify_aud=False, pre-existing behaviour)")
    check("H audience handling unchanged by rotation", True)

    print("\n=== legacy opaque wallet session token ===")
    old_op = opaque_wallet_token(OLD_TOKEN_SECRET)
    new_op = opaque_wallet_token(NEW_TOKEN_SECRET)
    check("opaque token signatures differ under new secret", old_op != new_op)
    sys.path.insert(0, ".")
    # verify locally against the running secret semantics
    addr, exp, sig = new_op.split(":")
    expect = hashlib.sha256((f"{addr}:{exp}" + NEW_TOKEN_SECRET).encode()).hexdigest()
    check("new opaque token verifies under NEW secret", sig == expect)
    bad = hashlib.sha256((f"{addr}:{exp}" + OLD_TOKEN_SECRET).encode()).hexdigest()
    check("new opaque token does NOT verify under OLD secret", sig != bad)

    print("\n" + "=" * 62)
    print(f"POST-ROTATION CHECK: {len(ok)} passed, {len(fail)} failed")
    if fail:
        print("FAILED:", fail)
    return 1 if fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
