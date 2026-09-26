"""Agent JWT: issuance and strict verification (Spec §9).

Uses `AGENT_JWT_SECRET` – NEVER shares with OAuth secrets. Fail-fast if
missing/default/too-short.
"""
from __future__ import annotations

import os
import secrets
import time
from typing import Any, Optional

import jwt as pyjwt

from . import repository
from .constants import (
    AGENT_JWT_TTL_SECONDS,
    AUDIENCE_ALLOWLIST,
    JWT_ALG,
    JWT_ISSUER,
    JWT_TYP,
)


class AgentJWTError(Exception):
    def __init__(self, code: str, http_status: int = 401, message: str = "") -> None:
        super().__init__(message or code)
        self.code = code
        self.http_status = http_status


_MIN_SECRET_LEN = 32
_FORBIDDEN_DEFAULTS = {
    "", "change-me", "changeme",
    "aera-secret-key-change-in-production",
    "aera-secret-key-change-in-production-oauth",
}


def get_secret() -> str:
    s = os.getenv("AGENT_JWT_SECRET", "")
    if s in _FORBIDDEN_DEFAULTS or len(s) < _MIN_SECRET_LEN:
        raise RuntimeError(
            "AGENT_JWT_SECRET missing, default, or shorter than 32 chars. "
            "Set a strong secret (e.g. `python -c 'import secrets; print(secrets.token_urlsafe(32))'`)."
        )
    oauth = os.getenv("OAUTH_JWT_SECRET", "")
    token = os.getenv("TOKEN_SECRET", "")
    if s == oauth or s == token:
        raise RuntimeError("AGENT_JWT_SECRET must NOT equal OAUTH_JWT_SECRET or TOKEN_SECRET.")
    return s


def issue(
    *,
    agent_id: str,
    key_id: str,
    aud: str,
    owner_wallet: str,
    capabilities: list[str],
) -> tuple[str, dict[str, Any]]:
    if aud not in AUDIENCE_ALLOWLIST:
        raise AgentJWTError("invalid_audience", 400)
    secret = get_secret()
    now = int(time.time())
    exp = now + AGENT_JWT_TTL_SECONDS
    jti = secrets.token_hex(16)
    payload = {
        "iss": JWT_ISSUER,
        "sub": agent_id,
        "aud": aud,
        "iat": now,
        "exp": exp,
        "jti": jti,
        "typ": JWT_TYP,
        "key_id": key_id,
        "owner_wallet": owner_wallet.lower(),
        "capabilities": sorted(set(capabilities)),
    }
    token = pyjwt.encode(payload, secret, algorithm=JWT_ALG)

    from datetime import datetime, timezone
    issued_iso = datetime.fromtimestamp(now, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    expires_iso = datetime.fromtimestamp(exp, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn = repository.get_connection()
    try:
        conn.execute(
            "INSERT INTO agent_jti(jti, agent_id, key_id, status, issued_at, expires_at, aud) "
            "VALUES (?, ?, ?, 'active', ?, ?, ?)",
            (jti, agent_id, key_id, issued_iso, expires_iso, aud),
        )
        conn.commit()
    finally:
        conn.close()
    return token, payload


def verify(token: str, *, expected_aud: str) -> dict[str, Any]:
    if expected_aud not in AUDIENCE_ALLOWLIST:
        raise AgentJWTError("invalid_audience")
    secret = get_secret()
    try:
        payload = pyjwt.decode(
            token,
            secret,
            algorithms=[JWT_ALG],
            audience=expected_aud,
            issuer=JWT_ISSUER,
            options={"require": ["exp", "iat", "sub", "jti", "aud", "iss"]},
        )
    except pyjwt.InvalidAudienceError:
        raise AgentJWTError("invalid_audience")
    except pyjwt.InvalidIssuerError:
        raise AgentJWTError("invalid_issuer")
    except pyjwt.ExpiredSignatureError:
        raise AgentJWTError("expired_token")
    except pyjwt.MissingRequiredClaimError:
        raise AgentJWTError("missing_claim")
    except pyjwt.InvalidSignatureError:
        raise AgentJWTError("invalid_signature")
    except pyjwt.PyJWTError:
        raise AgentJWTError("invalid_token")

    if payload.get("typ") != JWT_TYP:
        raise AgentJWTError("wrong_typ")
    jti = payload.get("jti")
    if not isinstance(jti, str) or not jti:
        raise AgentJWTError("invalid_jti")
    key_id = payload.get("key_id")
    if not isinstance(key_id, str) or not key_id:
        raise AgentJWTError("invalid_key_id")

    conn = repository.get_connection()
    try:
        row = conn.execute(
            "SELECT status, agent_id, key_id, aud FROM agent_jti WHERE jti=?", (jti,)
        ).fetchone()
        if row is None:
            raise AgentJWTError("jti_unknown")
        if row["status"] != "active":
            raise AgentJWTError("jti_revoked")
        if row["agent_id"] != payload["sub"]:
            raise AgentJWTError("invalid_token")
        if row["key_id"] != key_id:
            raise AgentJWTError("invalid_token")
        # Spec v1.2 §9.4/§9.6: the audience carried in the JWT must be bound to the
        # exact audience recorded at authentication time. Without this, an attacker
        # holding AGENT_JWT_SECRET could re-mint a token for an active JTI against a
        # different allowed audience (audience pivot).
        if row["aud"] != payload.get("aud"):
            raise AgentJWTError("invalid_token")

        agent = conn.execute(
            "SELECT status, owner_wallet, capabilities FROM agents WHERE agent_id=?",
            (payload["sub"],),
        ).fetchone()
        if agent is None or agent["status"] != "active":
            raise AgentJWTError("revoked_agent")
        key = conn.execute(
            "SELECT status FROM agent_keys WHERE key_id=? AND agent_id=?",
            (key_id, payload["sub"]),
        ).fetchone()
        if key is None or key["status"] != "active":
            raise AgentJWTError("revoked_key")
        if payload.get("owner_wallet", "").lower() != agent["owner_wallet"].lower():
            raise AgentJWTError("invalid_token")
        server_caps = set(repository.loads_capabilities(agent["capabilities"]))
        jwt_caps = set(payload.get("capabilities") or [])
        if not jwt_caps.issubset(server_caps):
            raise AgentJWTError("capability_denied", 403)
        # touch last_seen_at
        try:
            conn.execute(
                "UPDATE agents SET last_seen_at=? WHERE agent_id=?",
                (repository.utcnow_iso(), payload["sub"]),
            )
            conn.commit()
        except Exception:
            pass
    finally:
        conn.close()

    return payload


def revoke_jti(jti: str, *, reason: str = "explicit") -> bool:
    conn = repository.get_connection()
    try:
        cur = conn.execute(
            "UPDATE agent_jti SET status='revoked', revoked_at=?, revoked_reason=? "
            "WHERE jti=? AND status='active'",
            (repository.utcnow_iso(), reason, jti),
        )
        conn.commit()
        return cur.rowcount == 1
    finally:
        conn.close()


def revoke_all_for_key(conn, *, key_id: str, reason: str = "key_revoked") -> int:
    cur = conn.execute(
        "UPDATE agent_jti SET status='revoked', revoked_at=?, revoked_reason=? "
        "WHERE key_id=? AND status='active'",
        (repository.utcnow_iso(), reason, key_id),
    )
    return cur.rowcount


def revoke_all_for_agent(conn, *, agent_id: str, reason: str = "agent_revoked") -> int:
    cur = conn.execute(
        "UPDATE agent_jti SET status='revoked', revoked_at=?, revoked_reason=? "
        "WHERE agent_id=? AND status='active'",
        (repository.utcnow_iso(), reason, agent_id),
    )
    return cur.rowcount
