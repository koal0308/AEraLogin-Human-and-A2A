"""FastAPI router for the Agent Identity Layer.

Mounted from `server.py` only if `AGENT_LAYER_ENABLED=true`.
"""
from __future__ import annotations

import secrets
import sqlite3
from typing import Any, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request

from . import (
    audit,
    capabilities as cap_mod,
    challenges,
    enrollment,
    interactions,
    messages,
    owner_challenges,
    ratelimit,
    repository,
    tokens,
)
from .constants import (
    AUDIENCE_ALLOWLIST,
    AUD_AGENT_API,
    AUD_AGENT_RELAY,
    CAP_INTERACTION_RECORD,
    MAX_ACTIVE_KEYS_PER_AGENT,
    PROTO_AGENT_AUTH,
    PROTOCOL_VERSION,
)
from .crypto import (
    b64u_decode,
    canonical_json,
    decode_public_key,
    verify_signature,
)
from .constants import AGENT_AUTH_KEYS
from .models import (
    AddKeyRequest,
    AgentChallengeRequest,
    AuthenticateRequest,
    CapabilitiesPatchRequest,
    EnrollmentClaimRequest,
    EnrollmentCompleteRequest,
    EnrollmentStatusRequest,
    InteractionRequest,
    MessageRequest,
    OwnerChallengeRequest,
    OwnerChallengeResponse,
    RegisterRequest,
    RegisterResponse,
    RotateKeyRequest,
    TokenRevokeRequest,
)

router = APIRouter(prefix="/api/agents", tags=["agents"])


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _err(code: str, status: int = 400) -> HTTPException:
    return HTTPException(status_code=status, detail={"agent_error": code})


def _require_bearer(authorization: Optional[str]) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise _err("missing_bearer", 401)
    return authorization.split(" ", 1)[1].strip()


def _verify_jwt_for_aud(authorization: Optional[str], aud: str) -> dict[str, Any]:
    token = _require_bearer(authorization)
    try:
        return tokens.verify(token, expected_aud=aud)
    except tokens.AgentJWTError as e:
        raise HTTPException(status_code=e.http_status, detail={"agent_error": e.code})


def _rate(bucket: str, key: str, limit: int, window: int) -> None:
    if not ratelimit.check(bucket, key, limit=limit, window_seconds=window):
        raise _err("rate_limited", 429)


def _new_agent_id() -> str:
    return f"did:aera:agent:{secrets.token_hex(16)}"


def _new_key_id() -> str:
    return f"aera-key-{secrets.token_hex(12)}"


# --------------------------------------------------------------------------- #
# Owner Challenge
# --------------------------------------------------------------------------- #
@router.post("/owner-challenge")
def owner_challenge(req: OwnerChallengeRequest, request: Request) -> OwnerChallengeResponse:
    _rate("owner-challenge", req.owner_wallet.lower(), limit=30, window=60)
    try:
        rec = owner_challenges.issue(
            owner_wallet=req.owner_wallet,
            operation=req.operation,
            agent_id=req.agent_id,
        )
    except owner_challenges.OwnerChallengeError as e:
        raise _err(e.code, 400)
    audit.log_event(
        "agent.challenge_created",
        agent_id=req.agent_id,
        actor="owner",
        meta={"operation": req.operation, "owner_wallet": rec["owner_wallet"]},
    )
    return OwnerChallengeResponse(**rec)


# --------------------------------------------------------------------------- #
# Agent Registration
# --------------------------------------------------------------------------- #
@router.post("/register", response_model=RegisterResponse)
def register(req: RegisterRequest) -> RegisterResponse:
    _rate("register", req.owner_wallet.lower(), limit=10, window=60)
    try:
        decode_public_key(req.public_key)
    except ValueError:
        raise _err("invalid_public_key", 400)
    try:
        owner_challenges.consume(
            challenge_id=req.owner_challenge_id,
            owner_wallet=req.owner_wallet,
            operation="register",
            agent_id=None,
            signature_hex=req.owner_signature,
        )
    except owner_challenges.OwnerChallengeError as e:
        raise _err(e.code, 401)

    caps = cap_mod.normalize(req.capabilities)
    with repository.transaction() as conn:
        agent_id, key_id = create_agent(conn, owner_wallet=req.owner_wallet,
                                        public_key=req.public_key, label=req.label,
                                        caps=caps)
    return RegisterResponse(agent_id=agent_id, key_id=key_id, capabilities=caps)


def create_agent(conn: sqlite3.Connection, *, owner_wallet: str, public_key: str,
                 label: Optional[str], caps: list[str],
                 via: Optional[str] = None) -> tuple[str, str]:
    """Insert agent + first key. The ONE place an agent is created.

    Shared by `/register` (manual public key) and enrollment completion
    (runtime pairing) so both paths produce byte-identical identities.
    Caller owns the transaction and must have verified the owner signature.
    """
    agent_id = _new_agent_id()
    key_id = _new_key_id()
    now = repository.utcnow_iso()
    try:
        conn.execute(
            "INSERT INTO agents(agent_id, owner_wallet, status, capabilities, label, "
            "created_at, updated_at) VALUES (?, ?, 'active', ?, ?, ?, ?)",
            (agent_id, owner_wallet.lower(),
             repository.dumps_capabilities(caps), label, now, now),
        )
        conn.execute(
            "INSERT INTO agent_keys(key_id, agent_id, algorithm, public_key, status, "
            "created_at, activated_at) VALUES (?, ?, 'Ed25519', ?, 'active', ?, ?)",
            (key_id, agent_id, public_key, now, now),
        )
    except sqlite3.IntegrityError:
        raise _err("duplicate", 409)
    # Human Identity: the owner_wallet here is already signature-verified by
    # the caller; resolve (or create) its human in the SAME transaction.
    from identity import authorization as _identity_auth
    human_id = _identity_auth.human_for_verified_wallet(conn, owner_wallet)
    if human_id is None:
        raise _err("owner_identity_unavailable", 403)
    conn.execute("UPDATE agents SET owner_id = ? WHERE agent_id = ?",
                 (human_id, agent_id))
    meta = {"owner_wallet": owner_wallet.lower()}
    if via:
        meta["via"] = via
    audit.log_event("agent.created", agent_id=agent_id, key_id=key_id,
                    actor="owner", meta=meta, conn=conn)
    return agent_id, key_id


# --------------------------------------------------------------------------- #
# Enrollment / runtime pairing (see agent/enrollment.py for the model)
#
# Creation, owner view and cancel live in server.py because they are
# authenticated by the DASHBOARD SESSION. The two runtime-facing endpoints are
# authenticated by the enrollment secret; completion by the owner wallet.
# The enrollment code travels in the JSON body, never in a URL.
# --------------------------------------------------------------------------- #
def _enroll_err(e: "enrollment.EnrollmentError") -> HTTPException:
    return _err(e.code, e.http_status)


def _code_bucket_key(code: Any) -> str:
    # Rate-limit on the public enrollment id only; never key a bucket (which is
    # stored in the DB) on the secret.
    try:
        return enrollment.parse_code(code)[0]
    except enrollment.EnrollmentError:
        return "malformed"


@router.post("/enrollments/claim")
def enrollment_claim(req: EnrollmentClaimRequest, request: Request) -> dict[str, Any]:
    client_ip = request.client.host if request.client else "unknown"
    _rate("enroll-claim-ip", client_ip, limit=30, window=60)
    _rate("enroll-claim", _code_bucket_key(req.enrollment_code), limit=10, window=60)
    try:
        return enrollment.claim(code=req.enrollment_code, public_key=req.public_key,
                                signature=req.signature)
    except enrollment.EnrollmentError as e:
        raise _enroll_err(e)


@router.post("/enrollments/status")
def enrollment_status(req: EnrollmentStatusRequest, request: Request) -> dict[str, Any]:
    client_ip = request.client.host if request.client else "unknown"
    _rate("enroll-status-ip", client_ip, limit=120, window=60)
    _rate("enroll-status", _code_bucket_key(req.enrollment_code), limit=60, window=60)
    try:
        return enrollment.runtime_status(code=req.enrollment_code)
    except enrollment.EnrollmentError as e:
        raise _enroll_err(e)


@router.post("/enrollments/{enrollment_id}/complete", response_model=RegisterResponse)
def enrollment_complete(enrollment_id: str, req: EnrollmentCompleteRequest) -> RegisterResponse:
    _rate("register", req.owner_wallet.lower(), limit=10, window=60)
    if not enrollment.is_valid_enrollment_id(enrollment_id):
        raise _err("unknown_enrollment", 404)
    try:
        # Owner challenge bound to THIS enrollment. A plain `register`
        # challenge (agent_id NULL) is rejected here, and this challenge is
        # rejected by /register.
        owner_challenges.consume(
            challenge_id=req.owner_challenge_id,
            owner_wallet=req.owner_wallet,
            operation="register",
            agent_id=enrollment.challenge_binding(enrollment_id),
            signature_hex=req.owner_signature,
        )
    except owner_challenges.OwnerChallengeError as e:
        raise _err(e.code, 401)
    try:
        with repository.transaction() as conn:
            out = enrollment.complete(conn, enrollment_id=enrollment_id,
                                      owner_wallet=req.owner_wallet,
                                      create_agent=create_agent)
    except enrollment.EnrollmentError as e:
        raise _enroll_err(e)
    return RegisterResponse(**out)


# --------------------------------------------------------------------------- #
# Key Management
# --------------------------------------------------------------------------- #
def _load_agent(conn: sqlite3.Connection, agent_id: str) -> sqlite3.Row:
    a = conn.execute(
        "SELECT agent_id, owner_wallet, status, capabilities FROM agents WHERE agent_id=?",
        (agent_id,),
    ).fetchone()
    if a is None:
        raise _err("unknown_agent", 404)
    return a


def _active_key_count(conn, agent_id: str) -> int:
    r = conn.execute(
        "SELECT COUNT(*) AS n FROM agent_keys WHERE agent_id=? AND status='active'",
        (agent_id,),
    ).fetchone()
    return int(r["n"])


@router.post("/{agent_id}/keys")
def add_key(agent_id: str, req: AddKeyRequest) -> dict[str, str]:
    _rate("keys", agent_id, limit=20, window=60)
    try:
        decode_public_key(req.public_key)
    except ValueError:
        raise _err("invalid_public_key", 400)
    try:
        owner_challenges.consume(
            challenge_id=req.owner_challenge_id,
            owner_wallet=req.owner_wallet,
            operation="key_add",
            agent_id=agent_id,
            signature_hex=req.owner_signature,
        )
    except owner_challenges.OwnerChallengeError as e:
        raise _err(e.code, 401)

    key_id = _new_key_id()
    now = repository.utcnow_iso()
    with repository.transaction() as conn:
        agent = _load_agent(conn, agent_id)
        if agent["owner_wallet"].lower() != req.owner_wallet.lower():
            raise _err("owner_mismatch", 401)
        if agent["status"] != "active":
            raise _err("revoked_agent", 401)
        if _active_key_count(conn, agent_id) >= MAX_ACTIVE_KEYS_PER_AGENT:
            raise _err("too_many_active_keys", 409)
        try:
            conn.execute(
                "INSERT INTO agent_keys(key_id, agent_id, algorithm, public_key, status, "
                "created_at, activated_at) VALUES (?, ?, 'Ed25519', ?, 'active', ?, ?)",
                (key_id, agent_id, req.public_key, now, now),
            )
        except sqlite3.IntegrityError:
            raise _err("duplicate_public_key", 409)
        audit.log_event("agent.key_added", agent_id=agent_id, key_id=key_id,
                        actor="owner", conn=conn)
    return {"key_id": key_id}


@router.post("/{agent_id}/keys/rotate")
def rotate_key(agent_id: str, req: RotateKeyRequest) -> dict[str, str]:
    _rate("keys", agent_id, limit=20, window=60)
    try:
        decode_public_key(req.new_public_key)
    except ValueError:
        raise _err("invalid_public_key", 400)
    try:
        owner_challenges.consume(
            challenge_id=req.owner_challenge_id,
            owner_wallet=req.owner_wallet,
            operation="key_rotate",
            agent_id=agent_id,
            signature_hex=req.owner_signature,
        )
    except owner_challenges.OwnerChallengeError as e:
        raise _err(e.code, 401)

    new_id = _new_key_id()
    now = repository.utcnow_iso()
    with repository.transaction() as conn:
        agent = _load_agent(conn, agent_id)
        if agent["owner_wallet"].lower() != req.owner_wallet.lower():
            raise _err("owner_mismatch", 401)
        if agent["status"] != "active":
            raise _err("revoked_agent", 401)
        old = conn.execute(
            "SELECT status FROM agent_keys WHERE key_id=? AND agent_id=?",
            (req.revoke_key_id, agent_id),
        ).fetchone()
        if old is None:
            raise _err("unknown_key", 404)
        if _active_key_count(conn, agent_id) >= MAX_ACTIVE_KEYS_PER_AGENT:
            # rotating one key does not exceed limit; add first then revoke -> temporarily +1
            # allow strictly equal to max, since rotate is add+revoke transactional
            pass
        try:
            conn.execute(
                "INSERT INTO agent_keys(key_id, agent_id, algorithm, public_key, status, "
                "created_at, activated_at) VALUES (?, ?, 'Ed25519', ?, 'active', ?, ?)",
                (new_id, agent_id, req.new_public_key, now, now),
            )
        except sqlite3.IntegrityError:
            raise _err("duplicate_public_key", 409)
        conn.execute(
            "UPDATE agent_keys SET status='revoked', revoked_at=? WHERE key_id=?",
            (now, req.revoke_key_id),
        )
        tokens.revoke_all_for_key(conn, key_id=req.revoke_key_id, reason="key_rotated")
        audit.log_event("agent.key_rotated", agent_id=agent_id,
                        key_id=new_id, actor="owner",
                        meta={"revoked": req.revoke_key_id}, conn=conn)
    return {"key_id": new_id}


@router.delete("/{agent_id}/keys/{key_id}")
def revoke_key(agent_id: str, key_id: str,
               req: AddKeyRequest) -> dict[str, str]:
    _rate("keys", agent_id, limit=20, window=60)
    try:
        owner_challenges.consume(
            challenge_id=req.owner_challenge_id,
            owner_wallet=req.owner_wallet,
            operation="key_revoke",
            agent_id=agent_id,
            signature_hex=req.owner_signature,
        )
    except owner_challenges.OwnerChallengeError as e:
        raise _err(e.code, 401)
    now = repository.utcnow_iso()
    with repository.transaction() as conn:
        agent = _load_agent(conn, agent_id)
        if agent["owner_wallet"].lower() != req.owner_wallet.lower():
            raise _err("owner_mismatch", 401)
        cur = conn.execute(
            "UPDATE agent_keys SET status='revoked', revoked_at=? "
            "WHERE key_id=? AND agent_id=? AND status='active'",
            (now, key_id, agent_id),
        )
        if cur.rowcount != 1:
            raise _err("unknown_key", 404)
        tokens.revoke_all_for_key(conn, key_id=key_id, reason="key_revoked")
        audit.log_event("agent.key_revoked", agent_id=agent_id, key_id=key_id,
                        actor="owner", conn=conn)
    return {"status": "revoked"}


# --------------------------------------------------------------------------- #
# Agent Revoke
# --------------------------------------------------------------------------- #
@router.delete("/{agent_id}")
def revoke_agent(agent_id: str, req: AddKeyRequest) -> dict[str, str]:
    _rate("agent-revoke", agent_id, limit=20, window=60)
    try:
        owner_challenges.consume(
            challenge_id=req.owner_challenge_id,
            owner_wallet=req.owner_wallet,
            operation="agent_revoke",
            agent_id=agent_id,
            signature_hex=req.owner_signature,
        )
    except owner_challenges.OwnerChallengeError as e:
        raise _err(e.code, 401)
    now = repository.utcnow_iso()
    with repository.transaction() as conn:
        agent = _load_agent(conn, agent_id)
        if agent["owner_wallet"].lower() != req.owner_wallet.lower():
            raise _err("owner_mismatch", 401)
        conn.execute(
            "UPDATE agents SET status='revoked', revoked_at=?, updated_at=? WHERE agent_id=?",
            (now, now, agent_id),
        )
        conn.execute(
            "UPDATE agent_keys SET status='revoked', revoked_at=? WHERE agent_id=? AND status='active'",
            (now, agent_id),
        )
        tokens.revoke_all_for_agent(conn, agent_id=agent_id, reason="agent_revoked")
        audit.log_event("agent.revoked", agent_id=agent_id, actor="owner", conn=conn)
    return {"status": "revoked"}


# --------------------------------------------------------------------------- #
# Capability Update
# --------------------------------------------------------------------------- #
@router.patch("/{agent_id}/capabilities")
def patch_capabilities(agent_id: str, req: CapabilitiesPatchRequest) -> dict[str, list[str]]:
    try:
        owner_challenges.consume(
            challenge_id=req.owner_challenge_id,
            owner_wallet=req.owner_wallet,
            operation="capabilities",
            agent_id=agent_id,
            signature_hex=req.owner_signature,
        )
    except owner_challenges.OwnerChallengeError as e:
        raise _err(e.code, 401)
    caps = cap_mod.normalize(req.capabilities)
    with repository.transaction() as conn:
        agent = _load_agent(conn, agent_id)
        if agent["owner_wallet"].lower() != req.owner_wallet.lower():
            raise _err("owner_mismatch", 401)
        conn.execute(
            "UPDATE agents SET capabilities=?, updated_at=? WHERE agent_id=?",
            (repository.dumps_capabilities(caps), repository.utcnow_iso(), agent_id),
        )
        audit.log_event("agent.capabilities_changed", agent_id=agent_id,
                        actor="owner", meta={"capabilities": caps}, conn=conn)
    return {"capabilities": caps}


# --------------------------------------------------------------------------- #
# Public metadata
# --------------------------------------------------------------------------- #
@router.get("/{agent_id}")
def get_agent(agent_id: str) -> dict[str, Any]:
    conn = repository.get_connection()
    try:
        a = conn.execute(
            "SELECT agent_id, owner_wallet, status, label, created_at, updated_at "
            "FROM agents WHERE agent_id=?", (agent_id,),
        ).fetchone()
        if a is None:
            raise _err("unknown_agent", 404)
        keys = conn.execute(
            "SELECT key_id, algorithm, public_key, status FROM agent_keys "
            "WHERE agent_id=?", (agent_id,),
        ).fetchall()
    finally:
        conn.close()
    return {
        "agent_id": a["agent_id"],
        "owner_wallet": a["owner_wallet"],
        "status": a["status"],
        "label": a["label"],
        "created_at": a["created_at"],
        "updated_at": a["updated_at"],
        "keys": [dict(k) for k in keys],
    }


# --------------------------------------------------------------------------- #
# Agent Challenge / Authenticate
# --------------------------------------------------------------------------- #
@router.post("/{agent_id}/challenge")
def agent_challenge(agent_id: str, req: AgentChallengeRequest) -> dict[str, Any]:
    _rate("agent-challenge", agent_id, limit=60, window=60)
    if req.aud not in AUDIENCE_ALLOWLIST:
        raise _err("invalid_audience", 400)
    try:
        rec = challenges.issue(agent_id=agent_id, key_id=req.key_id, aud=req.aud)
    except challenges.AgentChallengeError as e:
        code_map = {"invalid_agent": 404, "invalid_key": 404}
        raise _err(e.code, code_map.get(e.code, 401))
    audit.log_event("agent.challenge_created", agent_id=agent_id,
                    key_id=req.key_id, actor="agent",
                    meta={"aud": req.aud})
    return rec


@router.post("/{agent_id}/authenticate")
def authenticate(agent_id: str, req: AuthenticateRequest) -> dict[str, Any]:
    _rate("authenticate", agent_id, limit=60, window=60)
    if req.aud not in AUDIENCE_ALLOWLIST:
        raise _err("invalid_audience", 400)
    # 1) Load challenge and atomically consume with binding checks + signature check.
    with repository.transaction() as conn:
        row = conn.execute(
            "SELECT * FROM agent_challenges WHERE challenge_id=? AND consumed_at IS NULL "
            "AND expires_at > ?", (req.challenge_id, repository.utcnow_iso()),
        ).fetchone()
        if row is None:
            audit.log_event("agent.authentication_failed",
                            agent_id=agent_id, actor="agent",
                            meta={"reason": "invalid_challenge"}, conn=conn)
            raise _err("invalid_challenge", 401)
        if row["agent_id"] != agent_id:
            raise _err("invalid_challenge", 401)
        if row["key_id"] != req.key_id:
            raise _err("key_mismatch", 401)
        if row["aud"] != req.aud:
            raise _err("invalid_audience", 401)

        agent = _load_agent(conn, agent_id)
        if agent["status"] != "active":
            raise _err("revoked_agent", 401)
        key = conn.execute(
            "SELECT public_key, status FROM agent_keys WHERE key_id=? AND agent_id=?",
            (req.key_id, agent_id),
        ).fetchone()
        if key is None or key["status"] != "active":
            raise _err("revoked_key", 401)

        payload = {
            "protocol": PROTO_AGENT_AUTH,
            "version": PROTOCOL_VERSION,
            "agent_id": agent_id,
            "key_id": req.key_id,
            "challenge_id": row["challenge_id"],
            "challenge": row["challenge"],
            "aud": row["aud"],
            "issued_at": row["issued_at"],
            "expires_at": row["expires_at"],
        }
        try:
            canonical = canonical_json(payload, AGENT_AUTH_KEYS)
        except ValueError:
            raise _err("invalid_signature", 401)
        if not verify_signature(key["public_key"], req.signature, canonical):
            audit.log_event("agent.authentication_failed",
                            agent_id=agent_id, actor="agent",
                            meta={"reason": "bad_signature"}, conn=conn)
            raise _err("invalid_signature", 401)

        cur = conn.execute(
            "UPDATE agent_challenges SET consumed_at=? WHERE challenge_id=? AND consumed_at IS NULL",
            (repository.utcnow_iso(), req.challenge_id),
        )
        if cur.rowcount != 1:
            raise _err("invalid_challenge", 401)

        caps = repository.loads_capabilities(agent["capabilities"])

    # 2) Issue JWT AFTER commit.
    token, jwt_payload = tokens.issue(
        agent_id=agent_id, key_id=req.key_id, aud=req.aud,
        owner_wallet=agent["owner_wallet"], capabilities=caps,
    )
    audit.log_event("agent.token_issued", agent_id=agent_id,
                    key_id=req.key_id, jti=jwt_payload["jti"], actor="agent")
    return {
        "token": token,
        "jti": jwt_payload["jti"],
        "aud": req.aud,
        "expires_at": jwt_payload["exp"],
        "capabilities": jwt_payload["capabilities"],
    }


# --------------------------------------------------------------------------- #
# Token Revoke / Introspection
# --------------------------------------------------------------------------- #
@router.post("/tokens/revoke")
def revoke_token(req: TokenRevokeRequest,
                 authorization: Optional[str] = Header(None)) -> dict[str, str]:
    # Self-revoke via valid Agent-JWT.
    payload = _verify_jwt_for_aud(authorization, AUD_AGENT_API)
    if payload.get("jti") != req.jti and req.jti not in {payload.get("jti")}:
        raise _err("forbidden", 403)
    tokens.revoke_jti(req.jti, reason="self_revoke")
    audit.log_event("agent.token_revoked", agent_id=payload["sub"], jti=req.jti,
                    actor="self")
    return {"status": "revoked"}


@router.post("/verify-jwt")
def verify_jwt(authorization: Optional[str] = Header(None)) -> dict[str, Any]:
    payload = _verify_jwt_for_aud(authorization, AUD_AGENT_API)
    return {
        "agent_id": payload["sub"],
        "key_id": payload["key_id"],
        "aud": payload["aud"],
        "capabilities": payload["capabilities"],
        "exp": payload["exp"],
        "typ": payload["typ"],
    }


# --------------------------------------------------------------------------- #
# A2A Message Relay
# --------------------------------------------------------------------------- #
@router.post("/messages")
def relay_message(req: MessageRequest,
                  authorization: Optional[str] = Header(None)) -> dict[str, Any]:
    payload = _verify_jwt_for_aud(authorization, AUD_AGENT_RELAY)
    try:
        cap_mod.require(payload, "agent.communicate")
    except tokens.AgentJWTError as e:
        raise HTTPException(status_code=e.http_status, detail={"agent_error": e.code})
    try:
        stored = messages.verify_and_store(req.payload, req.signature,
                                           jwt_sender=payload["sub"])
    except messages.MessageError as e:
        raise _err(e.code, 401)
    return {"status": "relayed", "message_id": stored["message_id"],
            "receiver": stored["receiver_agent_id"]}


# --------------------------------------------------------------------------- #
# Interactions
# --------------------------------------------------------------------------- #
@router.post("/interactions")
def create_interaction(req: InteractionRequest,
                       authorization: Optional[str] = Header(None)) -> dict[str, Any]:
    payload = _verify_jwt_for_aud(authorization, AUD_AGENT_API)
    try:
        cap_mod.require(payload, CAP_INTERACTION_RECORD)
    except tokens.AgentJWTError as e:
        raise HTTPException(status_code=e.http_status, detail={"agent_error": e.code})
    try:
        rec = interactions.record(
            payload=req.payload,
            signature_b64u=req.signature,
            interaction_type=req.interaction_type,
            metadata=req.metadata,
            jwt_sender=payload["sub"],
        )
    except interactions.InteractionError as e:
        raise _err(e.code, 401)
    return rec
