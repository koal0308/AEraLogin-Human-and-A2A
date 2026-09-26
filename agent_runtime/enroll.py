"""Runtime side of agent enrollment ("pairing").

    python -m agent_runtime enroll aera-enroll-<id>.<secret>

1. Generate the Ed25519 key LOCALLY (the existing LocalKeyStore; sealed with
   scrypt + AES-GCM when AERA_RUNTIME_KEY_PASSPHRASE is set).
2. Sign a proof-of-possession payload with it and submit the PUBLIC key.
3. Print the key fingerprint so the owner can compare it in the dashboard.
4. Wait for the owner's wallet approval, then store agent_id / key_id (public
   identifiers only) next to the key so `agent_runtime run` needs no manual
   configuration.

What is sent to AEra: the enrollment code, the public key, a signature.
What is never sent, printed or logged: the private key.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Callable, Optional

import httpx

from agent.crypto import b64u_encode, public_key_fingerprint
from agent.enrollment import EnrollmentError, build_pop_payload, parse_code

from .config import identity_path_for
from .keystore import LocalKeyStore, _write_private

POLL_INTERVAL_SECONDS = 3.0
TERMINAL_FAILURES = frozenset({"expired", "cancelled"})


class EnrollError(Exception):
    """Enrollment could not be completed."""


def _agent_error(resp: httpx.Response) -> str:
    try:
        detail = resp.json().get("detail")
        if isinstance(detail, dict) and detail.get("agent_error"):
            return str(detail["agent_error"])
    except Exception:
        pass
    return f"http_{resp.status_code}"


def claim(http: httpx.Client, code: str, store: LocalKeyStore) -> dict[str, Any]:
    enrollment_id, _ = parse_code(code)
    public_key = store.public_key
    signature = b64u_encode(store.sign(build_pop_payload(enrollment_id, public_key)))
    resp = http.post("/api/agents/enrollments/claim", json={
        "enrollment_code": code, "public_key": public_key, "signature": signature,
    })
    if resp.status_code != 200:
        raise EnrollError(_agent_error(resp))
    body = resp.json()
    # Defence in depth: the server must echo the fingerprint of OUR key.
    if body.get("key_fingerprint") != public_key_fingerprint(public_key):
        raise EnrollError("fingerprint_mismatch")
    return body


def wait_for_approval(http: httpx.Client, code: str, *, timeout: float,
                      interval: float = POLL_INTERVAL_SECONDS,
                      sleep: Callable[[float], None] = time.sleep) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while True:
        resp = http.post("/api/agents/enrollments/status", json={"enrollment_code": code})
        if resp.status_code == 200:
            body = resp.json()
            status = body.get("status")
            if status == "completed" and body.get("agent_id") and body.get("key_id"):
                return body
            if status in TERMINAL_FAILURES:
                raise EnrollError(f"enrollment_{status}")
        elif resp.status_code != 429:
            raise EnrollError(_agent_error(resp))
        if time.monotonic() >= deadline:
            raise EnrollError("timed_out_waiting_for_owner_approval")
        sleep(interval)


def write_identity(key_path: Path, *, agent_id: str, key_id: str, base_url: str) -> Path:
    path = identity_path_for(key_path)
    data = json.dumps({"agent_id": agent_id, "key_id": key_id,
                       "aera_base_url": base_url}, indent=2).encode("utf-8")
    _write_private(path, data)
    return path


def enroll(*, code: str, base_url: str, key_path: Path, reuse_key: bool = False,
           timeout: float = 15 * 60, http: Optional[httpx.Client] = None,
           out: Callable[[str], None] = print,
           sleep: Callable[[float], None] = time.sleep) -> dict[str, Any]:
    try:
        parse_code(code)
    except EnrollmentError:
        raise EnrollError("invalid_enrollment_code")

    identity_file = identity_path_for(key_path)
    if identity_file.exists():
        raise EnrollError(
            f"{identity_file} already exists: this key is already bound to an "
            "agent. Use a different AERA_RUNTIME_KEY_PATH for a new agent.")

    store = LocalKeyStore(key_path)
    if store.exists:
        if not reuse_key:
            raise EnrollError(
                f"a key already exists at {key_path}; pass --reuse-key to enroll "
                "that key, or set AERA_RUNTIME_KEY_PATH to a new location")
        store.load()
    else:
        store.create()

    fingerprint = public_key_fingerprint(store.public_key)
    own_http = http is None
    client = http or httpx.Client(base_url=base_url, timeout=30)
    try:
        claim(client, code, store)
        out(f"key file   : {store.path} "
            f"({'encrypted' if store.encrypted else 'NOT encrypted'})")
        out(f"fingerprint: {fingerprint}")
        out("")
        out("Compare this fingerprint with the one shown in the AEra dashboard,")
        out("then approve the Agent there with your wallet. Waiting…")
        result = wait_for_approval(client, code, timeout=timeout, sleep=sleep)
    finally:
        if own_http:
            client.close()

    path = write_identity(key_path, agent_id=result["agent_id"],
                          key_id=result["key_id"], base_url=base_url)
    out("")
    out(f"agent_id   : {result['agent_id']}")
    out(f"key_id     : {result['key_id']}")
    out(f"saved to   : {path}")
    out("Start the runtime with: python -m agent_runtime run")
    return {"agent_id": result["agent_id"], "key_id": result["key_id"],
            "fingerprint": fingerprint, "identity_file": str(path)}
