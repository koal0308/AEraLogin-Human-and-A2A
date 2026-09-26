#!/usr/bin/env python3
"""Part M -- reproducible release end-to-end check.

    ./venv/bin/python tools/release_live_e2e.py [--port 8892] [--keep]

One chained workflow against a real, ISOLATED AEra server process:

    Create Agent (dashboard) -> enrollment code -> `agent_runtime enroll`
    (key generated locally, PoP) -> fingerprint -> owner wallet approval
    -> identity file -> `agent_runtime run` -> Agent JWT -> signed L2 message
    -> external peer credential -> POST /api/a2a -> runtime reply (signature
    verified by the gateway) -> trust evidence -> revocation -> recovery
    (manual key replacement AND re-enrollment)

Isolation (all enforced, not advisory):
  * The server is started by THIS script on its own port (never 8840).
  * The database is a fresh file under a temp dir that receives only the
    SCHEMA of ./aera.db (no rows) -- no production data is read or written.
  * Every secret (TOKEN_SECRET, AGENT_JWT_SECRET, ...) is freshly random for
    this run and exists only in this process and the child processes.
  * Blockchain / bot credentials are blanked for the child server.
  * Owners are disposable EOAs generated per run.

Nothing sensitive is printed: no private key, no enrollment code, no
credential plaintext, no JWT, no signature. At the end the server log and
every captured output are scanned for all of them.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

RESULTS: list[tuple[str, str, bool]] = []
SECTION = ["-"]
SENSITIVE: set[str] = set()      # every secret value seen during the run
CAPTURED: list[str] = []         # every response body / CLI output


def section(name: str) -> None:
    SECTION[0] = name
    print(f"\n== {name} ==")


def check(name: str, ok: bool, detail: str = "") -> bool:
    RESULTS.append((SECTION[0], name, bool(ok)))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  [{detail}]" if detail and not ok else ""))
    return bool(ok)


def secret(value: str) -> str:
    if value:
        SENSITIVE.add(value)
    return value


# --------------------------------------------------------------------------- #
# isolated server
# --------------------------------------------------------------------------- #
def schema_only_db(target: Path) -> None:
    src = sqlite3.connect(f"file:{REPO / 'aera.db'}?mode=ro", uri=True)
    try:
        ddl = [r[0] for r in src.execute(
            "SELECT sql FROM sqlite_master WHERE sql IS NOT NULL "
            "AND name NOT LIKE 'sqlite_%' ORDER BY type='index'")]
    finally:
        src.close()
    dst = sqlite3.connect(target)
    try:
        for stmt in ddl:
            try:
                dst.execute(stmt)
            except sqlite3.OperationalError:
                pass
        dst.commit()
    finally:
        dst.close()


def server_env(work: Path, port: int) -> dict[str, str]:
    env = dict(os.environ)
    rnd = lambda p: f"e2e-{p}-" + secrets.token_urlsafe(32)  # noqa: E731
    env.update({
        "DATABASE_PATH": str(work / "e2e.db"),
        "PORT": str(port),
        "PUBLIC_URL": f"http://127.0.0.1:{port}",
        "TOKEN_SECRET": secret(rnd("tok")),
        "OAUTH_JWT_SECRET": secret(rnd("oauth")),
        "AGENT_JWT_SECRET": secret(rnd("agent")),
        "OAUTH_ADMIN_KEY": secret(rnd("admin")),
        "TELEGRAM_BOT_HMAC_SECRET": secret(rnd("hmac")),
        "AGENT_LAYER_ENABLED": "true",
        "AERA_A2A_GATEWAY_ENABLED": "true",
        "AERA_A2A_TRUST_MODE": "monitor",
        "AERA_A2A_AUTH_POLICY": "optional",
        # Loosen only the per-source/global buckets so that the credential
        # bucket is the one this run exercises; defaults stay in effect for
        # credential and per-agent limits.
        "AERA_A2A_PEER_RATE": "200", "AERA_A2A_PEER_BURST": "400",
        "AERA_A2A_GLOBAL_RATE": "400", "AERA_A2A_GLOBAL_BURST": "800",
        "AERA_A2A_AGENT_RATE": "50", "AERA_A2A_AGENT_BURST": "100",
        "AERA_RUNTIME_DIR": str(work / "rt"),
        "AERA_RUNTIME_INTERNAL_SECRET": secret(secrets.token_hex(32)),
        # blank everything that could reach a real chain or bot
        "PRIVATE_KEY": "", "ADMIN_PRIVATE_KEY": "", "BACKEND_PRIVATE_KEY": "",
        "ADMIN_WALLET": "", "BASE_ALCHEMY_API_URL": "",
        "BASE_RPC_URL": "http://127.0.0.1:1/unreachable",
        "TELEGRAM_BOT_TOKEN": "", "DISCORD_BOT_TOKEN": "",
        "PYTHONUNBUFFERED": "1",
    })
    for k in ("AERA_RUNTIME_AGENT_ID", "AERA_RUNTIME_KEY_ID", "AERA_RUNTIME_KEY_PATH",
              "AERA_RUNTIME_KEY_PASSPHRASE"):
        env.pop(k, None)
    return env


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
class Proc:
    """Background child process with captured output (never printed raw)."""

    def __init__(self, args, env, cwd=REPO):
        self.lines: list[str] = []
        self.p = subprocess.Popen(args, cwd=cwd, env=env, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, text=True)
        self._t = threading.Thread(target=self._pump, daemon=True)
        self._t.start()

    def _pump(self):
        for line in self.p.stdout:
            self.lines.append(line)

    def text(self) -> str:
        return "".join(self.lines)

    def wait_for(self, needle: str, timeout: float) -> bool:
        end = time.time() + timeout
        while time.time() < end:
            if needle in self.text():
                return True
            if self.p.poll() is not None:
                time.sleep(0.2)
                return needle in self.text()
            time.sleep(0.2)
        return False

    def stop(self) -> int:
        if self.p.poll() is None:
            self.p.send_signal(signal.SIGTERM)
            try:
                self.p.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.p.kill()
                self.p.wait()
        self._t.join(timeout=5)
        CAPTURED.append(self.text())
        return self.p.returncode


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8892)
    ap.add_argument("--keep", action="store_true", help="keep the temp dir")
    args = ap.parse_args()
    if args.port == 8840:
        print("refusing to run on the production port")
        return 3

    import httpx
    import jwt as pyjwt
    from eth_account import Account
    from eth_account.messages import encode_defunct

    from agent.constants import OWNER_CHALLENGE_KEYS, PROTO_AGENT_MESSAGE, PROTOCOL_VERSION, AGENT_MESSAGE_KEYS
    from agent.crypto import Ed25519Signer, b64u_encode, canonical_json, public_key_fingerprint
    from agent.enrollment import build_pop_payload
    from agent.messages import content_hash

    work = Path(tempfile.mkdtemp(prefix="aera-release-e2e-"))
    os.chmod(work, 0o700)
    (work / "rt").mkdir(mode=0o700)
    schema_only_db(work / "e2e.db")
    senv = server_env(work, args.port)
    base = f"http://127.0.0.1:{args.port}"
    log_path = work / "server.log"
    log_fh = open(log_path, "w")
    server = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "server:app", "--host", "127.0.0.1",
         "--port", str(args.port)], cwd=REPO, env=senv, stdout=log_fh,
        stderr=subprocess.STDOUT)
    http = httpx.Client(base_url=base, timeout=60)
    procs: list[Proc] = []

    def J(r):
        CAPTURED.append(r.text)
        try:
            return r.json()
        except ValueError:
            return {}

    def err(r):
        d = J(r).get("detail")
        return d.get("agent_error") if isinstance(d, dict) else d

    def session_for(address: str) -> dict:
        now = datetime.now(timezone.utc)
        tok = pyjwt.encode({"iss": "aeralogin.com", "sub": address, "address": address,
                            "iat": int(now.timestamp()),
                            "exp": int((now + timedelta(hours=1)).timestamp()),
                            "jti": secrets.token_hex(16), "type": "dashboard"},
                           senv["TOKEN_SECRET"], algorithm="HS256")
        return {"Authorization": f"Bearer {secret(tok)}"}

    def owner_challenge(acct, operation, agent_id=None):
        rec = J(http.post("/api/agents/owner-challenge", json={
            "owner_wallet": acct.address.lower(), "operation": operation, "agent_id": agent_id}))
        canon = canonical_json({k: (rec.get(k) or "") if k == "agent_id" else rec[k]
                                for k in OWNER_CHALLENGE_KEYS}, OWNER_CHALLENGE_KEYS)
        sig = acct.sign_message(encode_defunct(primitive=canon)).signature
        sig = sig.hex() if isinstance(sig, (bytes, bytearray)) else sig
        return rec["challenge_id"], secret(sig if sig.startswith("0x") else "0x" + sig)

    def owner_body(acct, operation, agent_id=None, **extra):
        cid, sig = owner_challenge(acct, operation, agent_id)
        return {"owner_wallet": acct.address.lower(), "owner_challenge_id": cid,
                "owner_signature": sig, **extra}

    def rpc(target, skill="agent.read.profile", mid=None, metadata=None, text="release e2e"):
        md = {"aera_target_agent": target, "skillId": skill, **(metadata or {})}
        return {"jsonrpc": "2.0", "id": str(uuid.uuid4()), "method": "message/send",
                "params": {"message": {"role": "user", "messageId": mid or str(uuid.uuid4()),
                                       "parts": [{"kind": "text", "text": text}],
                                       "metadata": md}}}

    def a2a(payload, bearer=None, retry=True):
        h = {"A2A-Version": "0.3"}
        if bearer:
            h["Authorization"] = f"Bearer {bearer}"
        for i in range(12):
            r = http.post("/api/a2a", json=payload, headers=h)
            body = J(r)
            limited = r.status_code == 429 or (body.get("error") or {}).get("code") == -32010
            if not (retry and limited):
                return r.status_code, body
            time.sleep(1 + i * 0.5)
        return r.status_code, body

    def db():
        c = sqlite3.connect(senv["DATABASE_PATH"])
        c.row_factory = sqlite3.Row
        return c

    def runtime_env(key_path: Path, passphrase: str, **extra):
        e = dict(senv)
        for k in ("TOKEN_SECRET", "OAUTH_JWT_SECRET", "AGENT_JWT_SECRET", "OAUTH_ADMIN_KEY",
                  "TELEGRAM_BOT_HMAC_SECRET", "DATABASE_PATH"):
            e.pop(k, None)        # the runtime needs none of the server's secrets
        e.update({"AERA_BASE_URL": base, "AERA_RUNTIME_KEY_PATH": str(key_path),
                  "AERA_RUNTIME_KEY_PASSPHRASE": passphrase,
                  "AERA_RUNTIME_PROVIDER": "mock"}, **extra)
        return e

    def load_store(key_path: Path, passphrase: str):
        from agent_runtime.keystore import LocalKeyStore
        return LocalKeyStore(key_path, passphrase=passphrase).load()

    def identity(agent_id, key_id, store):
        from agent_runtime.identity import RuntimeIdentity
        return RuntimeIdentity(base_url=base, agent_id=agent_id, key_id=key_id, keystore=store)

    def enroll_cli(code, key_path, passphrase, extra_args=()):
        return Proc([sys.executable, "-m", "agent_runtime", "enroll", code, "--timeout", "120",
                     *extra_args], runtime_env(key_path, passphrase))

    def wait_status(sess, eid, want, timeout=30):
        v = {}
        end = time.time() + timeout
        while time.time() < end:
            v = J(http.get(f"/api/dashboard/agents/enrollments/{eid}", headers=sess)).get("enrollment") or {}
            if v.get("status") == want:
                return v
            time.sleep(0.4)
        return v

    try:
        # ------------------------------------------------------------------ #
        section("0 isolated environment")
        up = False
        for _ in range(120):
            try:
                if http.get("/.well-known/agent-card.json").status_code == 200:
                    up = True
                    break
            except httpx.HTTPError:
                pass
            if server.poll() is not None:
                break
            time.sleep(0.5)
        if not check("isolated server up on its own port", up, f"port {args.port}"):
            return 1
        check("database is a fresh schema-only file (0 agents)",
              db().execute("SELECT COUNT(*) FROM agents").fetchone()[0] == 0)
        exposed = [p for p in ("/static/.env", "/static/aera.db", "/static/server.py",
                               "/docs/SYSTEM_ANALYSIS.md", "/docs/..%2f.env")
                   if http.get(p).status_code != 404]
        check("private files are not served under /static or /docs", not exposed, str(exposed))
        check("public assets still served (allowlist)",
              http.get("/static/aera-agent-enroll.js").status_code == 200
              and http.get("/docs/agent-api.html").status_code == 200)

        owner = Account.create()
        stranger = Account.create()
        O = owner.address.lower()
        S = session_for(O)
        S_stranger = session_for(stranger.address.lower())

        # ------------------------------------------------------------------ #
        section("1 enrollment (Part L) + negative cases")
        r = http.post("/api/dashboard/agents/enrollments", json={"label": "abc"})
        check("unauthenticated dashboard enrollment refused (401)", r.status_code == 401)

        r = http.post("/api/dashboard/agents/enrollments", headers=S,
                      json={"label": "Release E2E Agent", "capabilities": None})
        e = J(r).get("enrollment") or {}
        code, eid = secret(e.get("enrollment_code", "")), e.get("enrollment_id", "")
        check("owner creates enrollment", r.status_code == 200 and code.startswith("aera-enroll-"))
        exp = datetime.strptime(e["expires_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        ttl = (exp - datetime.now(timezone.utc)).total_seconds()
        check("enrollment TTL is 15 minutes", 14 * 60 < ttl <= 15 * 60, f"{ttl:.0f}s")
        row = db().execute("SELECT * FROM agent_enrollments WHERE enrollment_id=?", (eid,)).fetchone()
        check("only the SHA-256 of the secret is stored",
              row is not None and code.split(".", 1)[1] not in json.dumps(dict(row)))

        bad = f"aera-enroll-{eid}." + "A" * 32
        atk = Ed25519Signer.generate()
        atk_pk = atk.public_key_encoded()
        good_pop = lambda s, i: b64u_encode(s.sign(build_pop_payload(i, s.public_key_encoded())))  # noqa: E731
        r = http.post("/api/agents/enrollments/claim", json={
            "enrollment_code": bad, "public_key": atk_pk, "signature": good_pop(atk, eid)})
        check("invalid enrollment code refused (404, generic)",
              r.status_code == 404 and err(r) == "invalid_enrollment_code")
        r2 = http.post("/api/agents/enrollments/claim", json={
            "enrollment_code": "aera-enroll-0123456789abcdef." + "B" * 32,
            "public_key": atk_pk, "signature": good_pop(atk, "0123456789abcdef")})
        check("unknown id and wrong secret are indistinguishable",
              r2.status_code == r.status_code and err(r2) == err(r))
        other = Ed25519Signer.generate()
        r = http.post("/api/agents/enrollments/claim", json={
            "enrollment_code": code, "public_key": other.public_key_encoded(),
            "signature": good_pop(atk, eid)})
        check("PoP by a different key than the submitted public key refused",
              r.status_code == 401 and err(r) == "invalid_proof_of_possession")
        r = http.post("/api/agents/enrollments/claim", json={
            "enrollment_code": code, "public_key": atk_pk,
            "signature": good_pop(atk, "0123456789abcdef")})
        check("PoP bound to another enrollment id refused",
              r.status_code == 401 and err(r) == "invalid_proof_of_possession")
        r = http.post("/api/agents/enrollments/claim", json={
            "enrollment_code": code, "public_key": atk_pk, "signature": "A" * 86})
        check("garbage PoP signature refused", r.status_code == 401)
        check("failed claims leave the enrollment pending",
              wait_status(S, eid, "pending", 2).get("status") == "pending")

        k1 = work / "k1" / "agent_key.json"
        k1.parent.mkdir(mode=0o700)
        pass1 = secret("e2e-pass-" + secrets.token_hex(12))
        enr = enroll_cli(code, k1, pass1)
        procs.append(enr)
        view = wait_status(S, eid, "key_submitted")
        check("runtime claimed with PoP (status key_submitted)", view.get("status") == "key_submitted")
        fp = view.get("key_fingerprint") or ""
        check("dashboard shows the key fingerprint", fp.startswith("SHA256:") or len(fp) >= 16, fp[:12])

        r = http.post("/api/agents/enrollments/claim", json={
            "enrollment_code": code, "public_key": atk_pk, "signature": good_pop(atk, eid)})
        check("second claim with the same code refused (409)", r.status_code == 409)

        r = http.post(f"/api/agents/enrollments/{eid}/complete",
                      json=owner_body(stranger, "register", f"enrollment:{eid}"))
        check("wrong owner wallet cannot approve (404, no enumeration)", r.status_code == 404)
        cid, _ = owner_challenge(owner, "register", f"enrollment:{eid}")
        forged = stranger.sign_message(encode_defunct(text="not the challenge")).signature
        r = http.post(f"/api/agents/enrollments/{eid}/complete", json={
            "owner_wallet": O, "owner_challenge_id": cid,
            "owner_signature": secret("0x" + bytes(forged).hex().removeprefix("0x"))})
        check("invalid owner signature refused (401)", r.status_code == 401)
        r = http.post(f"/api/agents/enrollments/{eid}/complete",
                      json=owner_body(owner, "register", None))
        check("plain /register challenge cannot complete an enrollment (401)", r.status_code == 401)

        r = http.post(f"/api/agents/enrollments/{eid}/complete",
                      json=owner_body(owner, "register", f"enrollment:{eid}"))
        done = J(r)
        A, KA1 = done.get("agent_id", ""), done.get("key_id", "")
        check("owner wallet approval creates the agent", r.status_code == 200 and A.startswith("did:aera:agent:"))
        enr.p.wait(timeout=60)
        out = enr.stop()
        txt = enr.text()
        check("runtime enroll CLI exited 0", out == 0)
        check("runtime printed the same fingerprint", fp and fp in txt)
        check("runtime printed agent_id", A in txt)
        idf = k1.with_name("agent_key.identity.json")
        ident = json.loads(idf.read_text()) if idf.exists() else {}
        check("identity file holds agent_id + key_id (public only)",
              ident.get("agent_id") == A and ident.get("key_id") == KA1
              and set(ident) == {"agent_id", "key_id", "aera_base_url"})
        check("identity file and key file are 0600",
              oct(idf.stat().st_mode)[-3:] == "600" and oct(k1.stat().st_mode)[-3:] == "600")
        blob = json.loads(k1.read_text())
        check("private key sealed at rest (scrypt-aesgcm-v1)", blob.get("format") == "scrypt-aesgcm-v1")
        store1 = load_store(k1, pass1)
        check("DB holds exactly the runtime's PUBLIC key",
              db().execute("SELECT public_key FROM agent_keys WHERE key_id=?", (KA1,)).fetchone()[0]
              == store1.public_key)
        check("fingerprint == fingerprint(public key)", public_key_fingerprint(store1.public_key) == fp)

        r = http.post("/api/agents/enrollments/claim", json={
            "enrollment_code": code, "public_key": atk_pk, "signature": good_pop(atk, eid)})
        check("reusing a completed code refused (409)", r.status_code == 409)
        r = http.post(f"/api/agents/enrollments/{eid}/complete",
                      json=owner_body(owner, "register", f"enrollment:{eid}"))
        check("completing twice refused (409)", r.status_code == 409)

        # expired + cancelled
        e2 = J(http.post("/api/dashboard/agents/enrollments", headers=S,
                         json={"label": "expire me"}))["enrollment"]
        secret(e2["enrollment_code"])
        c = db()
        c.execute("UPDATE agent_enrollments SET expires_at='2000-01-01T00:00:00Z' WHERE enrollment_id=?",
                  (e2["enrollment_id"],))
        c.commit()
        c.close()
        r = http.post("/api/agents/enrollments/claim", json={
            "enrollment_code": e2["enrollment_code"], "public_key": atk_pk,
            "signature": good_pop(atk, e2["enrollment_id"])})
        check("expired enrollment refused (410)", r.status_code == 410)
        e3 = J(http.post("/api/dashboard/agents/enrollments", headers=S,
                         json={"label": "cancel me"}))["enrollment"]
        secret(e3["enrollment_code"])
        r = http.delete(f"/api/dashboard/agents/enrollments/{e3['enrollment_id']}", headers=S_stranger)
        check("foreign owner cannot cancel (404)", r.status_code == 404)
        r = http.delete(f"/api/dashboard/agents/enrollments/{e3['enrollment_id']}", headers=S)
        check("owner cancels enrollment", r.status_code == 200)
        r = http.post("/api/agents/enrollments/claim", json={
            "enrollment_code": e3["enrollment_code"], "public_key": atk_pk,
            "signature": good_pop(atk, e3["enrollment_id"])})
        check("cancelled enrollment cannot be claimed (409)", r.status_code == 409)

        # ------------------------------------------------------------------ #
        section("2 runtime start from identity file")
        run1 = Proc([sys.executable, "-m", "agent_runtime", "run"], runtime_env(k1, pass1))
        procs.append(run1)
        check("`agent_runtime run` authenticates with enrolled identity (no ID env)",
              run1.wait_for("runtime RUNNING", 40) and A in run1.text())
        h = subprocess.run([sys.executable, "-m", "agent_runtime", "health"], cwd=REPO,
                           env=runtime_env(k1, pass1), capture_output=True, text=True, timeout=30)
        CAPTURED.append(h.stdout + h.stderr)
        try:
            hj = json.loads(h.stdout)
        except ValueError:
            hj = {}
        check("`agent_runtime health` reports running", h.returncode == 0
              and "running" in json.dumps(hj).lower(), h.stdout[-120:])

        # ------------------------------------------------------------------ #
        section("3 agent authentication (Agent JWT) + L2 message relay")
        idA = identity(A, KA1, store1)
        tok_api = secret(idA.authenticate(aud="aera-agent-api"))
        tok_relay = secret(idA.authenticate(aud="aera-agent-relay"))
        v = J(http.post("/api/agents/verify-jwt", headers={"Authorization": f"Bearer {tok_api}"}))
        check("Agent JWT verifies (sub, key_id, aud)", v.get("agent_id") == A and v.get("key_id") == KA1
              and v.get("aud") == "aera-agent-api" and v.get("typ") == "agent")
        claims = pyjwt.decode(tok_api, options={"verify_signature": False})
        check("issuer is aeralogin.com", claims.get("iss") == "aeralogin.com")
        check("owner in JWT matches enrolling owner",
              any(str(val).lower() == O for val in claims.values() if isinstance(val, str)))
        r = http.post("/api/agents/verify-jwt", headers={"Authorization": f"Bearer {tok_relay}"})
        check("wrong audience (relay token on API) refused (401)", r.status_code == 401)
        forged_exp = pyjwt.encode({**claims, "iat": claims["iat"] - 7200, "exp": claims["iat"] - 3600},
                                  senv["AGENT_JWT_SECRET"], algorithm="HS256")
        r = http.post("/api/agents/verify-jwt", headers={"Authorization": f"Bearer {secret(forged_exp)}"})
        check("expired Agent JWT refused (401)", r.status_code == 401)
        forged_iss = pyjwt.encode({**claims, "iss": "evil.example"}, senv["AGENT_JWT_SECRET"], algorithm="HS256")
        r = http.post("/api/agents/verify-jwt", headers={"Authorization": f"Bearer {secret(forged_iss)}"})
        check("wrong issuer refused (401)", r.status_code == 401)
        r = http.post("/api/agents/did:aera:agent:" + "0" * 32 + "/challenge",
                      json={"key_id": KA1, "aud": "aera-agent-api"})
        check("unknown agent refused (404)", r.status_code == 404)
        r = http.post(f"/api/agents/{A}/challenge", json={"key_id": KA1, "aud": "aera-a2a-gateway"})
        check("non-allowlisted audience refused (400)", r.status_code == 400)

        # Advanced / manual path: register agent B with a locally generated key.
        signer_b = Ed25519Signer.generate()
        SENSITIVE.add(signer_b.raw_private().hex())
        SENSITIVE.add(b64u_encode(signer_b.raw_private()))
        r = http.post("/api/agents/register", json=owner_body(
            owner, "register", None, public_key=signer_b.public_key_encoded(),
            label="Manual Agent B", capabilities=["agent.authenticate", "agent.read.profile",
                                                   "agent.communicate"]))
        B = J(r).get("agent_id", "")
        check("advanced/manual register (public key) still works", r.status_code == 200 and bool(B))

        def message(sender, key_id, signer, receiver, token, mid=None):
            now = datetime.now(timezone.utc)
            p = {"protocol": PROTO_AGENT_MESSAGE, "version": PROTOCOL_VERSION,
                 "message_id": mid or uuid.uuid4().hex, "sender_agent_id": sender,
                 "sender_key_id": key_id, "receiver_agent_id": receiver,
                 "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                 "expires_at": (now + timedelta(minutes=4)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                 "content_hash": content_hash(b"hello B")}
            sig = b64u_encode(signer(canonical_json(p, AGENT_MESSAGE_KEYS)))
            return http.post("/api/agents/messages", json={"payload": p, "signature": sig,
                                                            "content": "hello B"},
                             headers={"Authorization": f"Bearer {token}"}), p, sig

        r, p, sig = message(A, KA1, store1.sign, B, tok_relay)
        check("signed L2 message A->B relayed (JWT + Ed25519)", r.status_code == 200)
        r = http.post("/api/agents/messages", json={"payload": p, "signature": sig},
                      headers={"Authorization": f"Bearer {tok_relay}"})
        check("replayed L2 message refused (message_replay)", r.status_code == 401 and err(r) == "message_replay")
        r, _, _ = message(A, KA1, signer_b.sign, B, tok_relay)
        check("message signed by a different key refused", r.status_code == 401)
        r, _, _ = message(A, KA1, store1.sign, B, tok_api)
        check("API-audience token refused on the relay (401)", r.status_code == 401)

        # ------------------------------------------------------------------ #
        section("4 external peer (Level 3) via POST /api/a2a")

        def issue(scoped_agents, skills, peer_id=None, sess=S):
            body = {"peer_label": "release-e2e-peer", "scoped_agents": scoped_agents,
                    "scoped_skills": skills}
            if peer_id:
                body["peer_id"] = peer_id
            r = http.post("/api/dashboard/a2a-credentials", json=body, headers=sess)
            j = J(r)
            return r.status_code, secret(j.get("credential", "")), j.get("cred_id"), j.get("peer_id")

        st, _, _, _ = issue([A], ["agent.read.profile"], sess=S_stranger)
        check("owner cannot scope another owner's agent (403)", st == 403)
        st, C1, C1id, PEER = issue([A], ["agent.read.profile", "agent.communicate"])
        check("owner issues peer credential (shown once)", st == 200 and C1.startswith("aera_a2a_"))
        _, C2, _, _ = issue([A], ["agent.read.profile"], peer_id=PEER)

        st, b = a2a(rpc(A), C1)
        check("valid credential: read.profile served", st == 200
              and ((b.get("result") or {}).get("parts") or [{}, {}])[-1].get("data", {}).get("agent", {}).get("agent_id") == A)
        st, b = a2a(rpc(A, "agent.communicate", text="Hello, who are you?"), C1)
        parts = (b.get("result") or {}).get("parts") or []
        reply = next((x.get("text") for x in parts if x.get("kind") == "text"), "")
        data = next((x.get("data") for x in parts if x.get("kind") == "data"), {}) or {}
        check("valid credential: communicate dispatched to runtime, signed reply accepted",
              st == 200 and bool(reply) and (data.get("agent") or {}).get("agent_id") == A,
              json.dumps(b)[:200])

        uniform = []
        unknown = f"aera_a2a_{secrets.token_hex(16)}_{secrets.token_hex(32)}"
        st, b = a2a(rpc(A), unknown)
        uniform.append(json.dumps(b.get("error", {}).get("message")))
        check("unknown credential refused (401)", st == 401)
        st, b = a2a(rpc(A), C1[:-4] + ("beef" if not C1.endswith("beef") else "dead"))
        uniform.append(json.dumps(b.get("error", {}).get("message")))
        check("wrong secret refused (401)", st == 401)
        _, C3, C3id, _ = issue([A], ["agent.read.profile"])
        _, C4, C4id, _ = issue([A], ["agent.read.profile"])
        _, C5, C5id, _ = issue([A], ["agent.read.profile"])
        c = db()
        c.execute("UPDATE a2a_peer_credentials SET audience='aera-agent-api' WHERE cred_id=?", (C3id,))
        c.execute("UPDATE a2a_peer_credentials SET expires_at='2000-01-01T00:00:00Z' WHERE cred_id=?", (C4id,))
        c.commit()
        c.close()
        st, b = a2a(rpc(A), C3)
        uniform.append(json.dumps(b.get("error", {}).get("message")))
        check("wrong credential audience refused (401)", st == 401)
        st, b = a2a(rpc(A), C4)
        uniform.append(json.dumps(b.get("error", {}).get("message")))
        check("expired credential refused (401)", st == 401)
        http.post(f"/api/dashboard/a2a-credentials/{C5id}/revoke", json={"reason": "e2e"}, headers=S)
        st, b = a2a(rpc(A), C5)
        uniform.append(json.dumps(b.get("error", {}).get("message")))
        check("revoked credential refused (401)", st == 401)
        check("all credential failures return one identical message", len(set(uniform)) == 1, str(set(uniform)))
        st, b = a2a(rpc(B), C1)
        check("unauthorized target agent refused", (b.get("error") or {}).get("code") == -32012)
        st, b = a2a(rpc(A, "agent.communicate"), C2)
        check("unauthorized skill refused", (b.get("error") or {}).get("code") == -32012)
        st, b = a2a(rpc(A), tok_api)
        check("AEra Agent JWT as peer credential refused (401)", st == 401)
        r = http.post("/api/agents/verify-jwt", headers={"Authorization": f"Bearer {C1}"})
        check("peer credential refused on /api/agents/verify-jwt (L3 != L2)", r.status_code == 401)
        mid = str(uuid.uuid4())
        a2a(rpc(A, mid=mid), C1)
        st, b = a2a(rpc(A, mid=mid), C1)
        check("replayed A2A messageId refused", "error" in b)
        codes = [a2a(rpc(A), C1, retry=False)[0] for _ in range(45)]
        check("credential rate limit enforced (429 observed)", 429 in codes, str(sorted(set(codes))))
        time.sleep(7)

        # ------------------------------------------------------------------ #
        section("5 trust evidence (monitor only)")
        from a2a_gateway import trust as gw_trust

        def evidence():
            c = db()
            try:
                return {r[0]: r[1] for r in c.execute(
                    "SELECT event_type, COUNT(*) FROM a2a_peer_evidence WHERE peer_id=? "
                    "GROUP BY event_type", (PEER,))}
            finally:
                c.close()

        def assess():
            c = db()
            try:
                return gw_trust.assess_peer(c, PEER)
            finally:
                c.close()

        for _ in range(6):
            a2a(rpc(A), C1)
        ev = evidence()
        print(f"  evidence for peer: {ev}")
        for k in ("request_success", "replay_rejected", "authorization_denied", "rate_limited"):
            check(f"evidence recorded: {k}", ev.get(k, 0) > 0)
        c = db()
        cred_ids = {r[0] for r in c.execute(
            "SELECT DISTINCT credential_id FROM a2a_peer_evidence WHERE peer_id=?", (PEER,))}
        anon = c.execute("SELECT COUNT(*) FROM a2a_peer_evidence WHERE peer_id IS NULL "
                         "OR peer_id=''").fetchone()[0]
        c.close()
        check("evidence rows for this peer come only from its own credential", cred_ids == {C1id})
        check("no evidence without an authenticated peer_id", anon == 0)
        a0 = assess()
        print(f"  assessment: level={a0.trust_level} confidence={a0.confidence:.2f}")
        view = J(http.get("/api/dashboard/a2a-peer-trust", headers=S))
        mine = [p for p in (view.get("peers") or []) if p.get("peer_id") == PEER]
        check("owner trust view lists the peer, not owner-settable",
              len(mine) == 1 and mine[0]["owner_settable"] is False
              and mine[0]["trust_level"] == a0.trust_level)
        check("trust view is owner-scoped (stranger sees none)",
              not (J(http.get("/api/dashboard/a2a-peer-trust", headers=S_stranger)).get("peers")))
        r = http.post("/api/dashboard/a2a-peer-trust", json={"peer_id": PEER, "trust_level": "established"},
                      headers=S)
        check("trust cannot be written via the API", r.status_code in (401, 403, 404, 405))
        st, b = a2a(rpc(B, metadata={"aera_trust_level": "established", "trust_level": "established",
                                     "aera_confidence": 1.0}), C1)
        check("caller-supplied trust fields grant nothing (still out of scope)",
              (b.get("error") or {}).get("code") == -32012)
        a1 = assess()
        check("caller-supplied trust fields did not raise the level",
              gw_trust.level_rank(a1.trust_level) <= gw_trust.level_rank(a0.trust_level))
        st, b = a2a(rpc(A, "agent.communicate"), C2)
        check("trust does not widen scope (C2 still refused for communicate)",
              (b.get("error") or {}).get("code") == -32012)
        c = db()
        check("peer never becomes an L2 agent",
              c.execute("SELECT COUNT(*) FROM agents WHERE agent_id=?", (PEER,)).fetchone()[0] == 0)
        c.close()
        before = sum(evidence().values())
        # A body `peer_id` is never honoured (caller cannot name itself).
        _, _, _, p_http = issue([A], ["agent.read.profile"], peer_id=PEER)
        check("body peer_id is ignored at issuance (caller cannot choose a peer)", p_http != PEER)
        # Rotation over HTTP: name one of the owner's own credentials.
        r = http.post("/api/dashboard/a2a-credentials", headers=S_stranger,
                      json={"rotate_cred_id": C1id, "scoped_agents": [], "scoped_skills": []})
        check("rotating another owner's credential is refused (404)", r.status_code == 404
              and "aera_a2a_" not in r.text)
        r = http.post("/api/dashboard/a2a-credentials", headers=S,
                      json={"rotate_cred_id": C1id, "scoped_agents": [A], "peer_label": "rotated",
                            "scoped_skills": ["agent.read.profile", "agent.communicate"]})
        j = J(r)
        C6, C6id, P6 = secret(j.get("credential", "")), j.get("cred_id"), j.get("peer_id")
        check("HTTP rotation (rotate_cred_id) issues a new credential", r.status_code == 200
              and C6id and C6id != C1id)
        http.post(f"/api/dashboard/a2a-credentials/{C1id}/revoke", json={"reason": "rotated"}, headers=S)
        st, b = a2a(rpc(A), C1)
        check("rotated-out credential refused after revoke", st == 401)
        st, b = a2a(rpc(A), C6)
        check("rotation keeps the same peer_id and history", P6 == PEER and st == 200
              and sum(evidence().values()) > before)
        a2 = assess()
        c = db()
        facts = gw_trust.credential_facts(c, PEER)
        c.close()
        check("revoked credential counted as negative evidence for the peer",
              facts.revoked >= 1 and any(getattr(f, "name", "") == "revoked_credentials"
                                         and f.contribution < 0 for f in a2.factors))
        print(f"  assessment after rotation: level={a2.trust_level} confidence={a2.confidence:.2f}")
        TRUST_OBS = {"evidence": ev, "level_before": a0.trust_level, "conf_before": round(a0.confidence, 2),
                     "level_after": a2.trust_level, "conf_after": round(a2.confidence, 2),
                     "body_peer_id_ignored": p_http != PEER}

        # ------------------------------------------------------------------ #
        section("6 recovery A: runtime lost, key replaced for the SAME agent (advanced)")
        k2 = work / "k2" / "agent_key.json"
        k2.parent.mkdir(mode=0o700)
        pass2 = secret("e2e-pass-" + secrets.token_hex(12))
        from agent_runtime.keystore import LocalKeyStore
        store2 = LocalKeyStore(k2, passphrase=pass2)
        store2.create()
        r = http.post(f"/api/agents/{A}/keys", json=owner_body(owner, "key_add", A,
                                                               public_key=store2.public_key))
        KA2 = J(r).get("key_id", "")
        check("owner adds the new runtime key (owner signature)", r.status_code == 200 and bool(KA2))
        r = http.request("DELETE", f"/api/agents/{A}/keys/{KA1}",
                         json=owner_body(owner, "key_revoke", A, public_key=store1.public_key))
        check("owner revokes the lost key", r.status_code == 200)
        r = http.post("/api/agents/verify-jwt", headers={"Authorization": f"Bearer {tok_api}"})
        check("JWT of the revoked key is dead (cascade)", r.status_code == 401)
        r = http.post(f"/api/agents/{A}/challenge", json={"key_id": KA1, "aud": "aera-agent-api"})
        check("revoked/inactive key cannot get a challenge", r.status_code in (401, 404))
        st, b = a2a(rpc(A, "agent.communicate"), C6)
        check("reply signed by the revoked key is rejected by the gateway",
              "error" in b and "result" not in b, json.dumps(b)[:160])
        run1.stop()
        (k2.with_name("agent_key.identity.json")).write_text(json.dumps(
            {"agent_id": "did:aera:agent:" + "f" * 32, "key_id": "stale", "aera_base_url": base}))
        os.chmod(k2.with_name("agent_key.identity.json"), 0o600)
        run2 = Proc([sys.executable, "-m", "agent_runtime", "run"],
                    runtime_env(k2, pass2, AERA_RUNTIME_AGENT_ID=A, AERA_RUNTIME_KEY_ID=KA2))
        procs.append(run2)
        check("explicit env wins over identity file; runtime runs with new key",
              run2.wait_for("runtime RUNNING", 40) and A in run2.text())
        st, b = a2a(rpc(A, "agent.communicate", text="are you back?"), C6)
        check("A2A to the same agent_id works again with the new key", st == 200 and "result" in b,
              json.dumps(b)[:160])

        # ------------------------------------------------------------------ #
        section("7 agent revocation reaches every enforcement path")
        store2.load()
        idA2 = identity(A, KA2, store2)
        tok2 = secret(idA2.authenticate(aud="aera-agent-api"))
        r = http.request("DELETE", f"/api/agents/{A}", json=owner_body(owner, "agent_revoke", A,
                                                                       public_key=store2.public_key))
        check("owner revokes the agent", r.status_code == 200)
        r = http.post("/api/agents/verify-jwt", headers={"Authorization": f"Bearer {tok2}"})
        check("existing Agent JWT refused after agent revoke", r.status_code == 401)
        from agent_runtime.identity import IdentityError
        try:
            idA2.forget_tokens()
            idA2.authenticate()
            reauth = False
        except IdentityError:
            reauth = True
        check("runtime cannot re-authenticate", reauth)
        st, b = a2a(rpc(A), C6)
        check("gateway refuses the revoked agent as target", "error" in b)
        run2.stop()
        rr = subprocess.run([sys.executable, "-m", "agent_runtime", "run"], cwd=REPO,
                            env=runtime_env(k2, pass2, AERA_RUNTIME_AGENT_ID=A, AERA_RUNTIME_KEY_ID=KA2),
                            capture_output=True, text=True, timeout=60)
        CAPTURED.append(rr.stdout + rr.stderr)
        check("fresh `agent_runtime run` exits 3 (revoked)", rr.returncode == 3, str(rr.returncode))
        c = db()
        st6 = c.execute("SELECT status FROM a2a_peer_credentials WHERE cred_id=?", (C6id,)).fetchone()[0]
        c.close()
        check("peer credential status untouched by agent revoke (separate systems)", st6 == "active")

        # ------------------------------------------------------------------ #
        section("8 recovery B: new machine -> re-enrollment (new agent)")
        bad_reuse = enroll_cli("aera-enroll-0123456789abcdef." + "C" * 32, k1, pass1)
        bad_reuse.p.wait(timeout=30)
        check("enroll refuses a key path that already has an identity", bad_reuse.stop() != 0)
        e4 = J(http.post("/api/dashboard/agents/enrollments", headers=S,
                         json={"label": "Recovered Agent"}))["enrollment"]
        code4 = secret(e4["enrollment_code"])
        k3 = work / "k3" / "agent_key.json"
        k3.parent.mkdir(mode=0o700)
        pass3 = secret("e2e-pass-" + secrets.token_hex(12))
        enr4 = enroll_cli(code4, k3, pass3)
        procs.append(enr4)
        v4 = wait_status(S, e4["enrollment_id"], "key_submitted")
        r = http.post(f"/api/agents/enrollments/{e4['enrollment_id']}/complete",
                      json=owner_body(owner, "register", f"enrollment:{e4['enrollment_id']}"))
        A3 = J(r).get("agent_id", "")
        enr4.p.wait(timeout=60)
        check("re-enrollment: new key, new PoP, owner approval", enr4.stop() == 0 and bool(A3))
        check("re-enrollment yields a NEW agent_id (no in-place pairing rotation)", A3 and A3 != A)
        check("new fingerprint differs from the lost key's", v4.get("key_fingerprint") != fp)
        run3 = Proc([sys.executable, "-m", "agent_runtime", "run"], runtime_env(k3, pass3))
        procs.append(run3)
        check("recovered runtime runs", run3.wait_for("runtime RUNNING", 40) and A3 in run3.text())
        _, C7, _, _ = issue([A3], ["agent.read.profile", "agent.communicate"])
        st, b = a2a(rpc(A3, "agent.communicate", text="hello recovered"), C7)
        check("A2A to the recovered agent works", st == 200 and "result" in b, json.dumps(b)[:160])
        run3.stop()

        # ------------------------------------------------------------------ #
        section("9 secret / log audit")
        for p in procs:
            if p.p.poll() is None:
                p.stop()
        http.close()
        server.send_signal(signal.SIGTERM)
        try:
            server.wait(timeout=20)
        except subprocess.TimeoutExpired:
            server.kill()
        log_fh.close()
        log = log_path.read_text(errors="replace")
        c = db()
        hashes = {r[0] for r in c.execute("SELECT secret_hash FROM a2a_peer_credentials")}
        hashes |= {r[0] for r in c.execute("SELECT secret_hash FROM agent_enrollments")}
        audit = "\n".join(json.dumps(dict(r)) for r in c.execute("SELECT * FROM agent_audit_log"))
        c.close()
        creds = {s for s in SENSITIVE if s.startswith("aera_a2a_")}
        codes = {s for s in SENSITIVE if s.startswith("aera-enroll-")}
        jwts = {s for s in SENSITIVE if s.startswith("eyJ")}
        others = SENSITIVE - creds - codes - jwts
        outputs = "\n".join(CAPTURED)
        runtime_out = "\n".join(p.text() for p in procs)

        def absent(values, hay):
            return not [v for v in values if v and v in hay]
        check("server log: no credential plaintext", absent(creds | {c.rsplit('_', 1)[-1] for c in creds}, log))
        check("server log: no credential/enrollment hashes", absent(hashes, log))
        check("server log: no full enrollment codes", absent(codes | {c.split('.', 1)[1] for c in codes}, log))
        check("server log: no Agent/dashboard JWT", absent(jwts, log) and "eyJ" not in log)
        check("server log: no secrets, passphrases, owner signatures", absent(others, log))
        check("audit log: no secrets/tokens/codes/hashes", absent(SENSITIVE | hashes, audit))
        check("runtime output: no private key, JWT, passphrase, credential",
              absent(SENSITIVE - codes, runtime_out) and "eyJ" not in runtime_out)
        check("runtime output: enrollment code not echoed",
              absent({c.split('.', 1)[1] for c in codes}, runtime_out))
        leaks = [v for v in SENSITIVE | hashes
                 if v and v in outputs and not v.startswith(("aera_a2a_", "aera-enroll-", "eyJ"))]
        check("HTTP responses: no secrets (beyond one-time issuance)", not leaks)
        check("error responses never echo a submitted credential",
              not any(cr in o for cr in creds for o in CAPTURED if '"error"' in o))
        print(f"\n  trust observed: {json.dumps(TRUST_OBS)}")
    except Exception as exc:  # noqa: BLE001
        check(f"unexpected exception: {type(exc).__name__}", False, str(exc)[:200])
    finally:
        for p in procs:
            if p.p.poll() is None:
                p.stop()
        if server.poll() is None:
            server.send_signal(signal.SIGTERM)
            try:
                server.wait(timeout=20)
            except subprocess.TimeoutExpired:
                server.kill()
        if not log_fh.closed:
            log_fh.close()
        if not args.keep:
            shutil.rmtree(work, ignore_errors=True)

    print("\n== RESULT ==")
    by: dict[str, list[bool]] = {}
    for sec, _, ok in RESULTS:
        by.setdefault(sec, []).append(ok)
    for sec, oks in by.items():
        print(f"  {sum(oks):>3}/{len(oks):<3} {sec}")
    total = sum(ok for *_, ok in RESULTS)
    print(f"{total}/{len(RESULTS)} checks passed")
    return 0 if total == len(RESULTS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
