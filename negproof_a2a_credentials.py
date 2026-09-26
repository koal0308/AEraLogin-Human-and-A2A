#!/usr/bin/env python3
"""Negative proof for the external A2A peer credential layer.

A passing test suite proves that the code does what the tests expect. It does
NOT prove the tests would notice if the code were wrong. This script breaks the
implementation on purpose, one defect at a time, and asserts the suite turns
red. A mutant that survives means the corresponding property is unguarded -- the
green tick was decoration.

Each mutant is a plausible mistake: something a tired developer, a careless
refactor or a bad merge could realistically produce.

Usage:  ./venv/bin/python negproof_a2a_credentials.py
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
GW = ROOT / "a2a_gateway"
SUITE = "tests/agent/test_a2a_credentials.py"

#: (label, file, find, replace)
MUTANTS: list[tuple[str, Path, str, str]] = [
    (
        "credentials.py: store the secret in plaintext instead of its hash",
        GW / "credentials.py",
        "(record.cred_id, record.peer_id, record.peer_label, hash_secret(secret),",
        "(record.cred_id, record.peer_id, record.peer_label, secret,",
    ),
    (
        "credentials.py: compare secrets with == instead of compare_digest",
        GW / "credentials.py",
        "if not hmac.compare_digest(stored_hash or \"\", hash_secret(secret)):",
        "if (stored_hash or \"\") != hash_secret(secret):",
    ),
    (
        "credentials.py: skip the revocation check",
        GW / "credentials.py",
        "    if record.status != STATUS_ACTIVE:",
        "    if False:",
    ),
    (
        "credentials.py: skip the expiry check",
        GW / "credentials.py",
        "    if expires is None or expires <= moment:",
        "    if False:",
    ),
    (
        "credentials.py: treat an unparsable expiry as valid forever",
        GW / "credentials.py",
        "    if expires is None or expires <= moment:",
        "    if expires is not None and expires <= moment:",
    ),
    (
        "credentials.py: accept any audience",
        GW / "credentials.py",
        "    if record.audience != CREDENTIAL_AUDIENCE:",
        "    if False:",
    ),
    (
        "credentials.py: distinguish 'unknown' from 'bad secret' in the message",
        GW / "credentials.py",
        'raise CredentialError("unknown_credential")',
        'raise CredentialError("unknown_credential", "no such credential id")',
    ),
    (
        "credentials.py: ignore agent scoping (authorise everything)",
        GW / "credentials.py",
        "    if record.scoped_agents and target_agent_id not in record.scoped_agents:",
        "    if False:",
    ),
    (
        "credentials.py: ignore skill scoping",
        GW / "credentials.py",
        "        if skill_id not in record.scoped_skills:",
        "        if False:",
    ),
    (
        "credentials.py: query the store before validating the format",
        GW / "credentials.py",
        "    cred_id, secret = parse_credential(raw)\n    moment = now or _now()",
        "    moment = now or _now()\n    conn.execute(f\"SELECT 1 FROM {TABLE}\")\n"
        "    cred_id, secret = parse_credential(raw)",
    ),
    (
        "credentials.py: let any owner revoke any credential",
        GW / "credentials.py",
        "\"WHERE cred_id = ? AND owner_address = ? AND status = ?\",",
        "\"WHERE cred_id = ? AND (owner_address = ? OR 1=1) AND status = ?\",",
    ),
    (
        "credentials.py: DELETE on revoke, destroying the audit trail",
        GW / "credentials.py",
        f"        f\"UPDATE {{TABLE}} SET status = ?, revoked_at = ?, revoked_reason = ? \"",
        f"        f\"DELETE FROM {{TABLE}} WHERE 0 = ? AND 0 = ? AND 0 = ? \"",
    ),
    (
        "credentials.py: ownership check ignores the owner",
        GW / "credentials.py",
        "\"AND lower(owner_wallet) = ?\",",
        "\"AND lower(owner_wallet) != ?\",",
    ),
    (
        "credentials.py: shorten the secret to 32 bits",
        GW / "credentials.py",
        "SECRET_BYTES = 32",
        "SECRET_BYTES = 4",
    ),
    (
        "auth.py: accept an AEra agent JWT as a peer credential",
        GW / "auth.py",
        "    if _looks_like_a_jwt(credential):",
        "    if False:",
    ),
    (
        "auth.py: a broken credential store grants anonymous access anyway",
        GW / "auth.py",
        "        except Exception:  # noqa: BLE001 - a broken store must not grant access\n"
        "            raise InboundAuthError(_cred.OPAQUE_AUTH_FAILURE) from None\n\n"
        "        _cred.touch(conn, record.cred_id)",
        "        except Exception:  # noqa: BLE001\n"
        "            return anonymous_peer(claimed_agent_id)\n\n"
        "        _cred.touch(conn, record.cred_id)",
    ),
    (
        "auth.py: 'required' policy silently falls back to optional",
        GW / "auth.py",
        "    return AUTH_POLICY_REQUIRED if value == AUTH_POLICY_REQUIRED else DEFAULT_AUTH_POLICY",
        "    return DEFAULT_AUTH_POLICY",
    ),
    (
        "auth.py: an API key satisfies the 'required' policy",
        GW / "auth.py",
        "        if authentication_required():\n"
        "            raise InboundAuthError(\n"
        "                \"this gateway requires an external peer credential\")\n"
        "        return ExternalPeerIdentity(\n"
        "            external_agent_id=claimed_agent_id,\n"
        "            authentication_method=AUTH_API_KEY,",
        "        return ExternalPeerIdentity(\n"
        "            external_agent_id=claimed_agent_id,\n"
        "            authentication_method=AUTH_API_KEY,",
    ),
    (
        "peer.py: trust the caller's claimed id as the authenticated principal",
        GW / "peer.py",
        "        authenticated_principal=record.peer_id,",
        "        authenticated_principal=claimed_id or record.peer_id,",
    ),
    (
        "peer.py: an authenticated external peer becomes a trusted AEra agent",
        GW / "peer.py",
        "        Kept as an explicit property so that any future code which *wants* to\n"
        "        make that leap has to delete this method deliberately rather than do it\n"
        "        by accident.\n"
        "        \"\"\"\n"
        "        return False",
        "        \"\"\"\n"
        "        return self.authentication_status == STATUS_AUTHENTICATED",
    ),
    (
        "handler.py: drop the authorisation check entirely",
        GW / "handler.py",
        "        if peer.is_authenticated and not authorize_request(",
        "        if False and not authorize_request(",
    ),
    (
        "handler.py: authorisation failure reveals that the agent exists",
        GW / "handler.py",
        'ERR_FORBIDDEN, "target agent is not available",',
        'ERR_FORBIDDEN, "you are not scoped for this agent",',
    ),
    (
        "handler.py: authenticated callers skip the credential rate limit",
        GW / "handler.py",
        "        if peer.is_authenticated and peer.credential_id:",
        "        if False:",
    ),
    (
        "ratelimit.py: remove the credential scope",
        GW / "ratelimit.py",
        "        SCOPE_CREDENTIAL: Limit(",
        "        \"unused_scope\": Limit(",
    ),
    (
        "card.py: claim protection the gateway does not enforce",
        GW / "card.py",
        "    required = [{SECURITY_SCHEME_NAME: []}] if authentication_required() else []",
        "    required = [{SECURITY_SCHEME_NAME: []}]",
    ),
    (
        "card.py: stay silent about a required credential",
        GW / "card.py",
        "    required = [{SECURITY_SCHEME_NAME: []}] if authentication_required() else []",
        "    required = []",
    ),
    (
        "server.py: take the owner from the request body",
        ROOT / "server.py",
        "    owner = _dashboard_owner_from_request(req)\n"
        "    if not owner:\n"
        "        return JSONResponse(status_code=401,\n"
        "                            content={\"success\": False, \"error\": \"unauthorized\"})\n"
        "    try:\n"
        "        from a2a_gateway import credentials as _gw_cred\n"
        "        from a2a_gateway.constants import SUPPORTED_SKILLS",
        "    owner = _dashboard_owner_from_request(req)\n"
        "    if not owner:\n"
        "        return JSONResponse(status_code=401,\n"
        "                            content={\"success\": False, \"error\": \"unauthorized\"})\n"
        "    try:\n"
        "        from a2a_gateway import credentials as _gw_cred\n"
        "        from a2a_gateway.constants import SUPPORTED_SKILLS\n"
        "        owner = (await req.json()).get(\"owner\", owner)",
    ),
    (
        "server.py: allow scoping to another owner's agent",
        ROOT / "server.py",
        "            if not_owned:",
        "            if False:",
    ),
    (
        "server.py: return the plaintext credential in the listing too",
        ROOT / "server.py",
        "        return {\"success\": True,\n"
        "                \"credentials\": [r.to_owner_dict() for r in records]}",
        "        return {\"success\": True,\n"
        "                \"credentials\": [dict(r.to_owner_dict(),\n"
        "                                     secret=\"" + "aera_a2a_x_y" + "\")\n"
        "                                for r in records]}",
    ),
]


def run_suite() -> tuple[bool, str]:
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", SUITE, "-x", "-q", "--no-header"],
        cwd=ROOT, capture_output=True, text=True,
    )
    tail = (proc.stdout or "").strip().splitlines()
    return proc.returncode == 0, tail[-1] if tail else ""


def main() -> int:
    print("=" * 78)
    print("NEGATIVE PROOF -- external A2A peer credentials")
    print("=" * 78)

    ok, summary = run_suite()
    if not ok:
        print(f"\nBASELINE IS RED -- fix that first.\n  {summary}")
        return 2
    print(f"\nBaseline: {summary}\n")

    caught, survived = 0, []

    for index, (label, path, find, replace) in enumerate(MUTANTS, 1):
        original = path.read_text(encoding="utf-8")
        if find not in original:
            print(f"[{index:2}/{len(MUTANTS)}] !! ANCHOR MISSING -- {label}")
            survived.append((label, "anchor not found; mutant never applied"))
            continue
        if original.count(find) > 1:
            print(f"[{index:2}/{len(MUTANTS)}] !! AMBIGUOUS ANCHOR -- {label}")
            survived.append((label, "anchor matches more than once"))
            continue

        path.write_text(original.replace(find, replace, 1), encoding="utf-8")
        try:
            passed, summary = run_suite()
        finally:
            path.write_text(original, encoding="utf-8")

        if passed:
            print(f"[{index:2}/{len(MUTANTS)}] SURVIVED  {label}")
            survived.append((label, summary))
        else:
            caught += 1
            print(f"[{index:2}/{len(MUTANTS)}] caught    {label}")

    print("\n" + "=" * 78)
    print(f"RESULT: {caught}/{len(MUTANTS)} mutants caught")
    if survived:
        print("\nSURVIVING MUTANTS -- these properties are NOT protected:")
        for label, detail in survived:
            print(f"  - {label}\n      {detail}")
    print("=" * 78)

    ok, summary = run_suite()
    print(f"Baseline restored: {summary}")
    return 0 if (not survived and ok) else 1


if __name__ == "__main__":
    raise SystemExit(main())
