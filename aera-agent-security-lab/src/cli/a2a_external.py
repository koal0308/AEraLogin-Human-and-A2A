"""Live external A2A interoperability runner.

Proves, end to end and against a REAL third-party agent, that:

  1. an AEra agent identity can be established (AEra internal identity layer),
  2. a standard Agent Card can be discovered at the well-known URI,
  3. the external agent's authentication requirement can be satisfied,
  4. a standard A2A JSON-RPC request can be sent,
  5. a valid A2A response comes back.

Every stage is reported separately on purpose. Agent Card discovery alone is
NOT interoperability, so a run that only reaches stage 2 reports FAIL.

The AEra identity is used to authorise the call INSIDE AEra. It is never sent
to the external agent: no AEra JWT, no Ed25519 private key and no owner wallet
key leaves the AEra trust boundary. See docs/external-a2a.md.

Usage:
    cd aera-agent-security-lab
    ../venv/bin/python -m src.cli.a2a_external \
        --agent https://sanctum-beacon.onrender.com \
        --skill community-discovery
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.config.settings import get_settings  # noqa: E402
from src.crypto.aera_crypto import AUD_AGENT_API  # noqa: E402
from src.external_a2a import (  # noqa: E402
    A2AClient,
    A2AError,
    AuditLog,
    NetPolicy,
    build_record,
    describe_required_auth,
    select_adapter,
)
from src.identity.aera_client import AeraError, AeraIdentityClient  # noqa: E402

RULE = "-" * 62
BAR = "=" * 62

DEFAULT_AGENT = "https://sanctum-beacon.onrender.com"
DEFAULT_MESSAGE = "Hello. What is this community and what is it for?"


class Stages:
    """Ordered pass/fail record for the five mandated stages."""

    ORDER = (
        "AEra Identity",
        "Agent Card Discovery",
        "Authentication",
        "A2A Request",
        "A2A Response",
    )

    def __init__(self) -> None:
        self.result: dict[str, str] = {name: "NOT REACHED" for name in self.ORDER}
        self.note: dict[str, str] = {}

    def passed(self, name: str, note: str = "") -> None:
        self.result[name] = "PASS"
        if note:
            self.note[name] = note

    def failed(self, name: str, note: str = "") -> None:
        self.result[name] = "FAIL"
        if note:
            self.note[name] = note

    @property
    def all_passed(self) -> bool:
        return all(self.result[n] == "PASS" for n in self.ORDER)

    def render(self) -> str:
        lines = []
        for name in self.ORDER:
            note = self.note.get(name, "")
            lines.append(f"{name}: {self.result[name]}" + (f"  ({note})" if note else ""))
        return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="a2a_external",
        description="Live interoperability test against one real external A2A agent.",
    )
    p.add_argument("--agent", default=DEFAULT_AGENT,
                   help="external agent origin or Agent Card URL")
    p.add_argument("--skill", default=None, help="skill id to invoke (from the card)")
    p.add_argument("--message", default=None, help="message text to send")
    p.add_argument("--base-url", default=None, help="AEra base URL (default: settings)")
    p.add_argument("--bearer-token", default=None,
                   help="EXTERNAL bearer token, obtained out of band. Never an AEra JWT.")
    p.add_argument("--api-key", default=None, help="EXTERNAL API key, obtained out of band")
    p.add_argument("--api-key-header", default=None, help="header name for --api-key")
    p.add_argument("--timeout", type=float, default=30.0, help="external HTTP timeout (s)")
    p.add_argument("--allow-http", action="store_true",
                   help="permit plain http:// to the external agent (testing only)")
    p.add_argument("--allow-private", action="store_true",
                   help="permit private/loopback targets (local testing only)")
    p.add_argument("--audit-file", default=None, help="append JSONL audit records here")
    p.add_argument("--no-aera", action="store_true",
                   help="skip the AEra identity stage (external-only smoke test)")
    p.add_argument("--keep-agent", action="store_true",
                   help="do not revoke the disposable AEra agent afterwards")
    return p


def _compose_message(args: argparse.Namespace, card) -> tuple[str, Optional[str]]:
    """Return (text, skill_id). A skill id is prefixed the way the card documents."""
    if args.message:
        return args.message, args.skill
    if args.skill:
        return f"{args.skill}: {DEFAULT_MESSAGE}", args.skill
    return DEFAULT_MESSAGE, None


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    settings = get_settings()
    stages = Stages()
    audit = AuditLog(Path(args.audit_file) if args.audit_file else None)

    card = iface = response = None
    adapter = None
    agent_id: Optional[str] = None
    aera: Optional[AeraIdentityClient] = None
    http: Optional[httpx.Client] = None
    error_category: Optional[str] = None
    error_message: Optional[str] = None
    http_status: Optional[int] = None

    print(BAR)
    print("AEra <-> external A2A interoperability run")
    print(BAR)

    try:
        # -- Stage 1: AEra identity -----------------------------------------
        if args.no_aera:
            stages.note["AEra Identity"] = "skipped via --no-aera"
        else:
            base = args.base_url or settings.aera_base_url
            http = httpx.Client(base_url=base, timeout=settings.http_timeout)
            try:
                aera = AeraIdentityClient(http, name="external-a2a-bridge")
                aera.register(label="external-a2a-bridge")
                aera.authenticate(aud=AUD_AGENT_API)
                agent_id = aera.agent_id
                stages.passed("AEra Identity", f"agent_id={agent_id}")
                print(f"{RULE}\nAEra agent registered and authenticated: {agent_id}")
            except AeraError as exc:
                stages.failed("AEra Identity", f"HTTP {exc.status}")
                raise

        # -- Stage 2: Agent Card discovery ----------------------------------
        policy = NetPolicy(
            allow_http=args.allow_http,
            allow_private_addresses=args.allow_private,
            timeout=args.timeout,
        )
        client = A2AClient(policy=policy)
        card, iface = client.discover_agent(args.agent)
        stages.passed("Agent Card Discovery", f"{card.name} @ {iface.url}")
        print(RULE)
        print(f"Agent Card : {card.card_url}")
        print(f"Agent      : {card.name} v{card.version}")
        print(f"Interface  : {iface.protocol_binding} {iface.protocol_version} -> {iface.url}")
        print(f"Skills     : {', '.join(s.id for s in card.skills) or '<none declared>'}")
        print(f"Auth       : {describe_required_auth(card)}")

        # -- Stage 3: authentication ----------------------------------------
        adapter = select_adapter(
            card,
            bearer_token=args.bearer_token,
            api_key=args.api_key,
            api_key_header=args.api_key_header,
        )
        stages.passed("Authentication", f"scheme={adapter.describe()}")
        print(f"{RULE}\nAuth adapter: {adapter.describe()} "
              f"(no AEra credential is forwarded)")

        # -- Stage 4 + 5: request and response -------------------------------
        text, skill_id = _compose_message(args, card)
        print(f"{RULE}\n-> {text}")
        response = client.send_message(card, text, interface=iface, auth=adapter)
        stages.passed("A2A Request", f"id={response.request_id}")
        http_status = 200

        if not response.text and response.kind != "task":
            stages.failed("A2A Response", "valid envelope but no content")
        else:
            stages.passed(
                "A2A Response",
                f"kind={response.kind}" + (f", state={response.state}" if response.state else ""),
            )
        print(f"<- [{response.kind}] {response.text or '<no text parts>'}")

    except A2AError as exc:
        error_category, error_message = exc.category, str(exc)
        http_status = getattr(exc, "status", None)
        stage = {
            "ssrf_blocked": "Agent Card Discovery",
            "network": "Agent Card Discovery" if card is None else "A2A Request",
            "protocol": "Agent Card Discovery" if card is None else "A2A Response",
            "auth": "Authentication",
            "remote": "A2A Response",
        }.get(exc.category, "A2A Request")
        stages.failed(stage, exc.category)
        print(f"{RULE}\nERROR [{exc.category}] {exc}")
    except AeraError as exc:
        error_category, error_message = "aera_identity", str(exc)
        http_status = exc.status
        print(f"{RULE}\nERROR [aera_identity] {exc}")
    finally:
        # Cleanup: the disposable AEra agent must not survive the run.
        if aera is not None and aera.agent_id and not args.keep_agent:
            try:
                r = aera.revoke()
                print(f"{RULE}\nAEra agent revoked: HTTP {r.status_code}")
            except Exception as exc:  # cleanup must never mask the real result
                print(f"{RULE}\nAEra agent revoke FAILED: {type(exc).__name__}")
        if http is not None:
            http.close()

    record = build_record(
        aera_agent_id=agent_id,
        card=card,
        interface=iface,
        skill_id=args.skill,
        auth_scheme=adapter.describe() if adapter else "none",
        http_status=http_status,
        request_id=getattr(response, "request_id", None),
        task_id=getattr(response, "task_id", None),
        success=stages.all_passed,
        error_category=error_category,
        error_message=error_message,
        response_kind=getattr(response, "kind", None),
    )
    audit.append(record)

    print(BAR)
    print(stages.render())
    print(BAR)
    print("AUDIT")
    print(audit.render())
    print(BAR)

    if stages.all_passed:
        print(f"RESULT: AEra successfully interoperated with {card.name!r} "
              f"using the standard A2A protocol.")
        return 0
    print("RESULT: FAIL -- external A2A interoperability was NOT demonstrated.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
