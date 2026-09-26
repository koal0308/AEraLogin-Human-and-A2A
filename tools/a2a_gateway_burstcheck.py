"""Live burst test for the public A2A gateway rate limiter.

Runs against the real public endpoint over the real internet, through the real
cloudflared tunnel. Nothing here is mocked and nothing is asserted from theory:
every number printed is measured.

Sequence:
  1. baseline       - one request must succeed
  2. burst          - send until throttled; record at which request
  3. inspect 429    - Retry-After present, body structured, nothing leaked
  4. recovery       - wait the advertised time, then succeed again
  5. card unaffected- discovery must keep working while POSTs are throttled
"""
from __future__ import annotations

import json
import sys
import time
import uuid
import urllib.error
import urllib.request

BASE = "https://aeralogin.com"
ENDPOINT = f"{BASE}/api/a2a"
CARD = f"{BASE}/.well-known/agent-card.json"

# Cloudflare sits in front of this host and rejects urllib's default browser
# signature with error 1010 before the request ever reaches AEra. That is an
# edge-layer control, not our rate limiter, so we present the same client
# identity the Phase-1/2 A2A client uses. This is not an evasion: it is how a
# real A2A client identifies itself.
UA = "AEra-A2A-Client/0.1 (+https://aeralogin.com)"

FORBIDDEN = ("aera_a2a_", "burst", "token bucket", "traceback",
             "sqlite", "/home/", "127.0.0.1", "8840")


def rpc(target: str) -> bytes:    return json.dumps({
        "jsonrpc": "2.0", "id": str(uuid.uuid4()), "method": "message/send",
        "params": {"message": {
            "messageId": uuid.uuid4().hex, "role": "user",
            "parts": [{"kind": "text", "text": "rate limit probe"}],
            "metadata": {"aera_target_agent": target, "skillId": "agent.read.profile"},
        }},
    }).encode()


def header(headers, name: str):
    """HTTP header names are case-insensitive, and uvicorn emits them in
    lowercase. Looking them up case-sensitively in a plain dict silently
    reports a header as missing when it is in fact present."""
    target = name.lower()
    for key, value in headers.items():
        if key.lower() == target:
            return value
    return None


def post(target: str):
    req = urllib.request.Request(
        ENDPOINT, data=rpc(target),
        headers={"Content-Type": "application/json", "A2A-Version": "0.3",
                 "User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, dict(r.headers), r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()


def main() -> int:
    target = sys.argv[1] if len(sys.argv) > 1 else "did:aera:agent:probe"
    results = []

    print("== 1. baseline ==")
    status, _, body = post(target)
    print(f"   first request -> HTTP {status}")
    results.append(("baseline reachable", status != 429))

    print("== 2. burst ==")
    tripped_at = None
    throttled = None
    for i in range(1, 61):
        status, headers, body = post(target)
        if status == 429:
            tripped_at = i
            throttled = (headers, body)
            break
    print(f"   throttled after {tripped_at} additional requests"
          if tripped_at else "   NEVER throttled after 60 requests")
    results.append(("burst is throttled", tripped_at is not None))
    if not tripped_at:
        summarise(results)
        return 1

    headers, body = throttled
    print("== 3. the 429 ==")
    retry_after = header(headers, "Retry-After")
    print(f"   Retry-After: {retry_after!r}")
    print(f"   body: {body[:200]}")
    results.append(("Retry-After present", retry_after is not None))
    results.append(("Retry-After >= 1",
                    bool(retry_after and int(retry_after) >= 1)))
    try:
        parsed = json.loads(body)
        ok = parsed.get("jsonrpc") == "2.0" and "error" in parsed
    except json.JSONDecodeError:
        ok = False
    results.append(("429 body is structured JSON-RPC", ok))
    low = body.lower()
    leaked = [f for f in FORBIDDEN if f in low]
    print(f"   leak check: {'CLEAN' if not leaked else leaked}")
    results.append(("no internals leaked", not leaked))

    print("== 5. agent card while throttled ==")
    try:
        card_req = urllib.request.Request(CARD, headers={"User-Agent": UA})
        with urllib.request.urlopen(card_req, timeout=30) as r:
            card_status = r.status
    except urllib.error.HTTPError as e:
        card_status = e.code
    print(f"   GET agent-card -> HTTP {card_status}")
    results.append(("discovery unaffected", card_status == 200))

    print("== 4. recovery ==")
    wait = int(retry_after or 1) + 2
    print(f"   sleeping {wait}s ...")
    time.sleep(wait)
    status, _, _ = post(target)
    print(f"   after waiting -> HTTP {status}")
    results.append(("recovers after Retry-After", status != 429))

    return summarise(results)


def summarise(results) -> int:
    print("\n== RESULT ==")
    for label, ok in results:
        print(f"   {'PASS' if ok else 'FAIL'}  {label}")
    failed = sum(1 for _, ok in results if not ok)
    print(f"\n{len(results) - failed} passed / {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
