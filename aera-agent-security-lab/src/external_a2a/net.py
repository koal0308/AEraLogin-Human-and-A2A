"""SSRF-hardened HTTP layer for talking to arbitrary third-party agents.

Everything the adapter fetches is attacker-influenced: a dashboard user could
name any URL, and a malicious Agent Card could redirect us anywhere. So this
module is the single choke point and enforces, in order:

  1. scheme policy        -- https required (http only when explicitly allowed)
  2. no credentials in URL
  3. port allowlist
  4. DNS resolution + rejection of every non-public address
  5. connect/read timeout, separate from the LLM provider budget
  6. redirects followed MANUALLY, re-validating each hop
  7. streamed response with a hard byte ceiling
  8. safe JSON decoding

DNS rebinding is closed by PINNING. The hostname is resolved exactly once per
hop; every resolved address must pass the policy; the connection is then made to
one validated IP literal, while the original hostname is preserved for the Host
header and for TLS SNI (so certificate verification still happens against the
real hostname, not against the IP). There is therefore no second, unchecked
resolution between validation and connection.
"""
from __future__ import annotations

import ipaddress
import json
import socket
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlsplit, urlunsplit

import httpx

from .errors import A2ANetworkError, A2AProtocolError, SSRFBlocked

#: Ports a public A2A agent may plausibly listen on.
ALLOWED_PORTS = frozenset({80, 443, 8080, 8443})

#: Hard ceiling for any external response body.
MAX_RESPONSE_BYTES = 2 * 1024 * 1024  # 2 MiB

#: Connect/read budget for external agents. Deliberately NOT the LLM provider
#: timeout -- the lab already learned that conflating them hides real stalls.
DEFAULT_EXTERNAL_TIMEOUT = 30.0

MAX_REDIRECTS = 3


@dataclass(frozen=True)
class NetPolicy:
    """How permissive we are about where we will send traffic."""

    allow_http: bool = False
    #: Only ever enabled by tests/local development, never by a dashboard user.
    allow_private_addresses: bool = False
    timeout: float = DEFAULT_EXTERNAL_TIMEOUT
    max_bytes: int = MAX_RESPONSE_BYTES
    allowed_ports: frozenset = field(default_factory=lambda: ALLOWED_PORTS)
    #: Connect to the validated IP instead of re-resolving. Closes the DNS
    #: rebinding window. Only ever disabled to demonstrate the attack in tests.
    pin_dns: bool = True


def _address_is_public(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def resolve_and_validate(url: str, policy: NetPolicy) -> list[str]:
    """Validate a URL against the policy. Returns the resolved IPs.

    Raises SSRFBlocked for anything we refuse to contact.
    """
    parts = urlsplit(url)
    scheme = (parts.scheme or "").lower()

    if scheme not in ("http", "https"):
        raise SSRFBlocked(f"unsupported URL scheme: {scheme or '<none>'}")
    if scheme == "http" and not policy.allow_http:
        raise SSRFBlocked("plain http is not allowed for external agents; use https")
    if parts.username or parts.password:
        raise SSRFBlocked("credentials embedded in URL are not accepted")

    host = parts.hostname
    if not host:
        raise SSRFBlocked("URL has no host")

    port = parts.port or (443 if scheme == "https" else 80)
    if port not in policy.allowed_ports:
        raise SSRFBlocked(f"port {port} is not in the allowed port set")

    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise A2ANetworkError(f"cannot resolve host {host!r}", detail=str(exc)) from exc

    ips = sorted({i[4][0] for i in infos})
    if not ips:
        raise A2ANetworkError(f"host {host!r} resolved to no addresses")

    if not policy.allow_private_addresses:
        for ip in ips:
            if not _address_is_public(ip):
                raise SSRFBlocked(
                    f"host {host!r} resolves to non-public address {ip}"
                )
    return ips


def pin_url_to_ip(url: str, ip: str) -> tuple[str, str, str]:
    """Rewrite a URL to target a validated IP literal.

    Returns (pinned_url, host_header, sni_hostname).

    The hostname is preserved in the Host header and for TLS SNI, so the
    certificate is still verified against the real hostname. Only the address
    we dial is fixed -- which is exactly what removes the rebinding window.
    """
    parts = urlsplit(url)
    host = parts.hostname or ""
    literal = f"[{ip}]" if ":" in ip else ip
    netloc = f"{literal}:{parts.port}" if parts.port else literal
    pinned = urlunsplit((parts.scheme, netloc, parts.path, parts.query, ""))
    host_header = f"{host}:{parts.port}" if parts.port else host
    return pinned, host_header, host


def _read_limited(resp: httpx.Response, max_bytes: int) -> bytes:
    body = bytearray()
    for chunk in resp.iter_bytes():
        body.extend(chunk)
        if len(body) > max_bytes:
            resp.close()
            raise A2ANetworkError(
                f"external response exceeded {max_bytes} bytes"
            )
    return bytes(body)


def request(
    method: str,
    url: str,
    *,
    policy: NetPolicy,
    headers: Optional[dict[str, str]] = None,
    json_body: Any = None,
    client: Optional[httpx.Client] = None,
) -> tuple[int, dict[str, str], bytes]:
    """Perform one guarded request, following redirects manually.

    Returns (status_code, headers, body_bytes). Never raises for HTTP status --
    the caller decides what a 401 or 400 means.
    """
    owned = client is None
    cli = client or httpx.Client(timeout=policy.timeout, follow_redirects=False)
    try:
        current = url
        for _ in range(MAX_REDIRECTS + 1):
            ips = resolve_and_validate(current, policy)

            # Pin to a validated address. The hostname survives in the Host
            # header and in SNI, so TLS verification is unaffected.
            target = current
            hop_headers = dict(headers or {})
            extensions: dict[str, Any] = {}
            if policy.pin_dns:
                target, host_header, sni = pin_url_to_ip(current, ips[0])
                hop_headers["Host"] = host_header
                extensions["sni_hostname"] = sni

            try:
                with cli.stream(
                    method,
                    target,
                    headers=hop_headers,
                    json=json_body,
                    timeout=policy.timeout,
                    follow_redirects=False,
                    extensions=extensions,
                ) as resp:
                    body = _read_limited(resp, policy.max_bytes)
                    status = resp.status_code
                    hdrs = {k.lower(): v for k, v in resp.headers.items()}
            except httpx.TimeoutException as exc:
                raise A2ANetworkError(
                    f"external agent timed out after {policy.timeout}s", detail=str(exc)
                ) from exc
            except httpx.HTTPError as exc:
                raise A2ANetworkError(
                    f"transport error talking to external agent: {type(exc).__name__}",
                    detail=str(exc),
                ) from exc

            if status in (301, 302, 303, 307, 308) and "location" in hdrs:
                current = str(httpx.URL(current).join(hdrs["location"]))
                continue
            return status, hdrs, body

        raise A2ANetworkError("too many redirects from external agent")
    finally:
        if owned:
            cli.close()


def decode_json(body: bytes, *, what: str) -> Any:
    """Parse untrusted JSON without letting a decode blow up the runtime."""
    if not body:
        raise A2AProtocolError(f"{what}: empty response body")
    try:
        return json.loads(body.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise A2AProtocolError(f"{what}: response is not valid UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise A2AProtocolError(
            f"{what}: response is not valid JSON", detail=str(exc)
        ) from exc
