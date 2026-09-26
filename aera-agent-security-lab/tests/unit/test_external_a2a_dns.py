"""DNS security: rebinding, private resolution and redirect-based SSRF.

The point of these tests is that validation and connection must refer to the
SAME address. A guard that validates a hostname and then lets the HTTP library
resolve it again is not a guard at all -- so several of these tests attack the
gap between the two steps directly.
"""
from __future__ import annotations

import socket
import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.external_a2a.errors import SSRFBlocked  # noqa: E402
from src.external_a2a.net import (  # noqa: E402
    NetPolicy,
    pin_url_to_ip,
    request,
    resolve_and_validate,
)

PUBLIC_IP = "93.184.216.34"
PRIVATE_IP = "10.1.2.3"
LOOPBACK = "127.0.0.1"
PRIVATE_V6 = "fd00::1"
METADATA = "169.254.169.254"


def fake_resolver(*sequences):
    """getaddrinfo stub returning the next address set on each call."""
    calls = {"n": 0}

    def _resolve(host, port, *a, **kw):
        idx = min(calls["n"], len(sequences) - 1)
        calls["n"] += 1
        addrs = sequences[idx]
        if not addrs:
            raise socket.gaierror("no address")
        family = lambda ip: socket.AF_INET6 if ":" in ip else socket.AF_INET  # noqa: E731
        return [(family(ip), socket.SOCK_STREAM, 6, "", (ip, port)) for ip in addrs]

    _resolve.calls = calls
    return _resolve


def capturing_client():
    """Records the address each request was actually dialled at."""
    seen = []

    def handler(req):
        seen.append({"host": req.url.host, "headers": dict(req.headers),
                     "ext": req.extensions})
        return httpx.Response(200, json={"ok": True})

    client = httpx.Client(transport=httpx.MockTransport(handler),
                          follow_redirects=False)
    return client, seen


# -- 27/28/29: DNS resolving into ranges we must never contact ---------------
def test_dns_resolving_to_private_ipv4_is_blocked(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", fake_resolver([PRIVATE_IP]))
    with pytest.raises(SSRFBlocked) as exc:
        resolve_and_validate("https://evil.test/a2a", NetPolicy())
    assert PRIVATE_IP in str(exc.value)


def test_dns_resolving_to_loopback_is_blocked(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", fake_resolver([LOOPBACK]))
    with pytest.raises(SSRFBlocked):
        resolve_and_validate("https://evil.test/a2a", NetPolicy())


def test_dns_resolving_to_private_ipv6_is_blocked(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", fake_resolver([PRIVATE_V6]))
    with pytest.raises(SSRFBlocked):
        resolve_and_validate("https://evil.test/a2a", NetPolicy())


def test_ipv4_mapped_ipv6_loopback_is_blocked(monkeypatch):
    """::ffff:127.0.0.1 is loopback wearing a costume."""
    monkeypatch.setattr(socket, "getaddrinfo", fake_resolver(["::ffff:127.0.0.1"]))
    with pytest.raises(SSRFBlocked):
        resolve_and_validate("https://evil.test/a2a", NetPolicy())


def test_one_private_address_among_public_ones_blocks_the_whole_host(monkeypatch):
    """A split-horizon answer must not be salvageable by picking a good IP."""
    monkeypatch.setattr(socket, "getaddrinfo", fake_resolver([PUBLIC_IP, PRIVATE_IP]))
    with pytest.raises(SSRFBlocked):
        resolve_and_validate("https://evil.test/a2a", NetPolicy())


# -- 32: cloud metadata ------------------------------------------------------
def test_metadata_endpoint_by_ip_is_blocked():
    with pytest.raises(SSRFBlocked):
        resolve_and_validate(f"https://{METADATA}/latest/meta-data/", NetPolicy())


def test_metadata_endpoint_via_hostname_is_blocked(monkeypatch):
    """The classic bypass: a public name that resolves to the metadata IP."""
    monkeypatch.setattr(socket, "getaddrinfo", fake_resolver([METADATA]))
    with pytest.raises(SSRFBlocked):
        resolve_and_validate("https://metadata.attacker.test/", NetPolicy())


# -- 30: rebinding -----------------------------------------------------------
def test_connection_is_pinned_to_the_validated_address(monkeypatch):
    """The dialled host must be the IP we checked, not the name."""
    monkeypatch.setattr(socket, "getaddrinfo", fake_resolver([PUBLIC_IP]))
    client, seen = capturing_client()
    request("GET", "https://agent.test/a2a", policy=NetPolicy(), client=client)
    assert seen[0]["host"] == PUBLIC_IP


def test_dns_rebinding_after_validation_cannot_redirect_the_connection(monkeypatch):
    """First answer public (passes the check), second answer private.

    Without pinning the second answer would be used for the actual connection.
    With pinning the connection still goes to the validated public IP.
    """
    resolver = fake_resolver([PUBLIC_IP], [PRIVATE_IP], [PRIVATE_IP])
    monkeypatch.setattr(socket, "getaddrinfo", resolver)
    client, seen = capturing_client()
    request("GET", "https://rebind.test/a2a", policy=NetPolicy(), client=client)
    assert seen[0]["host"] == PUBLIC_IP
    assert seen[0]["host"] != PRIVATE_IP


def test_original_hostname_is_preserved_for_host_header_and_sni(monkeypatch):
    """Pinning must not break virtual hosting or certificate verification."""
    monkeypatch.setattr(socket, "getaddrinfo", fake_resolver([PUBLIC_IP]))
    client, seen = capturing_client()
    request("GET", "https://agent.test/a2a", policy=NetPolicy(), client=client)
    assert seen[0]["headers"]["host"] == "agent.test"
    assert seen[0]["ext"]["sni_hostname"] == "agent.test"


def test_pinning_resolves_the_hostname_exactly_once_per_hop(monkeypatch):
    """No second, unchecked resolution between validation and connection."""
    resolver = fake_resolver([PUBLIC_IP])
    monkeypatch.setattr(socket, "getaddrinfo", resolver)
    client, _ = capturing_client()
    request("GET", "https://agent.test/a2a", policy=NetPolicy(), client=client)
    assert resolver.calls["n"] == 1


def test_pin_url_to_ip_preserves_path_query_and_port():
    pinned, host, sni = pin_url_to_ip("https://a.test:8443/a2a?x=1", PUBLIC_IP)
    assert pinned == f"https://{PUBLIC_IP}:8443/a2a?x=1"
    assert host == "a.test:8443" and sni == "a.test"


def test_pin_url_to_ip_brackets_ipv6():
    pinned, _, _ = pin_url_to_ip("https://a.test/a2a", "2606:4700::1111")
    assert pinned.startswith("https://[2606:4700::1111]/")


# -- 31: redirect-based SSRF -------------------------------------------------
def test_redirect_to_a_private_ip_is_blocked(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", fake_resolver([PUBLIC_IP]))

    def handler(req):
        return httpx.Response(302, headers={"Location": f"http://{PRIVATE_IP}:8080/x"})

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    with pytest.raises(SSRFBlocked):
        request("GET", "https://agent.test/a2a", policy=NetPolicy(), client=client)


def test_redirect_to_the_metadata_endpoint_is_blocked(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", fake_resolver([PUBLIC_IP]))

    def handler(req):
        return httpx.Response(302, headers={"Location": f"http://{METADATA}/latest/"})

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    with pytest.raises(SSRFBlocked):
        request("GET", "https://agent.test/a2a", policy=NetPolicy(), client=client)


def test_redirect_hop_is_revalidated_and_repinned(monkeypatch):
    """A legitimate redirect must itself be resolved, checked and pinned."""
    second_ip = "93.184.216.35"
    monkeypatch.setattr(socket, "getaddrinfo", fake_resolver([PUBLIC_IP], [second_ip]))
    seen = []

    def handler(req):
        seen.append(req.url.host)
        if len(seen) == 1:
            return httpx.Response(302, headers={"Location": "https://other.test/final"})
        return httpx.Response(200, json={})

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    status, _, _ = request("GET", "https://agent.test/a2a", policy=NetPolicy(),
                           client=client)
    assert status == 200
    assert seen == [PUBLIC_IP, second_ip]


def test_redirect_to_a_non_http_scheme_is_blocked(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", fake_resolver([PUBLIC_IP]))

    def handler(req):
        return httpx.Response(302, headers={"Location": "file:///etc/passwd"})

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    with pytest.raises(SSRFBlocked):
        request("GET", "https://agent.test/a2a", policy=NetPolicy(), client=client)


# -- the guard is genuinely load-bearing ------------------------------------
def test_without_pinning_the_rebound_address_would_be_used(monkeypatch):
    """Demonstrates the attack the pinning prevents (pin_dns disabled)."""
    monkeypatch.setattr(socket, "getaddrinfo", fake_resolver([PUBLIC_IP], [PRIVATE_IP]))
    client, seen = capturing_client()
    request("GET", "https://rebind.test/a2a",
            policy=NetPolicy(pin_dns=False), client=client)
    # Unpinned, the hostname reaches the transport and would be re-resolved.
    assert seen[0]["host"] == "rebind.test"
