"""Network policy: SSRF guards, size caps, redirect handling, JSON decoding.

These tests use httpx.MockTransport so that no unit test depends on the
internet. The SSRF tests use real DNS names that are guaranteed by RFC to
resolve locally or to reserved space, so no external lookup is required either.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.external_a2a.errors import A2ANetworkError, A2AProtocolError, SSRFBlocked  # noqa: E402
from src.external_a2a.net import (  # noqa: E402
    ALLOWED_PORTS,
    NetPolicy,
    _address_is_public,
    decode_json,
    request,
    resolve_and_validate,
)

OPEN = NetPolicy(allow_private_addresses=True)


def mock_client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)


# -- address classification --------------------------------------------------
@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1",
                                "169.254.169.254", "0.0.0.0", "::1", "::ffff:127.0.0.1"])
def test_private_and_reserved_addresses_are_not_public(ip):
    assert _address_is_public(ip) is False


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
def test_public_addresses_are_public(ip):
    assert _address_is_public(ip) is True


def test_cloud_metadata_endpoint_is_blocked():
    """169.254.169.254 is the classic SSRF target."""
    with pytest.raises(SSRFBlocked):
        resolve_and_validate("https://169.254.169.254/latest/meta-data/", NetPolicy())


# -- URL policy --------------------------------------------------------------
def test_plain_http_is_rejected_by_default():
    with pytest.raises(SSRFBlocked) as exc:
        resolve_and_validate("http://example.com/a2a", NetPolicy())
    assert "https" in str(exc.value)


def test_non_http_schemes_are_rejected():
    for url in ("file:///etc/passwd", "gopher://x/", "ftp://x/", "data:text/plain,x"):
        with pytest.raises(SSRFBlocked):
            resolve_and_validate(url, OPEN)


def test_url_embedded_credentials_are_rejected():
    with pytest.raises(SSRFBlocked) as exc:
        resolve_and_validate("https://user:pass@example.com/a2a", OPEN)
    assert "credentials" in str(exc.value)


def test_unusual_ports_are_rejected():
    with pytest.raises(SSRFBlocked) as exc:
        resolve_and_validate("https://example.com:22/a2a", OPEN)
    assert "22" in str(exc.value)


def test_allowed_ports_are_conservative():
    assert set(ALLOWED_PORTS) == {80, 443, 8080, 8443}


def test_loopback_is_blocked_unless_explicitly_allowed():
    with pytest.raises(SSRFBlocked):
        resolve_and_validate("https://localhost/a2a", NetPolicy())
    assert resolve_and_validate("https://localhost/a2a", OPEN)


def test_unresolvable_host_is_a_network_error_not_an_ssrf_block():
    with pytest.raises(A2ANetworkError):
        resolve_and_validate("https://no-such-host.invalid/a2a", OPEN)


# -- request behaviour -------------------------------------------------------
def test_request_returns_status_headers_and_body():
    def handler(req):
        assert req.headers["x-test"] == "1"
        return httpx.Response(200, json={"ok": True})

    status, headers, body = request(
        "GET", "https://localhost/x", policy=OPEN,
        headers={"X-Test": "1"}, client=mock_client(handler))
    assert status == 200
    assert "json" in headers["content-type"]
    assert json.loads(body)["ok"] is True


def test_request_does_not_raise_on_http_error_status():
    """The caller decides what a 401 or 500 means."""
    for code in (400, 401, 404, 500):
        status, _, _ = request(
            "GET", "https://localhost/x", policy=OPEN,
            client=mock_client(lambda r, c=code: httpx.Response(c, json={})))
        assert status == code


def test_oversized_response_is_refused():
    big = b"x" * (5000)
    policy = NetPolicy(allow_private_addresses=True, max_bytes=1000)
    with pytest.raises(A2ANetworkError) as exc:
        request("GET", "https://localhost/x", policy=policy,
                client=mock_client(lambda r: httpx.Response(200, content=big)))
    assert "exceeded" in str(exc.value)


def test_redirect_to_a_private_address_is_blocked():
    """A redirect must be re-validated, not blindly followed."""
    def handler(req):
        if req.url.path == "/x":
            return httpx.Response(302, headers={"Location": "http://127.0.0.1:8840/admin"})
        return httpx.Response(200, json={})

    with pytest.raises(SSRFBlocked):
        request("GET", "https://example.com/x", policy=NetPolicy(),
                client=mock_client(handler))


def test_redirect_chain_is_bounded():
    def handler(req):
        return httpx.Response(302, headers={"Location": "https://localhost/loop"})

    with pytest.raises(A2ANetworkError) as exc:
        request("GET", "https://localhost/loop", policy=OPEN, client=mock_client(handler))
    assert "redirect" in str(exc.value)


def test_allowed_redirect_is_followed():
    def handler(req):
        if req.url.path == "/a":
            return httpx.Response(302, headers={"Location": "https://localhost/b"})
        return httpx.Response(200, json={"landed": True})

    status, _, body = request("GET", "https://localhost/a", policy=OPEN,
                              client=mock_client(handler))
    assert status == 200 and json.loads(body)["landed"] is True


def test_timeout_is_reported_as_a_network_error():
    def handler(req):
        raise httpx.ReadTimeout("too slow", request=req)

    with pytest.raises(A2ANetworkError) as exc:
        request("GET", "https://localhost/x", policy=OPEN, client=mock_client(handler))
    assert "timed out" in str(exc.value)


def test_transport_error_is_reported_as_a_network_error():
    def handler(req):
        raise httpx.ConnectError("refused", request=req)

    with pytest.raises(A2ANetworkError):
        request("GET", "https://localhost/x", policy=OPEN, client=mock_client(handler))


# -- JSON decoding -----------------------------------------------------------
def test_decode_json_parses_valid_payloads():
    assert decode_json(b'{"a": 1}', what="x") == {"a": 1}


def test_decode_json_rejects_empty_body():
    with pytest.raises(A2AProtocolError) as exc:
        decode_json(b"", what="Agent Card")
    assert "empty" in str(exc.value)


def test_decode_json_rejects_html_error_pages():
    with pytest.raises(A2AProtocolError):
        decode_json(b"<html><body>502 Bad Gateway</body></html>", what="Agent Card")


def test_decode_json_rejects_invalid_utf8():
    with pytest.raises(A2AProtocolError) as exc:
        decode_json(b"\xff\xfe\x00", what="x")
    assert "UTF-8" in str(exc.value)
