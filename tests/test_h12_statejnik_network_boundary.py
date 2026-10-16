"""Negative-network protocol tests use *only* simulated DNS/TLS/HTTP."""
from __future__ import annotations

import os
import signal
import socket
import time
import unittest
from contextlib import nullcontext
from unittest.mock import patch

from statejnik_integration import network_boundary as net

ALLOWED = frozenset({"news.example.org", "research.example.org"})
PUBLIC = "93.184.216.34"
REAL_WALL_BUDGET = net._wall_budget


def resolution(*addresses: str):
    return [(socket.AF_INET if ":" not in ip else socket.AF_INET6,
             socket.SOCK_STREAM, socket.IPPROTO_TCP, "",
             (ip, 443)) for ip in addresses]


class FakeResponse:
    def __init__(self, status=200, body=b"<html>ok</html>", location=None,
                 headers=None):
        self.status = status
        self.body = body
        self.location = location
        self.headers = {"Content-Type": "text/html; charset=utf-8"}
        self.headers.update(headers or {})
        self.calls = []

    def getheader(self, name):
        return self.location if name == "Location" else self.headers.get(name)

    def read(self, limit):
        self.calls.append(limit)
        return self.body[:limit]


class FakeConnection:
    instances = []
    responses = []

    def __init__(self, hostname, pinned_ip, *, timeout):
        self.host = hostname
        self.ip = pinned_ip
        self.timeout = timeout
        self.calls = []
        self.closed = False
        FakeConnection.instances.append(self)

    def request(self, method, path, *, headers):
        self.calls.append((method, path, headers))

    def getresponse(self):
        return FakeConnection.responses.pop(0)

    def close(self):
        self.closed = True


class NetworkBoundaryTests(unittest.TestCase):
    def setUp(self):
        FakeConnection.instances = []
        FakeConnection.responses = []
        # Protocol fake tests are portable to Windows, where a live
        # POSIX-only process timer would correctly refuse network.
        mocked_budget = patch.object(net, "_wall_budget",
                                     side_effect=lambda _seconds: nullcontext())
        mocked_budget.start()
        self.addCleanup(mocked_budget.stop)

    def test_default_denies_without_even_resolving_dns(self):
        with patch.object(net.socket, "getaddrinfo") as resolver:
            with self.assertRaisesRegex(net.NetworkDenied, "network_not_enabled"):
                net.fetch_public_html("https://news.example.org/",
                                      allowed_hosts=ALLOWED)
            resolver.assert_not_called()

    def test_valid_canonical_https_only(self):
        entry = net.target("https://news.example.org/a?q=1", ALLOWED)
        self.assertEqual(entry.hostname, "news.example.org")
        self.assertEqual(entry.path, "/a?q=1")
        self.assertEqual(net.target("https://news.example.org:443/", ALLOWED).path, "/")

    def test_authority_tricks_are_rejected(self):
        urls = (
            "http://news.example.org", "https://news.example.org:444/",
            "https://user:pass@news.example.org/a",
            "https://news.example.org@127.0.0.1/", "https://127.0.0.1/",
            "https://[::1]/", "https://169.254.169.254/metadata",
            "file:///etc/passwd", "https://news.example.org.evil.org/",
            "https://news.example.org./", "https://news.example.org%2f.evil.org/",
            "https://news.example.org\\@evil.org/", "https://news.example.org/\r\n",
            "https://news.example.org/#secret",
            "https://news.example.org:443:444/",
            "https://NEWS.example.org/", "https://news.example.org:0443/",
            "https://news.example.org//evil.org/",
        )
        for url in urls:
            with self.subTest(url=url), self.assertRaises(net.NetworkDenied):
                net.target(url, ALLOWED)

    def test_allowlist_cannot_be_missing_malformed_or_relaxed(self):
        for hosts in (frozenset(), {"news.example.org"}, frozenset({"NEWS.example.org"}),
                      frozenset({"*.example.org"}), frozenset({"evil.local"}),
                      frozenset({"news.example.org."})):
            with self.subTest(hosts=str(hosts)), self.assertRaises(net.NetworkDenied):
                net.target("https://news.example.org/", hosts)

    def test_malformed_dns_and_private_answers_fail_closed(self):
        for ip in ("127.0.0.1", "10.1.2.3", "172.16.0.1",
                   "192.168.1.1", "169.254.169.254",
                   "100.64.0.1", "192.0.2.1", "224.0.0.1",
                   "::1", "fe80::1", "fc00::1", "::ffff:127.0.0.1"):
            with self.subTest(ip=ip), self.assertRaises(net.NetworkDenied):
                net.pinned_addresses("news.example.org",
                                     lambda *a, **k: resolution(ip))

    def test_mixed_public_and_private_dns_rebinding_denied(self):
        with self.assertRaisesRegex(net.NetworkDenied, "dns_not_public"):
            net.pinned_addresses("news.example.org",
                                 lambda *a, **k: resolution(PUBLIC, "127.0.0.1"))

    def test_failed_empty_or_too_many_dns_records_denied(self):
        resolvers = (
            lambda *a, **k: [],
            lambda *a, **k: resolution(*([PUBLIC] * 17)),
            lambda *a, **k: (_ for _ in ()).throw(socket.gaierror("no dns")),
        )
        for resolve in resolvers:
            with self.assertRaises(net.NetworkDenied):
                net.pinned_addresses("news.example.org", resolve)

    def test_valid_https_request_uses_ip_pin_with_original_host_header(self):
        answer = FakeResponse()
        FakeConnection.responses = [answer]
        result = net.fetch_public_html(
            "https://news.example.org/page", allowed_hosts=ALLOWED,
            authorized=True, resolver=lambda *a, **k: resolution(PUBLIC),
            connection_factory=FakeConnection,
        )
        self.assertEqual(result, (200, b"<html>ok</html>"))
        self.assertEqual(len(FakeConnection.instances), 1)
        conn = FakeConnection.instances[0]
        self.assertEqual(conn.host, "news.example.org")
        self.assertEqual(conn.ip, PUBLIC)
        self.assertEqual(conn.timeout, 8)
        self.assertTrue(conn.closed)
        method, path, headers = conn.calls[0]
        self.assertEqual((method, path), ("GET", "/page"))
        self.assertEqual(headers["Host"], "news.example.org")
        self.assertEqual(set(headers), {"Host", "User-Agent", "Accept",
                                        "Accept-Encoding", "Connection"})
        self.assertEqual(headers["Accept-Encoding"], "identity")
        self.assertEqual(headers["Connection"], "close")
        self.assertEqual(answer.calls, [net.MAX_RESPONSE_BYTES + 1])

    def test_actual_pinned_https_socket_uses_ip_and_hostname_for_tls(self):
        from unittest.mock import Mock
        raw_socket = Mock()
        context = Mock()
        context.wrap_socket.return_value = Mock()
        with (patch.object(net.socket, "create_connection",
                           return_value=raw_socket) as socket_call,
              patch.object(net.ssl, "create_default_context",
                           return_value=context)):
            conn = net._PinnedHttps("news.example.org", PUBLIC, timeout=8)
            conn.connect()
        socket_call.assert_called_once_with((PUBLIC, 443), timeout=8)
        context.wrap_socket.assert_called_once_with(
            raw_socket, server_hostname="news.example.org")
        self.assertIs(conn.sock, context.wrap_socket.return_value)

    def test_tls_failure_closes_raw_socket_without_fallback(self):
        from unittest.mock import Mock
        raw_socket = Mock()
        context = Mock()
        context.wrap_socket.side_effect = net.ssl.SSLError("certificate failure")
        with (patch.object(net.socket, "create_connection",
                           return_value=raw_socket) as socket_call,
              patch.object(net.ssl, "create_default_context",
                           return_value=context)):
            conn = net._PinnedHttps("news.example.org", PUBLIC, timeout=8)
            with self.assertRaises(net.ssl.SSLError):
                conn.connect()
        socket_call.assert_called_once_with((PUBLIC, 443), timeout=8)
        raw_socket.close.assert_called_once()

    def test_redirect_to_metadata_and_unapproved_domain_never_connects(self):
        for redirect in ("http://169.254.169.254/latest",
                         "https://evil.org/", "//localhost/admin",
                         "https://research.example.org.evil.org"):
            FakeConnection.responses = [FakeResponse(302, location=redirect)]
            with self.subTest(redirect=redirect), self.assertRaises(net.NetworkDenied):
                net.fetch_public_html(
                    "https://news.example.org/", allowed_hosts=ALLOWED,
                    authorized=True, resolver=lambda *a, **k: resolution(PUBLIC),
                    connection_factory=FakeConnection,
                )
            self.assertTrue(all(c.closed for c in FakeConnection.instances))
            FakeConnection.instances.clear()

    def test_redirect_to_second_allowlisted_host_is_freshly_resolved(self):
        FakeConnection.responses = [
            FakeResponse(302, location="https://research.example.org/final"),
            FakeResponse(200, body=b"fine"),
        ]
        resolved = []
        def resolver(host, *_a, **_k):
            resolved.append(host)
            return resolution(PUBLIC)
        status, body = net.fetch_public_html(
            "https://news.example.org/", allowed_hosts=ALLOWED,
            authorized=True, resolver=resolver, connection_factory=FakeConnection,
        )
        self.assertEqual((status, body), (200, b"fine"))
        self.assertEqual(resolved, ["news.example.org", "research.example.org"])
        self.assertEqual([c.host for c in FakeConnection.instances],
                         ["news.example.org", "research.example.org"])
        self.assertTrue(all(c.closed for c in FakeConnection.instances))

    def test_redirect_fresh_dns_is_private_denied_before_second_connection(self):
        FakeConnection.responses = [
            FakeResponse(301, location="https://research.example.org/redirect"),
        ]
        def resolver(host, *_a, **_k):
            return resolution("10.0.0.1" if host == "research.example.org" else PUBLIC)
        with self.assertRaisesRegex(net.NetworkDenied, "dns_not_public"):
            net.fetch_public_html(
                "https://news.example.org/", allowed_hosts=ALLOWED,
                authorized=True, resolver=resolver, connection_factory=FakeConnection)
        self.assertEqual(len(FakeConnection.instances), 1)

    def test_oversize_body_denied_without_returning_bytes(self):
        FakeConnection.responses = [FakeResponse(200, b"SECRET" * 200_000)]
        with self.assertRaisesRegex(net.NetworkDenied, "response_too_large") as err:
            net.fetch_public_html(
                "https://news.example.org/", allowed_hosts=ALLOWED,
                authorized=True, resolver=lambda *a, **k: resolution(PUBLIC),
                connection_factory=FakeConnection)
        self.assertNotIn("SECRET", str(err.exception))

    def test_content_type_missing_binary_json_and_overlong_denied_before_read(self):
        for content_type in (None, "application/json", "image/svg+xml",
                             "application/octet-stream", "x" * 129):
            answer = FakeResponse(headers={"Content-Type": content_type},
                                  body=b"PRIVATE_DOCUMENT")
            FakeConnection.responses = [answer]
            with self.subTest(content_type=content_type), self.assertRaisesRegex(
                net.NetworkDenied, "content_type_denied"
            ):
                net.fetch_public_html(
                    "https://news.example.org/", allowed_hosts=ALLOWED,
                    authorized=True, resolver=lambda *a, **k: resolution(PUBLIC),
                    connection_factory=FakeConnection)
            self.assertEqual(answer.calls, [])
            self.assertTrue(FakeConnection.instances[-1].closed)

    def test_compression_and_attachment_denied_before_body(self):
        for headers, reason in (
            ({"Content-Encoding": "gzip"}, "content_encoding_denied"),
            ({"Content-Encoding": "br"}, "content_encoding_denied"),
            ({"Content-Encoding": "gzip, identity"}, "content_encoding_denied"),
            ({"Content-Disposition": "attachment; filename=a.html"},
             "content_disposition_denied"),
        ):
            answer = FakeResponse(headers=headers, body=b"PRIVATE_CONTENT")
            FakeConnection.responses = [answer]
            with self.subTest(headers=headers), self.assertRaisesRegex(
                net.NetworkDenied, reason
            ):
                net.fetch_public_html(
                    "https://news.example.org/", allowed_hosts=ALLOWED,
                    authorized=True, resolver=lambda *a, **k: resolution(PUBLIC),
                    connection_factory=FakeConnection)
            self.assertEqual(answer.calls, [])

    def test_invalid_oversize_and_ambiguous_content_length_denied(self):
        for headers, reason in (
            ({"Content-Length": str(net.MAX_RESPONSE_BYTES + 1)},
             "content_length_denied"),
            ({"Content-Length": "-1"}, "content_length_denied"),
            ({"Content-Length": "123, 456"}, "content_length_denied"),
            ({"Content-Length": "0xABC"}, "content_length_denied"),
            ({"Content-Length": "9" * 32}, "content_length_denied"),
            ({"Transfer-Encoding": "gzip"}, "transfer_encoding_denied"),
            ({"Transfer-Encoding": "chunked", "Content-Length": "12"},
             "transfer_encoding_denied"),
        ):
            answer = FakeResponse(headers=headers, body=b"PRIVATE_CONTENT")
            FakeConnection.responses = [answer]
            with self.subTest(headers=headers), self.assertRaisesRegex(
                net.NetworkDenied, reason
            ):
                net.fetch_public_html(
                    "https://news.example.org/", allowed_hosts=ALLOWED,
                    authorized=True, resolver=lambda *a, **k: resolution(PUBLIC),
                    connection_factory=FakeConnection)
            self.assertEqual(answer.calls, [])

    def test_normal_identity_and_chunked_html_have_bounded_read(self):
        for headers in (
            {"Content-Type": "application/xhtml+xml",
             "Content-Encoding": "identity", "Content-Length": "4"},
            {"Transfer-Encoding": "chunked"},
        ):
            answer = FakeResponse(body=b"<x/>", headers=headers)
            FakeConnection.responses = [answer]
            self.assertEqual(net.fetch_public_html(
                "https://news.example.org/", allowed_hosts=ALLOWED,
                authorized=True, resolver=lambda *a, **k: resolution(PUBLIC),
                connection_factory=FakeConnection), (200, b"<x/>"))
            self.assertEqual(answer.calls, [net.MAX_RESPONSE_BYTES + 1])

    def test_status_error_and_loop_denied(self):
        FakeConnection.responses = [FakeResponse(500, b"SECRET")]
        with self.assertRaisesRegex(net.NetworkDenied, "upstream_status_denied"):
            net.fetch_public_html(
                "https://news.example.org/", allowed_hosts=ALLOWED,
                authorized=True, resolver=lambda *a, **k: resolution(PUBLIC),
                connection_factory=FakeConnection)
        FakeConnection.responses = [FakeResponse(302, location="/")]
        with self.assertRaisesRegex(net.NetworkDenied, "redirect_loop"):
            net.fetch_public_html(
                "https://news.example.org/", allowed_hosts=ALLOWED,
                authorized=True, resolver=lambda *a, **k: resolution(PUBLIC),
                connection_factory=FakeConnection)

    def test_original_vendor_and_runner_do_not_reference_live_boundary(self):
        from statejnik_integration import runner
        self.assertEqual(runner.catalog()["network_enabled"], False)
        self.assertEqual(runner.catalog()["automatic_publication_enabled"], False)
        self.assertNotIn("network_boundary", runner.run.__code__.co_names)


if __name__ == "__main__":
    unittest.main()
