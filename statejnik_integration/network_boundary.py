"""Hermes-owned SSRF-resistant HTTPS transport candidate for Statejnik.

No command-line or runner integration. Default ALWAYS denies network traffic.
For future owner-approved, separately sandboxed use: only exact host allowlists,
pinning a validated public DNS address to each TLS connection, hostname-verified
TLS and strictly bounded redirects/response bytes. No proxy, cookies, headers
from outside, POST, secrets or automatic publication.
"""
from __future__ import annotations

import http.client
import ipaddress
import re
import socket
import ssl
import urllib.parse
from dataclasses import dataclass
from typing import Callable

MAX_RESPONSE_BYTES = 1_048_576
MAX_REDIRECTS = 3
MAX_DNS_ANSWERS = 16
USER_AGENT = "Hermes-Statejnik-ReadOnly/0.1"
HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class NetworkDenied(ValueError):
    """Fixed reason only; never include URL, query, content or credentials."""


@dataclass(frozen=True)
class HttpsTarget:
    hostname: str
    path: str


def canonical_host(host: str) -> str:
    if type(host) is not str or not 1 <= len(host) <= 253:
        raise NetworkDenied("host_invalid")
    if host != host.strip() or any(c in host for c in "@:/\\%\x00"):
        raise NetworkDenied("host_invalid")
    if host.endswith(".") or host.startswith("."):
        raise NetworkDenied("host_invalid")
    try:
        host = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise NetworkDenied("host_invalid") from None
    if (not 4 <= len(host) <= 253 or "." not in host
            or len(host.split(".")) > 12
            or any(not HOST_LABEL.fullmatch(part) for part in host.split("."))):
        raise NetworkDenied("host_invalid")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise NetworkDenied("host_ip_literal_denied")
    if host.endswith((".local", ".localhost", ".internal", ".test", ".invalid",
                      ".example", ".onion")):
        raise NetworkDenied("host_reserved")
    return host


def target(url: str, allowed_hosts: frozenset[str]) -> HttpsTarget:
    if type(url) is not str or not 1 <= len(url) <= 2048:
        raise NetworkDenied("url_invalid")
    if any(ord(c) < 33 or ord(c) == 127 or c == "\\" for c in url):
        raise NetworkDenied("url_invalid")
    if type(allowed_hosts) is not frozenset or not 1 <= len(allowed_hosts) <= 8:
        raise NetworkDenied("host_allowlist_missing")
    if any(type(h) is not str or canonical_host(h) != h for h in allowed_hosts):
        raise NetworkDenied("host_allowlist_invalid")
    try:
        part = urllib.parse.urlsplit(url)
        hostname = canonical_host(part.hostname or "")
        port = part.port
    except ValueError:
        raise NetworkDenied("url_invalid") from None
    if (part.scheme != "https" or not part.netloc or part.username is not None
            or part.password is not None or part.fragment or part.netloc.count("@")
            or port not in (None, 443) or hostname not in allowed_hosts):
        raise NetworkDenied("url_not_admitted")
    # urllib parses 'evil.com:443:123' as an invalid port above. Disallow
    # altered authorities, Unicode lookalikes and noncanonical percent hosts.
    authority = hostname + (":443" if port == 443 else "")
    if part.netloc != authority:
        raise NetworkDenied("url_authority_invalid")
    path = part.path or "/"
    if not path.startswith("//"):
        path = urllib.parse.quote(path, safe="/%:@!$&'()*+,;=-._~")
    # Reject encoded controls in request target and deceptive paths.
    if (len(path) > 2048 or "\x00" in urllib.parse.unquote(path)
            or any(ord(c) < 32 for c in urllib.parse.unquote(path))
            or path.startswith("//")):
        raise NetworkDenied("url_path_invalid")
    if part.query:
        path += "?" + part.query
    if len(path) > 2048:
        raise NetworkDenied("url_path_invalid")
    return HttpsTarget(hostname, path)


def pinned_addresses(hostname: str, resolver: Callable = socket.getaddrinfo) -> tuple[str, ...]:
    """All DNS answers must be globally routable; one private = fail closed."""
    try:
        answers = resolver(hostname, 443, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError, ValueError):
        raise NetworkDenied("dns_unavailable") from None
    if not 1 <= len(answers) <= MAX_DNS_ANSWERS:
        raise NetworkDenied("dns_unavailable")
    addresses: set[str] = set()
    for answer in answers:
        try:
            family, socktype, proto, _canonical, endpoint = answer
            if family not in (socket.AF_INET, socket.AF_INET6):
                raise ValueError("family")
            if socktype != socket.SOCK_STREAM:
                raise ValueError("socktype")
            ip = ipaddress.ip_address(endpoint[0])
            if (not ip.is_global or ip.is_multicast or ip.is_reserved
                    or (isinstance(ip, ipaddress.IPv6Address)
                        and ip.ipv4_mapped is not None)):
                raise ValueError("not_global")
            addresses.add(str(ip))
        except (ValueError, TypeError, IndexError, AttributeError):
            raise NetworkDenied("dns_not_public") from None
    if not addresses:
        raise NetworkDenied("dns_unavailable")
    return tuple(sorted(addresses))


def _admit_html_response_headers(response: http.client.HTTPResponse) -> None:
    """Deny non-HTML, compressed and ambiguous bodies before any body read."""
    ctype = response.getheader("Content-Type")
    if (type(ctype) is not str or not 1 <= len(ctype) <= 128
            or ctype.split(";", 1)[0].strip().lower()
            not in ("text/html", "application/xhtml+xml")):
        raise NetworkDenied("content_type_denied")
    encoding = response.getheader("Content-Encoding")
    if encoding is not None and (
        type(encoding) is not str or encoding.strip().lower() != "identity"
    ):
        raise NetworkDenied("content_encoding_denied")
    length = response.getheader("Content-Length")
    transfer = response.getheader("Transfer-Encoding")
    if transfer is not None and (
        type(transfer) is not str or transfer.strip().lower() != "chunked"
        or length is not None
    ):
        raise NetworkDenied("transfer_encoding_denied")
    if length is not None:
        if (type(length) is not str or not length.isascii()
                or not length.isdecimal() or len(length) > 10
                or int(length) > MAX_RESPONSE_BYTES):
            raise NetworkDenied("content_length_denied")
    disposition = response.getheader("Content-Disposition")
    if disposition is not None and (
        type(disposition) is not str or
        disposition.strip().lower().startswith("attachment")
    ):
        raise NetworkDenied("content_disposition_denied")


class _PinnedHttps(http.client.HTTPSConnection):
    def __init__(self, hostname: str, pinned_ip: str, *, timeout: float):
        super().__init__(hostname, 443, timeout=timeout,
                         context=ssl.create_default_context())
        self._pinned_ip = pinned_ip

    def connect(self) -> None:
        # Socket connects ONLY to an IP validated from the same DNS answer.
        # TLS SNI and certificate validation retain the original hostname.
        raw = socket.create_connection((self._pinned_ip, 443), timeout=self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


def fetch_public_html(
    url: str, *,
    allowed_hosts: frozenset[str],
    authorized: bool = False,
    resolver: Callable = socket.getaddrinfo,
    connection_factory: Callable | None = None,
) -> tuple[int, bytes]:
    """Opt-in candidate. NEVER wired to live Statejnik runner/CMS.

    DNS pinning and exact hostname TLS prevent connect-time DNS rebinding.
    Redirects revalidate and repin. This is no substitute for an egress
    firewall, reviewed host allowlist, provider permissions or real TLS E2E.
    """
    if authorized is not True:
        raise NetworkDenied("network_not_enabled")
    location = url
    visited: set[str] = set()
    for hop in range(MAX_REDIRECTS + 1):
        current = target(location, allowed_hosts)
        if location in visited:
            raise NetworkDenied("redirect_loop")
        visited.add(location)
        addresses = pinned_addresses(current.hostname, resolver)
        conn = None
        try:
            factory = connection_factory or _PinnedHttps
            conn = factory(current.hostname, addresses[0], timeout=8)
            conn.request("GET", current.path,
                         headers={"Host": current.hostname, "User-Agent": USER_AGENT,
                                  "Accept": "text/html,application/xhtml+xml",
                                  "Accept-Encoding": "identity",
                                  "Connection": "close"})
            response = conn.getresponse()
            status = response.status
            if status in (301, 302, 303, 307, 308):
                redirect = response.getheader("Location")
                if not redirect or hop >= MAX_REDIRECTS:
                    raise NetworkDenied("redirect_denied")
                nxt = urllib.parse.urljoin(location, redirect)
                # Validate BEFORE any resolution or socket creation.
                target(nxt, allowed_hosts)
                location = nxt
                continue
            if status != 200:
                raise NetworkDenied("upstream_status_denied")
            _admit_html_response_headers(response)
            body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                raise NetworkDenied("response_too_large")
            return status, body
        except (OSError, http.client.HTTPException, ssl.SSLError):
            raise NetworkDenied("connection_denied") from None
        finally:
            if conn is not None:
                conn.close()
    raise NetworkDenied("redirect_denied")
