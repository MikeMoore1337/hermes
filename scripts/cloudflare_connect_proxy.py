"""Narrow TLS CONNECT relay: only api.cloudflare.com:443, no credentials handled."""
from __future__ import annotations

import ipaddress
import select
import socket
import socketserver
import time

LISTEN = ("172.29.250.1", 18573)
CLIENT_IP = "172.29.250.2"
TARGET_HOST = "api.cloudflare.com"
TARGET_PORT = 443


def permitted_connect(line: bytes, client_ip: str) -> bool:
    """Only the fixed agent address may request the exact Cloudflare authority."""
    return client_ip == CLIENT_IP and line == b"CONNECT api.cloudflare.com:443 HTTP/1.1"


def public_ip() -> str:
    """Resolve only globally routable IPv4 for the fixed endpoint."""
    for item in socket.getaddrinfo(TARGET_HOST, TARGET_PORT, socket.AF_INET, socket.SOCK_STREAM):
        ip = item[4][0]
        if ipaddress.ip_address(ip).is_global:
            return ip
    raise OSError("no_public_cloudflare_ip")


def relay(a: socket.socket, b: socket.socket) -> None:
    """Relay encrypted TLS bytes only, bounded to 90 seconds."""
    expires = time.monotonic() + 90
    while time.monotonic() < expires:
        ready, _, _ = select.select((a, b), (), (), 1.0)
        for source in ready:
            target = b if source is a else a
            data = source.recv(32768)
            if not data:
                return
            target.sendall(data)


class Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        client = self.request
        client.settimeout(7)
        header = b""
        while b"\r\n\r\n" not in header and len(header) < 4096:
            data = client.recv(1024)
            if not data:
                return
            header += data
        if b"\r\n\r\n" not in header or len(header) >= 4096:
            client.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            return
        first = header.split(b"\r\n", 1)[0]
        if not permitted_connect(first, self.client_address[0]):
            client.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            return
        try:
            cloudflare = socket.create_connection((public_ip(), TARGET_PORT), timeout=7)
        except (OSError, TimeoutError):
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            return
        with cloudflare:
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            tail = header.split(b"\r\n\r\n", 1)[1]
            if tail:
                cloudflare.sendall(tail)
            client.settimeout(None)
            cloudflare.settimeout(None)
            try:
                relay(client, cloudflare)
            except (OSError, TimeoutError, ConnectionError):
                pass


class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 4


def main() -> int:
    with Server(LISTEN, Handler) as server:
        server.serve_forever(poll_interval=0.5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
