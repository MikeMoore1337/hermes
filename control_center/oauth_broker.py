"""Strict Unix-socket GitHub identity broker for Hermes Control Center.

Only the broker is permitted narrowly-scoped outbound GitHub TLS. The web
server retains IPAddressDeny=any with loopback only. No URLs, HTTP methods,
headers, scopes or OAuth client secrets are accepted from the web server.
"""
from __future__ import annotations

from dataclasses import dataclass
from collections import deque
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import socketserver
import struct
import time

from control_center.auth import AuthConfig, AuthError, GitHubProvider
from control_center.credentials import load_runtime_credentials

BROKER_SOCKET = "/run/hermes-oauth/broker.sock"
MAX_REQUEST = 2048
MAX_RESPONSE = 128
MAX_ATTEMPTS = 30
WINDOW_SECONDS = 3600


@dataclass(frozen=True)
class BrokerConfig:
    client_id: str
    client_secret: str
    owner_id: int
    socket_path: str = BROKER_SOCKET

    @classmethod
    def from_env(cls, env=None):
        source = os.environ if env is None else env
        client_id = source.get("HERMES_OAUTH_CLIENT_ID", "")
        secret = source.get("HERMES_OAUTH_CLIENT_SECRET", "")
        owner = source.get("HERMES_OAUTH_ALLOWED_GITHUB_ID", "")
        path = source.get("HERMES_OAUTH_SOCKET", BROKER_SOCKET)
        if not re.fullmatch(r"[A-Za-z0-9_-]{10,100}", client_id):
            raise AuthError("Invalid broker client ID")
        if not 20 <= len(secret) <= 256 or any(ord(c) < 33 for c in secret):
            raise AuthError("Invalid broker secret")
        if not owner.isdecimal() or not 1 <= len(owner) <= 18 or int(owner) <= 0:
            raise AuthError("Invalid broker numeric GitHub ID")
        if path != BROKER_SOCKET:
            raise AuthError("Invalid broker socket path")
        return cls(client_id, secret, int(owner), path)


def parse_request(raw: bytes) -> tuple[str, str]:
    if len(raw) > MAX_REQUEST or not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        raise AuthError("Malformed broker frame")
    try:
        data = json.loads(raw[:-1])
    except (UnicodeError, ValueError) as exc:
        raise AuthError("Invalid broker request") from exc
    if not isinstance(data, dict) or set(data) != {"action", "code", "verifier"}:
        raise AuthError("Unknown broker operation")
    if data["action"] != "identify":
        raise AuthError("Unknown broker action")
    code, verifier = data["code"], data["verifier"]
    if not isinstance(code, str) or not re.fullmatch(r"[A-Za-z0-9._-]{8,512}", code):
        raise AuthError("Invalid OAuth code")
    if not isinstance(verifier, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43,128}", verifier):
        raise AuthError("Invalid PKCE verifier")
    return code, verifier


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        server = self.server
        try:
            self.request.settimeout(7)
            if not server.peer_allowed(self.request):
                raise AuthError("Peer not permitted")
            raw = self.request.recv(MAX_REQUEST + 1)
            code, verifier = parse_request(raw)
            if not server.consume_attempt():
                raise AuthError("Attempt limit")
            if not server.consume_code(code):
                raise AuthError("Replayed OAuth code")
            user_id = server.provider.identify(server.auth_config, code, verifier)
            if type(user_id) is not int or user_id != server.config.owner_id:
                raise AuthError("Owner ID denied")
            data = {"ok": True, "id": user_id}
        except Exception:
            # Never return provider errors, token, identity or code to a denied client.
            data = {"ok": False}
        response = (json.dumps(data, separators=(",", ":")) + "\n").encode("ascii")
        assert len(response) <= MAX_RESPONSE
        try:
            self.request.sendall(response)
        except OSError:
            pass


class IdentityBroker(getattr(socketserver, "UnixStreamServer", socketserver.TCPServer)):
    allow_reuse_address = False

    def __init__(self, config: BrokerConfig, *, provider=None, allowed_uid=None, clock=None):
        self.config = config
        self.auth_config = AuthConfig(
            mode="github", client_id=config.client_id, client_secret=config.client_secret,
            owner_id=config.owner_id)
        self.provider = provider if provider is not None else GitHubProvider()
        self.allowed_uid = allowed_uid
        self.clock = clock if clock is not None else time.monotonic
        self.attempts = deque()
        # Only digests, never raw OAuth codes, held for one bounded window.
        self.used_codes = deque()
        self.used_digests = set()
        self._owns_socket = False
        path = Path(config.socket_path)
        if path.is_symlink() or path.exists():
            raise AuthError("Broker socket path occupied")
        if not path.parent.is_dir():
            raise AuthError("Broker runtime directory missing")
        super().__init__(config.socket_path, _Handler)
        self._owns_socket = True
        os.chmod(path, 0o660)

    def peer_allowed(self, stream):
        if self.allowed_uid is None:
            return False
        if not hasattr(socket, "SO_PEERCRED"):
            return False
        creds = stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        pid, uid, gid = struct.unpack("3i", creds)
        return uid == self.allowed_uid

    def consume_attempt(self):
        now = self.clock()
        while self.attempts and self.attempts[0] <= now - WINDOW_SECONDS:
            self.attempts.popleft()
        if len(self.attempts) >= MAX_ATTEMPTS:
            return False
        self.attempts.append(now)
        return True

    def consume_code(self, code: str) -> bool:
        now = self.clock()
        while self.used_codes and self.used_codes[0][0] <= now - WINDOW_SECONDS:
            _, old_digest = self.used_codes.popleft()
            self.used_digests.discard(old_digest)
        digest = hashlib.sha256(code.encode("ascii")).digest()
        if digest in self.used_digests:
            return False
        if len(self.used_codes) >= MAX_ATTEMPTS:
            return False
        self.used_codes.append((now, digest))
        self.used_digests.add(digest)
        return True

    def server_close(self):
        super().server_close()
        if self._owns_socket:
            try:
                Path(self.config.socket_path).unlink()
            except FileNotFoundError:
                pass
            self._owns_socket = False


def main():
    import pwd
    supplied = load_runtime_credentials("broker.env")
    if supplied is None:
        raise AuthError("Broker requires systemd LoadCredential")
    config = BrokerConfig.from_env(supplied)
    account = pwd.getpwnam("hermes-control")
    with IdentityBroker(config, allowed_uid=account.pw_uid) as server:
        server.serve_forever(poll_interval=0.25)


if __name__ == "__main__":
    main()
