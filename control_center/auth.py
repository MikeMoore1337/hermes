"""Owner-only GitHub OAuth for the separately sandboxed Hermes Control Center.

Disabled by default. Caddy Basic Auth remains the production perimeter until
a dedicated OAuth App, owner ID, negative tests, and cutover are approved.
No provider tokens, OAuth codes, or sensitive URLs are written to logs/disks.
"""
from __future__ import annotations

from dataclasses import dataclass
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import ssl
from threading import Lock
import time
from urllib.parse import urlencode
from urllib.request import HTTPSHandler, HTTPRedirectHandler, ProxyHandler, Request, build_opener


ORIGIN = "https://hermes.mikemoore.top"
CALLBACK_PATH = "/auth/github/callback"
AUTH_URL = "https://github.com/login/oauth/authorize"
TOKEN_URL = "https://github.com/login/oauth/access_token"
USER_URL = "https://api.github.com/user"
STATE_COOKIE = "hermes_cc_state"
SESSION_COOKIE = "hermes_cc_session"
BROKER_SOCKET = "/run/hermes-oauth/broker.sock"
STATE_TTL = 600
SESSION_TTL = 43200
MAX_PENDING = 24
MAX_SESSIONS = 128


class AuthError(ValueError):
    """Internal fail-closed OAuth rejection. Never return details to clients."""


@dataclass(frozen=True)
class AuthConfig:
    mode: str = "proxy"
    public_origin: str = ORIGIN
    client_id: str = ""
    client_secret: str = ""
    owner_id: int = 0
    session_secret: bytes = b""
    broker_socket: str = BROKER_SOCKET

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "AuthConfig":
        env = dict(os.environ if env is None else env)
        mode = env.get("HERMES_CC_AUTH_MODE", "proxy")
        if mode == "proxy":
            return cls()
        if mode != "github":
            raise AuthError("Invalid authentication mode")
        origin = env.get("HERMES_CC_PUBLIC_ORIGIN", "")
        client_id = env.get("HERMES_CC_GITHUB_CLIENT_ID", "")
        client_secret = env.get("HERMES_CC_GITHUB_CLIENT_SECRET", "")
        owner = env.get("HERMES_CC_ALLOWED_GITHUB_ID", "")
        secret = env.get("HERMES_CC_SESSION_SECRET", "")
        broker = env.get("HERMES_CC_OAUTH_BROKER_SOCKET", BROKER_SOCKET)
        if origin != ORIGIN:
            raise AuthError("Invalid canonical public origin")
        if not re.fullmatch(r"[A-Za-z0-9_-]{10,100}", client_id):
            raise AuthError("Missing or malformed OAuth client ID")
        if client_secret:
            raise AuthError("OAuth client secret must only be loaded by isolated broker")
        if broker != BROKER_SOCKET:
            raise AuthError("Unexpected OAuth broker socket")
        if not owner.isdecimal() or not 1 <= len(owner) <= 18 or int(owner) <= 0:
            raise AuthError("Invalid allowed numeric owner ID")
        if len(secret.encode("utf-8")) < 32 or len(secret) > 1024:
            raise AuthError("Weak session signing secret")
        return cls(mode, origin, client_id, "", int(owner), secret.encode("utf-8"), broker)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise AuthError("Provider redirect blocked")


def _fetch_json(request: Request) -> dict:
    opener = build_opener(ProxyHandler({}), _NoRedirect, HTTPSHandler(context=ssl.create_default_context()))
    with opener.open(request, timeout=5) as response:
        if response.status != 200:
            raise AuthError("Provider status failure")
        body = response.read(16385)
        if len(body) > 16384:
            raise AuthError("Provider response too large")
    result = json.loads(body)
    if not isinstance(result, dict):
        raise AuthError("Malformed provider response")
    return result


class LocalBrokerProvider:
    """Only outbound transport used by the web server: exact Unix socket."""

    def identify(self, config: AuthConfig, code: str, verifier: str) -> int:
        if config.broker_socket != BROKER_SOCKET:
            raise AuthError("Broker socket denied")
        request = json.dumps(
            {"action": "identify", "code": code, "verifier": verifier},
            separators=(",", ":"),
        ).encode("ascii") + b"\n"
        if len(request) > 2048:
            raise AuthError("Broker request too large")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(7)
            client.connect(config.broker_socket)
            client.sendall(request)
            data = bytearray()
            while b"\n" not in data and len(data) < 129:
                block = client.recv(129-len(data))
                if not block:
                    break
                data.extend(block)
        if len(data) > 128 or data.count(b"\n") != 1 or not data.endswith(b"\n"):
            raise AuthError("Broker response malformed")
        try:
            parsed = json.loads(data)
        except (ValueError, UnicodeError) as exc:
            raise AuthError("Broker response invalid") from exc
        uid = parsed.get("id") if isinstance(parsed, dict) and parsed.get("ok") is True else None
        if type(uid) is not int or uid <= 0:
            raise AuthError("Broker identity denied")
        return uid


class GitHubProvider:
    """Minimal-scope code exchange; drops the access token after /user lookup."""

    def identify(self, config: AuthConfig, code: str, verifier: str) -> int:
        form = urlencode({
            "client_id": config.client_id,
            "client_secret": config.client_secret,
            "code": code,
            "redirect_uri": config.public_origin + CALLBACK_PATH,
            "code_verifier": verifier,
        }).encode("utf-8")
        token = _fetch_json(Request(
            TOKEN_URL, data=form, method="POST",
            headers={"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded",
                     "User-Agent": "Hermes-Control-Center"}))
        key = token.get("access_token")
        if not isinstance(key, str) or not 8 <= len(key) <= 512:
            raise AuthError("Invalid OAuth token response")
        if str(token.get("token_type", "")).lower() != "bearer":
            raise AuthError("Unexpected token type")
        # An existing authorization may include broad scopes; owner login
        # must not accidentally receive repo/org privileges.
        if token.get("scope", "") not in ("", None):
            raise AuthError("Unexpected OAuth permissions")
        identity = _fetch_json(Request(
            USER_URL, headers={
                "Authorization": "Bearer " + key,
                "Accept": "application/vnd.github+json",
                "User-Agent": "Hermes-Control-Center",
                "X-GitHub-Api-Version": "2022-11-28",
            }))
        user_id = identity.get("id")
        if type(user_id) is not int or user_id <= 0:
            raise AuthError("Provider identity invalid")
        return user_id


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


class OAuthService:
    """Bounded process-local one-time login states and revocable sessions."""

    def __init__(self, config: AuthConfig, provider=None, clock=None):
        if config.mode != "github":
            raise AuthError("OAuth service cannot run in proxy mode")
        self.config = config
        self.provider = provider if provider is not None else LocalBrokerProvider()
        self.clock = clock if clock is not None else time.time
        self._pending: dict[str, tuple[str, float]] = {}
        self._sessions: dict[str, float] = {}
        self._lock = Lock()

    def _prune(self, now: float) -> None:
        self._pending = {k: v for k, v in self._pending.items() if v[1] > now}
        self._sessions = {k: v for k, v in self._sessions.items() if v > now}

    def begin(self) -> tuple[str, str]:
        state = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(48)
        challenge = _b64(hashlib.sha256(verifier.encode("ascii")).digest())
        with self._lock:
            now = self.clock()
            self._prune(now)
            if len(self._pending) >= MAX_PENDING:
                raise AuthError("Pending state capacity reached")
            self._pending[_digest(state)] = (verifier, now + STATE_TTL)
        url = AUTH_URL + "?" + urlencode({
            "client_id": self.config.client_id,
            "redirect_uri": ORIGIN + CALLBACK_PATH,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "allow_signup": "false",
        })
        return url, state

    def finish(self, *, code: str, state: str, cookie_state: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9._-]{8,512}", code or ""):
            raise AuthError("Invalid OAuth code")
        if not re.fullmatch(r"[A-Za-z0-9_-]{40,128}", state or ""):
            raise AuthError("Invalid OAuth state")
        if not isinstance(cookie_state, str) or not cookie_state.isascii() or not hmac.compare_digest(state, cookie_state):
            raise AuthError("Cross-browser OAuth state")
        with self._lock:
            now = self.clock()
            self._prune(now)
            value = self._pending.pop(_digest(state), None)
            if value is None or value[1] <= now:
                raise AuthError("Used or expired OAuth state")
            verifier = value[0]
        try:
            user_id = self.provider.identify(self.config, code, verifier)
        except Exception as exc:
            raise AuthError("OAuth provider identity lookup failed") from exc
        if type(user_id) is not int or user_id != self.config.owner_id:
            raise AuthError("Owner ID denied")
        token = secrets.token_urlsafe(32)
        signature = _b64(hmac.new(self.config.session_secret, token.encode("ascii"), hashlib.sha256).digest())
        with self._lock:
            now = self.clock()
            self._prune(now)
            if len(self._sessions) >= MAX_SESSIONS:
                raise AuthError("Session capacity reached")
            self._sessions[_digest(token)] = now + SESSION_TTL
        return token + "." + signature

    def authenticated(self, cookie: str | None) -> bool:
        if not isinstance(cookie, str) or not 50 <= len(cookie) <= 160:
            return False
        parts = cookie.split(".")
        if len(parts) != 2:
            return False
        token, signature = parts
        if not re.fullmatch(r"[A-Za-z0-9_-]{40,70}", token):
            return False
        expected = _b64(hmac.new(self.config.session_secret, token.encode("ascii"), hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            return False
        with self._lock:
            now = self.clock()
            self._prune(now)
            return self._sessions.get(_digest(token), 0) > now

    def revoke(self, cookie: str | None) -> None:
        if not self.authenticated(cookie):
            return
        token = cookie.split(".", 1)[0]
        with self._lock:
            self._sessions.pop(_digest(token), None)


def cookie_header(name: str, value: str, max_age: int, path: str = "/") -> str:
    if name not in (STATE_COOKIE, SESSION_COOKIE):
        raise AuthError("Invalid cookie name")
    if path not in ("/", "/auth/github"):
        raise AuthError("Invalid cookie path")
    if not value.isascii() or any(c in value for c in "\r\n; ,"):
        raise AuthError("Unsafe cookie")
    return (f"{name}={value}; Path={path}; Max-Age={max_age}; "
            "HttpOnly; Secure; SameSite=Lax")


def parse_cookie(raw: str | None, name: str) -> str:
    if not raw or len(raw) > 4096:
        return ""
    matches = []
    for item in raw.split(";"):
        key, sep, value = item.strip().partition("=")
        if sep and key == name:
            matches.append(value)
    # Reject duplicated cookies: user agents and proxies can disagree
    # over first-vs-last precedence, including after cookie tossing.
    return matches[0] if len(matches) == 1 else ""
