"""Sandboxed loopback UI with exact static allowlist and optional owner-only OAuth.

Default proxy mode remains protected by Caddy Basic Auth. GitHub mode is an
opt-in separate production change and fails closed without all owner secrets.
"""
from __future__ import annotations

import argparse
import datetime as dt
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import logging
import sqlite3
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from control_center.infrastructure import (
    ROOT as INFRA_ROOT, hosts as infrastructure_hosts,
    history as infrastructure_history,
)
from control_center.provider_registry import registry as provider_quota_registry
from control_center.snapshot import DEFAULT_OUTPUT
from control_center.codex_usage import DEFAULT_OUTPUT as CODEX_OUTPUT, read_snapshot, UsageError
from control_center.codex_history import read as read_codex_history
from control_center.codex_analytics import DEFAULT_DB as ANALYTICS_DB, read as read_codex_analytics
from control_center.codex_policy import decision as codex_decision
from control_center.codex_scheduler import DEFAULT_DB as SCHEDULER_DB
from control_center.codex_scheduler_status import read_status as read_scheduler_status, StatusUnavailable
from control_center.desktop_commander import (DEFAULT_OUTPUT as DC_OUTPUT,
                                              read_snapshot as read_desktop_commander,
                                              CommanderError)
from control_center.desktop_commander_history import read as read_desktop_history, HistoryError
from control_center.credentials import load_runtime_credentials
from control_center.auth import (
    AuthConfig, AuthError, OAuthService, ORIGIN,
    SESSION_COOKIE, STATE_COOKIE, STATE_TTL, SESSION_TTL,
    cookie_header, parse_cookie,
)

WEB = Path(__file__).with_name("web")
HOSTS = {"127.0.0.1:9133", "localhost:9133", "hermes.mikemoore.top"}
ASSETS = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/desktop-commander.js": ("desktop-commander.js", "text/javascript; charset=utf-8"),
    "/desktop-commander.css": ("desktop-commander.css", "text/css; charset=utf-8"),
    "/ai-analytics.js": ("ai-analytics.js", "text/javascript; charset=utf-8"),
    "/ai-analytics.css": ("ai-analytics.css", "text/css; charset=utf-8"),
    "/infrastructure.js": ("infrastructure.js", "text/javascript; charset=utf-8"),
    "/infrastructure.css": ("infrastructure.css", "text/css; charset=utf-8"),
    "/provider-quota.js": ("provider-quota.js", "text/javascript; charset=utf-8"),
    "/provider-quota.css": ("provider-quota.css", "text/css; charset=utf-8"),
    "/brand.webp": ("brand.webp", "image/webp"),
    "/favicon.png": ("favicon.png", "image/png"),
    "/apple-touch-icon.png": ("apple-touch-icon.png", "image/png"),
    "/pwa-192.png": ("pwa-192.png", "image/png"),
    "/pwa-512.png": ("pwa-512.png", "image/png"),
    "/pwa-maskable-192.png": ("pwa-maskable-192.png", "image/png"),
    "/pwa-maskable-512.png": ("pwa-maskable-512.png", "image/png"),
    "/manifest.webmanifest": ("manifest.webmanifest", "application/manifest+json"),
    "/sw.js": ("sw.js", "text/javascript; charset=utf-8"),
    "/offline.html": ("offline.html", "text/html; charset=utf-8"),
    "/third-party-notices.txt": ("third-party-notices.txt", "text/plain; charset=utf-8"),
}
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; "
       "connect-src 'self'; img-src 'self' data:; manifest-src 'self'; "
       "worker-src 'self'; base-uri 'none'; "
       "frame-ancestors 'none'; form-action 'none'")


def make_handler(snapshot_path: Path = DEFAULT_OUTPUT, *,
                 codex_path: Path = CODEX_OUTPUT,
                 scheduler_path: Path = SCHEDULER_DB,
                 analytics_path: Path = ANALYTICS_DB,
                 desktop_commander_path: Path = DC_OUTPUT,
                 infrastructure_dir: Path = INFRA_ROOT,
                 auth_config: AuthConfig | None = None, oauth_service: OAuthService | None = None):
    config = auth_config if auth_config is not None else AuthConfig.from_env()
    oauth = oauth_service if oauth_service is not None else (
        OAuthService(config) if config.mode == "github" else None)
    if config.mode == "github" and oauth is None:
        raise AuthError("OAuth mode without service")

    class Handler(BaseHTTPRequestHandler):
        server_version = "HermesControlCenter"
        sys_version = ""

        def log_message(self, fmt, *args):
            # Never log callback paths (OAuth codes/states), cookies, or provider tokens.
            return

        def respond(self, status, content_type, payload, headers=()):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", CSP)
            for name, value in headers:
                self.send_header(name, value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(payload)

        def redirect(self, url, cookies=()):
            headers = [("Location", url)]
            headers.extend(("Set-Cookie", item) for item in cookies)
            return self.respond(303, "text/plain; charset=utf-8", b"", headers)

        def _trusted(self):
            return self.headers.get("Host", "") in HOSTS

        def _cookie(self, name):
            return parse_cookie(self.headers.get("Cookie"), name)

        def do_HEAD(self):
            path = urlsplit(self.path).path
            if path in ("/auth/github/start", "/auth/github/callback", "/auth/logout"):
                return self.respond(405, "text/plain", b"Method not allowed")
            self.do_GET()

        def do_GET(self):
            if not self._trusted():
                return self.respond(400, "text/plain", b"Invalid host")
            parsed = urlsplit(self.path)
            path = parsed.path
            if path == "/healthz" and not parsed.query:
                return self.respond(200, "text/plain", b"ok")
            if path == "/api/auth/session" and not parsed.query:
                is_authenticated = config.mode == "proxy" or oauth.authenticated(
                    self._cookie(SESSION_COOKIE))
                data = json.dumps({"mode": config.mode, "authenticated": is_authenticated},
                                  separators=(",", ":")).encode()
                return self.respond(200, "application/json; charset=utf-8", data)
            if config.mode == "github" and path == "/auth/github/start" and not parsed.query:
                try:
                    location, state = oauth.begin()
                except AuthError:
                    return self.respond(429, "text/plain", b"Sign-in temporarily unavailable")
                return self.redirect(location, (
                    cookie_header(STATE_COOKIE, state, STATE_TTL, "/auth/github"),))
            if config.mode == "github" and path == "/auth/github/callback":
                clear = cookie_header(STATE_COOKIE, "", 0, "/auth/github")
                if len(self.path) > 1500 or parsed.fragment:
                    return self.respond(403, "text/plain", b"Sign-in denied",
                                        (("Set-Cookie", clear),))
                try:
                    args = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True,
                                    max_num_fields=8)
                    # GitHub can return a provider error instead of an auth code.
                    # A callback is valid only with one code and one state, but
                    # incidental additional query fields do not weaken PKCE,
                    # same-browser state binding or the owner identity check.
                    if "error" in args:
                        raise AuthError("GitHub declined authorization")
                    if "code" not in args:
                        raise AuthError("OAuth callback missing code")
                    if "state" not in args:
                        raise AuthError("OAuth callback missing state")
                    if len(args["code"]) != 1 or len(args["state"]) != 1:
                        raise AuthError("Duplicate callback code or state")
                    session = oauth.finish(
                        code=args["code"][0], state=args["state"][0],
                        cookie_state=self._cookie(STATE_COOKIE))
                except (AuthError, ValueError) as exc:
                    # Only fixed labels are logged: never the callback URL,
                    # authorization code, state, cookie, or provider response.
                    category = {
                        "Invalid callback parameters": "invalid_parameters",
                        "GitHub declined authorization": "github_declined",
                        "OAuth callback missing code": "missing_code",
                        "OAuth callback missing state": "missing_state",
                        "Duplicate callback code or state": "duplicate_code_or_state",
                        "Cross-browser OAuth state": "state_cookie_mismatch",
                        "Used or expired OAuth state": "state_missing_or_expired",
                        "OAuth provider identity lookup failed": "github_provider_denied",
                        "Owner ID denied": "owner_denied",
                        "Invalid OAuth state": "state_invalid",
                        "Invalid OAuth code": "code_invalid",
                    }.get(str(exc), "callback_invalid")
                    logging.getLogger(__name__).warning(
                        "oauth_callback_rejection category=%s", category)
                    return self.respond(403, "text/plain", b"Sign-in denied",
                                        (("Set-Cookie", clear),))
                return self.redirect("/", (clear, cookie_header(SESSION_COOKIE, session,
                                                                 SESSION_TTL)))
            if parsed.query and path not in (
                "/api/providers/codex/policy", "/control-center/api/providers/codex/policy",
                "/api/analytics/codex", "/control-center/api/analytics/codex",
                "/api/providers/codex/history", "/control-center/api/providers/codex/history",
                "/api/providers/desktop-commander/history",
                "/control-center/api/providers/desktop-commander/history",
                "/api/infrastructure/history",
                "/control-center/api/infrastructure/history",
            ) and not (path == "/" and parsed.query == "preview=login"):
                return self.respond(404, "text/plain", b"Not found")
            if path in ("/api/providers/registry", "/control-center/api/providers/registry"):
                if config.mode == "github" and not oauth.authenticated(
                        self._cookie(SESSION_COOKIE)):
                    return self.respond(401, "application/json",
                                        b'{"error":"authentication_required"}')
                if parsed.query:
                    return self.respond(404, "text/plain", b"Not found")
                data = provider_quota_registry(
                    codex_path=codex_path, desktop_path=desktop_commander_path)
                return self.respond(200, "application/json; charset=utf-8",
                                    json.dumps(data, separators=(",", ":")).encode())
            if path in ("/api/infrastructure/hosts",
                         "/control-center/api/infrastructure/hosts",
                         "/api/infrastructure/history",
                         "/control-center/api/infrastructure/history"):
                if config.mode == "github" and not oauth.authenticated(
                        self._cookie(SESSION_COOKIE)):
                    return self.respond(401, "application/json",
                                        b'{"error":"authentication_required"}')
                if path.endswith("/history"):
                    try:
                        params = parse_qs(parsed.query, keep_blank_values=True,
                                          strict_parsing=True, max_num_fields=2)
                        if set(params) != {"host", "days"} or any(
                                len(values) != 1 for values in params.values()):
                            raise ValueError("missing or repeated parameter")
                        host, days_text = params["host"][0], params["days"][0]
                        if host not in ("hermes", "yfc") or days_text not in ("1", "7", "30"):
                            raise ValueError("invalid host or period")
                        data = infrastructure_history(infrastructure_dir, host, int(days_text))
                    except ValueError:
                        return self.respond(400, "application/json",
                                            b'{"error":"invalid_parameter"}')
                    except (OSError, sqlite3.DatabaseError):
                        return self.respond(503, "application/json",
                                            b'{"error":"infrastructure_history_unavailable"}')
                else:
                    if parsed.query:
                        return self.respond(404, "text/plain", b"Not found")
                    data = infrastructure_hosts(infrastructure_dir)
                return self.respond(200, "application/json; charset=utf-8",
                                    json.dumps(data, separators=(",", ":")).encode())
            if path in ("/api/analytics/codex", "/control-center/api/analytics/codex"):
                if config.mode == "github" and not oauth.authenticated(
                        self._cookie(SESSION_COOKIE)):
                    return self.respond(401, "application/json",
                                        b'{"error":"authentication_required"}')
                try:
                    args = parse_qs(parsed.query, strict_parsing=True,
                                    max_num_fields=1) if parsed.query else {}
                    if set(args) - {"period"} or len(args.get("period", [])) > 1:
                        raise ValueError("invalid_parameter")
                    period = args.get("period", ["7d"])[0]
                    if period not in ("24h", "7d", "30d", "all"):
                        raise ValueError("invalid_parameter")
                except ValueError:
                    return self.respond(400, "application/json",
                                        b'{"error":"invalid_parameter"}')
                try:
                    data = read_codex_analytics(analytics_path, period=period)
                except (OSError, ValueError):
                    return self.respond(503, "application/json",
                                        b'{"error":"analytics_unavailable"}')
                return self.respond(200, "application/json; charset=utf-8",
                                    json.dumps(data, separators=(",", ":")).encode())
            if path in (
                "/api/providers/codex", "/control-center/api/providers/codex",
                "/api/providers/codex/policy", "/control-center/api/providers/codex/policy",
                "/api/providers/codex/history", "/control-center/api/providers/codex/history",
            ):
                if config.mode == "github" and not oauth.authenticated(
                        self._cookie(SESSION_COOKIE)):
                    return self.respond(401, "application/json",
                                        b'{"error":"authentication_required"}')
                if path.endswith("/history") or path.endswith("/policy"):
                    try:
                        args = parse_qs(parsed.query, strict_parsing=True, max_num_fields=1)
                        key = "days" if path.endswith("/history") else "threshold"
                        if set(args) - {key} or len(args.get(key, [])) > 1:
                            raise ValueError("invalid_parameter")
                        raw = args.get(key, [])
                        if raw and (not raw[0].isascii() or not raw[0].isdigit() or len(raw[0]) > 2):
                            raise ValueError("invalid_parameter")
                        option = int(raw[0]) if raw else (7 if key == "days" else 20)
                        if not (1 <= option <= 30 if key == "days" else 0 <= option <= 50):
                            raise ValueError("invalid_parameter")
                    except ValueError:
                        return self.respond(400, "application/json", b'{"error":"invalid_parameter"}')
                elif parsed.query:
                    return self.respond(404, "text/plain", b"Not found")
                if path.endswith("/history"):
                    try:
                        data = read_codex_history(codex_path.with_name("history.sqlite3"), days=option)
                    except (OSError, ValueError):
                        return self.respond(503, "application/json",
                                            b'{"error":"codex_history_unavailable"}')
                else:
                    try:
                        data = read_snapshot(codex_path)
                    except UsageError:
                        if not path.endswith("/policy"):
                            return self.respond(503, "application/json",
                                                b'{"error":"codex_snapshot_invalid"}')
                        data = None
                    if path.endswith("/policy"):
                        data = codex_decision(data, threshold_percent=option)
                return self.respond(200, "application/json; charset=utf-8",
                                    json.dumps(data, separators=(",", ":")).encode())
            if path in ("/api/providers/desktop-commander/history",
                        "/control-center/api/providers/desktop-commander/history"):
                if config.mode == "github" and not oauth.authenticated(
                        self._cookie(SESSION_COOKIE)):
                    return self.respond(401, "application/json",
                                        b'{"error":"authentication_required"}')
                try:
                    args = parse_qs(parsed.query, keep_blank_values=True,
                                    strict_parsing=True, max_num_fields=2) if parsed.query else {}
                    if set(args) - {"days"} or len(args.get("days", [])) > 1:
                        raise ValueError("invalid_days")
                    raw_days = args.get("days", ["7"])[0]
                    if not raw_days.isascii() or not raw_days.isdigit() or len(raw_days) > 2:
                        raise ValueError("invalid_days")
                    days = int(raw_days)
                    if not 1 <= days <= 30:
                        raise ValueError("invalid_days")
                except ValueError:
                    return self.respond(400, "application/json",
                                        b'{"error":"invalid_parameter"}')
                try:
                    data = read_desktop_history(
                        desktop_commander_path.with_name("history.sqlite3"), days=days)
                except HistoryError:
                    return self.respond(503, "application/json",
                                        b'{"error":"desktop_commander_history_unavailable"}')
                return self.respond(200, "application/json; charset=utf-8",
                                    json.dumps(data, separators=(",", ":")).encode())
            if path in ("/api/providers/desktop-commander",
                        "/control-center/api/providers/desktop-commander"):
                if config.mode == "github" and not oauth.authenticated(
                        self._cookie(SESSION_COOKIE)):
                    return self.respond(401, "application/json",
                                        b'{"error":"authentication_required"}')
                try:
                    data = read_desktop_commander(desktop_commander_path)
                except CommanderError:
                    return self.respond(503, "application/json",
                                        b'{"error":"desktop_commander_snapshot_invalid"}')
                return self.respond(200, "application/json; charset=utf-8",
                                    json.dumps(data, separators=(",", ":")).encode())
            if path in ("/api/codex/tasks", "/control-center/api/codex/tasks"):
                if parsed.query:
                    return self.respond(404, "text/plain", b"Not found")
                if config.mode == "github" and not oauth.authenticated(
                        self._cookie(SESSION_COOKIE)):
                    return self.respond(401, "application/json",
                                        b'{"error":"authentication_required"}')
                try:
                    try:
                        quota = read_snapshot(codex_path)
                    except UsageError:
                        quota = None
                    data = read_scheduler_status(scheduler_path, quota_snapshot=quota)
                except StatusUnavailable:
                    return self.respond(503, "application/json",
                                        b'{"error":"scheduler_unavailable"}')
                return self.respond(200, "application/json; charset=utf-8",
                                    json.dumps(data, separators=(",", ":")).encode())
            if path in ("/api/overview", "/control-center/api/overview"):
                if config.mode == "github" and not oauth.authenticated(
                        self._cookie(SESSION_COOKIE)):
                    return self.respond(401, "application/json",
                                        b'{"error":"authentication_required"}')
                try:
                    raw = snapshot_path.read_bytes()
                    data = json.loads(raw)
                    if data.get("schema") != 1 or data.get("mode") != "read_only":
                        raise ValueError("invalid schema")
                    generated = dt.datetime.fromisoformat(data["generated_at"].replace("Z", "+00:00"))
                    age = (dt.datetime.now(dt.timezone.utc) - generated).total_seconds()
                    if not -120 <= age <= 180:
                        raise ValueError("stale or future snapshot")
                except (OSError, ValueError, TypeError, AttributeError):
                    return self.respond(503, "application/json", b'{"error":"snapshot_unavailable"}')
                return self.respond(200, "application/json; charset=utf-8", raw)
            if path in ASSETS:
                name, mime = ASSETS[path]
                try:
                    raw = (WEB / name).read_bytes()
                    if name == "index.html":
                        # Additive same-origin widget; never modify the Vite bundle at runtime.
                        raw = raw.replace(b"</head>", (
                            b'<link rel="stylesheet" href="/desktop-commander.css">'
                            b'<script src="/desktop-commander.js" defer></script>'
                            b'<link rel="stylesheet" href="/ai-analytics.css">'
                            b'<script src="/ai-analytics.js" defer></script>'
                             b'<link rel="stylesheet" href="/infrastructure.css">'
                             b'<script src="/infrastructure.js" defer></script>'
                             b'<link rel="stylesheet" href="/provider-quota.css">'
                             b'<script src="/provider-quota.js" defer></script></head>'))
                except OSError:
                    return self.respond(503, "text/plain", b"Static asset unavailable")
                return self.respond(200, mime, raw)
            return self.respond(404, "text/plain", b"Not found")

        def do_POST(self):
            if not self._trusted():
                return self.respond(400, "text/plain", b"Invalid host")
            if config.mode != "github" or self.path != "/auth/logout":
                return self.respond(501, "text/plain", b"Method not implemented")
            if self.headers.get("Origin") != ORIGIN:
                return self.respond(403, "text/plain", b"Origin denied")
            if self.headers.get("Content-Length", "0") != "0":
                return self.respond(400, "text/plain", b"Invalid body")
            oauth.revoke(self._cookie(SESSION_COOKIE))
            return self.respond(204, "text/plain", b"", (
                ("Set-Cookie", cookie_header(SESSION_COOKIE, "", 0)),))

    return Handler


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=9133)
    args = parser.parse_args()
    supplied = load_runtime_credentials("web.env")
    config = AuthConfig.from_env(supplied) if supplied is not None else AuthConfig.from_env()
    if config.mode == "github":
        if supplied is None:
            raise AuthError("GitHub auth mode requires systemd LoadCredential")
        # Both files are provided by systemd; never inject the GitHub secret
        # into the web process command line or environment.
        identity = load_runtime_credentials("broker.env")
        if identity is None:
            raise AuthError("Direct GitHub OAuth requires identity credential")
        config = AuthConfig.from_direct_credentials(supplied, identity)

    server = ThreadingHTTPServer(
        ("127.0.0.1", args.port), make_handler(auth_config=config))
    server.serve_forever(poll_interval=0.5)


if __name__ == "__main__":
    main()
