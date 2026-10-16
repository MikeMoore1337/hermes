"""Local-only, unprivileged HTTP server serving static UI and sanitized snapshots.

Authentication is deliberately not implemented here: an authenticated HTTPS reverse
proxy is required before any public exposure. The listener is fixed to loopback.
"""
from __future__ import annotations

import argparse
import datetime as dt
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path

from control_center.snapshot import DEFAULT_OUTPUT

WEB = Path(__file__).with_name("web")
HOSTS = {"127.0.0.1:9133", "localhost:9133", "hermes.mikemoore.top"}
ASSETS = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
}
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; "
       "connect-src 'self'; img-src 'self' data:; base-uri 'none'; "
       "frame-ancestors 'none'; form-action 'none'")


def make_handler(snapshot_path: Path = DEFAULT_OUTPUT):
    class Handler(BaseHTTPRequestHandler):
        server_version = "HermesControlCenter"
        sys_version = ""

        def log_message(self, fmt, *args):
            # Do not log URLs or headers: security events are handled by the proxy.
            return

        def respond(self, status, content_type, payload):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", CSP)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(payload)

        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            if self.headers.get("Host", "") not in HOSTS:
                return self.respond(400, "text/plain", b"Invalid host")
            path = self.path
            if path == "/healthz":
                return self.respond(200, "text/plain", b"ok")
            if path in ("/api/overview", "/control-center/api/overview"):
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
                except OSError:
                    return self.respond(503, "text/plain", b"Static asset unavailable")
                return self.respond(200, mime, raw)
            return self.respond(404, "text/plain", b"Not found")
    return Handler


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=9133)
    args = parser.parse_args()
    # Hard-coded loopback is a security boundary; no --host / 0.0.0.0 option.
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler())
    srv.serve_forever(poll_interval=0.5)


if __name__ == "__main__":
    main()
