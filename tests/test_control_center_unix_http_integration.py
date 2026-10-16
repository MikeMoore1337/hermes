"""Real HTTP -> Unix RPC -> fake provider end-to-end tests, no GitHub network.

These run only where Linux SO_PEERCRED exists; they prove the web-server
session checks actually compose with a separate process-local Unix broker.
All login codes, provider identities and secrets below are synthetic.
"""
from __future__ import annotations

from datetime import datetime, timezone
import http.client
import json
import os
from pathlib import Path
import socket
import tempfile
from threading import Thread
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlsplit

from http.server import ThreadingHTTPServer

from control_center.auth import AuthConfig, ORIGIN
from control_center.oauth_broker import BrokerConfig, IdentityBroker
from control_center.server import make_handler


OWNER_ID = 42142321


class SyntheticProvider:
    def __init__(self):
        self.codes: list[str] = []

    def identify(self, config, code, verifier):
        assert len(verifier) >= 43
        assert code.startswith("h15-synthetic-")
        self.codes.append(code)
        return 9999 if code.endswith("-denied") else OWNER_ID


@unittest.skipUnless(
    hasattr(socket, "SO_PEERCRED") and hasattr(socketserver := __import__("socketserver"), "UnixStreamServer"),
    "Linux Unix socket peer credentials required",
)
class UnixHttpIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        path = str(root / "broker.sock")
        self.provider = SyntheticProvider()
        self.broker = IdentityBroker(
            BrokerConfig("Ov23syntheticID", "synthetic-secret-never-used-for-network", OWNER_ID, path),
            provider=self.provider, allowed_uid=os.getuid())
        self.addCleanup(self.broker.server_close)
        self.broker_thread = Thread(target=self.broker.serve_forever, daemon=True)
        self.broker_thread.start()
        self.addCleanup(self.broker_thread.join, 3)
        self.addCleanup(self.broker.shutdown)

        self.patch_socket = patch("control_center.auth.BROKER_SOCKET", path)
        self.patch_socket.start()
        self.addCleanup(self.patch_socket.stop)
        self.snapshot = root / "overview.json"
        self.snapshot.write_text(json.dumps({
            "schema": 1, "mode": "read_only",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "services": [{"id": "ops", "state": "active"}],
        }), encoding="utf-8")
        config = AuthConfig(
            mode="github", public_origin=ORIGIN, client_id="Ov23syntheticID",
            client_secret="", owner_id=OWNER_ID,
            session_secret=b"synthetic-local-session-secret-is-not-production",
            broker_socket=path,
        )
        self.web = ThreadingHTTPServer(
            ("127.0.0.1", 0), make_handler(self.snapshot, auth_config=config))
        self.addCleanup(self.web.server_close)
        self.web_thread = Thread(target=self.web.serve_forever, daemon=True)
        self.web_thread.start()
        self.addCleanup(self.web_thread.join, 3)
        self.addCleanup(self.web.shutdown)

    def request(self, path, method="GET", headers=None):
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.web.server_port, timeout=3)
        connection.request(method, path, headers={
            "Host": "hermes.mikemoore.top", **(headers or {})
        })
        response = connection.getresponse()
        result = response.status, response.getheaders(), response.read()
        connection.close()
        return result

    @staticmethod
    def header(headers, name):
        return next((value for key, value in headers if key.lower() == name.lower()), "")

    def begin(self):
        status, headers, body = self.request("/auth/github/start")
        self.assertEqual(status, 303)
        parsed = urlsplit(self.header(headers, "Location"))
        self.assertEqual(parsed.netloc, "github.com")
        arguments = parse_qs(parsed.query)
        self.assertEqual(arguments["code_challenge_method"], ["S256"])
        self.assertNotIn("scope", arguments)
        state = arguments["state"][0]
        state_cookie = self.header(headers, "Set-Cookie").split(";", 1)[0]
        self.assertEqual(state_cookie, "hermes_cc_state=" + state)
        return state, state_cookie

    def callback(self, code, state, browser_cookie):
        params = urlencode({"code": code, "state": state})
        return self.request("/auth/github/callback?" + params,
                            headers={"Cookie": browser_cookie})

    def test_real_http_and_unix_broker_owner_session_and_logout(self):
        self.assertEqual(self.request("/api/overview")[0], 401)
        state, browser_cookie = self.begin()
        code = "h15-synthetic-new-owner-code"
        status, headers, body = self.callback(code, state, browser_cookie)
        self.assertEqual(status, 303)
        session = next(
            value.split(";", 1)[0] for key, value in headers
            if key.lower() == "set-cookie" and value.startswith("hermes_cc_session=")
        )
        self.assertEqual(self.request("/api/overview",
                                      headers={"Cookie": session})[0], 200)
        self.assertTrue(json.loads(
            self.request("/api/auth/session", headers={"Cookie": session})[2]
        )["authenticated"])
        self.assertEqual(self.provider.codes, [code])
        self.assertEqual(
            self.request("/auth/logout", method="POST", headers={
                "Origin": ORIGIN, "Cookie": session
            })[0], 204)
        self.assertEqual(self.request("/api/overview",
                                      headers={"Cookie": session})[0], 401)

    def test_replayed_code_across_fresh_browser_states_is_denied(self):
        code = "h15-synthetic-used-code"
        first_state, first_cookie = self.begin()
        self.assertEqual(self.callback(code, first_state, first_cookie)[0], 303)
        second_state, second_cookie = self.begin()
        self.assertEqual(self.callback(code, second_state, second_cookie)[0], 403)
        self.assertEqual(self.provider.codes, [code])

    def test_denied_identity_does_not_authorize_api(self):
        state, browser_cookie = self.begin()
        self.assertEqual(
            self.callback("h15-synthetic-other-denied", state, browser_cookie)[0],
            403)
        self.assertEqual(self.request("/api/overview")[0], 401)
        self.assertEqual(self.provider.codes, ["h15-synthetic-other-denied"])

    def test_wrong_state_rejected_before_provider_rpc(self):
        state, browser_cookie = self.begin()
        self.assertEqual(
            self.callback("h15-synthetic-valid-unused", state, "hermes_cc_state=wrong")[0],
            403)
        self.assertEqual(self.provider.codes, [])
        self.assertEqual(self.request("/auth/logout", method="POST")[0], 403)


if __name__ == "__main__":
    unittest.main()
