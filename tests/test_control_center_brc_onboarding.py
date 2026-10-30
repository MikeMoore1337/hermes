"""Owner-only, non-executing project previews; no network or host access."""
from __future__ import annotations

import json
import http.client
from http.server import ThreadingHTTPServer
from threading import Thread
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener
import unittest
from unittest.mock import patch

from control_center.auth import AuthConfig, ORIGIN
from control_center.brc_onboarding import PreviewRejected, preview
from control_center.server import make_handler


class PreviewTests(unittest.TestCase):
    def test_valid_preview_never_claims_live_checks(self):
        with patch("socket.socket.connect", side_effect=AssertionError("network")):
            result = preview("https://github.com/Example/Project.git")
        self.assertEqual(result, {
            "schema": 1, "status": "preview_only",
            "repository": "https://github.com/Example/project.git",
            "device": "Windows sandbox", "root": "/workspace/projects/project",
            "scope": "sandbox", "catalog": "not_reserved",
            "remote": "not_checked", "filesystem": "not_checked",
            "can_connect": False,
        })

    def test_existing_catalog_name_is_a_conflict(self):
        result = preview("https://github.com/example/HERMES")
        self.assertEqual(result["catalog"], "reserved")
        self.assertFalse(result["can_connect"])

    def test_urls_with_credentials_paths_or_other_hosts_are_rejected(self):
        for value in (
            "http://github.com/example/project", "https://evil.example/example/project",
            "https://github.com@evil.example/example/project",
            "https://name:secret@github.com/example/project",
            "https://github.com/example/../hermes",
            "https://github.com/example/%2fproject",
            "https://github.com/example/project?token=secret",
            "https://github.com/example/project#section",
            "https://github.com/example/project/subdir",
            "https://github.com/example/project_with_underscore",
            "https://github.com/example/p",
            "https://github.com/example/" + "a" * 81,
            "file:///workspace/projects/project", "", None,
        ):
            with self.subTest(value=value), self.assertRaises(PreviewRejected):
                preview(value)


class Owner:
    def authenticated(self, cookie):
        return cookie == "test_owner"


class PreviewHttpTests(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(
            auth_config=AuthConfig(mode="github"), oauth_service=Owner()))
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def post(self, body=b'{"repository_url":"https://github.com/example/project"}',
             headers=None, path="/api/providers/hermes-brc/onboarding-preview"):
        values = {"Host": "localhost:9133", "Origin": ORIGIN,
                  "Cookie": "hermes_cc_session=test_owner",
                  "Content-Type": "application/json",
                  "X-Hermes-Onboarding-Intent": "owner-interactive"}
        values.update(headers or {})
        req = Request(f"http://127.0.0.1:{self.server.server_port}" + path,
                      data=body, method="POST", headers=values)
        try:
            response = build_opener(ProxyHandler({})).open(req, timeout=5)
        except HTTPError as exc:
            response = exc
        with response:
            return response.status, response.headers, response.read()

    def test_owner_gets_preview_without_executing_or_claiming_live_checks(self):
        with patch("subprocess.run", side_effect=AssertionError("process")):
            status, headers, body = self.post()
        self.assertEqual(status, 200)
        self.assertEqual(headers["Cache-Control"], "no-store")
        value = json.loads(body)
        self.assertFalse(value["can_connect"])
        self.assertEqual(value["filesystem"], "not_checked")
        self.assertEqual(value["remote"], "not_checked")

    def test_auth_origin_intent_and_fetch_site_fail_closed(self):
        for headers, status in (
            ({"Cookie": ""}, 401),
            ({"Origin": "https://evil.example"}, 403),
            ({"X-Hermes-Onboarding-Intent": ""}, 403),
            ({"Sec-Fetch-Site": "cross-site"}, 403),
            ({"Host": "evil.example"}, 400),
            ({"Content-Type": "text/plain"}, 415),
        ):
            with self.subTest(headers=headers):
                self.assertEqual(self.post(headers=headers)[0], status)

    def test_invalid_or_ambiguous_bodies_rejected_without_reflection(self):
        for body in (
            b'{"repository_url":"https://github.com/example/project?token=secret"}',
            b'{"repository_url":"https://github.com/example/project","extra":true}',
            b'{"repository_url":"x","repository_url":"y"}',
            b'{"repository_url":NaN}', b'[]', b'{}', b'x' * 4097,
        ):
            with self.subTest(body=body[:80]):
                status, _, payload = self.post(body=body)
                self.assertIn(status, (400, 413))
                self.assertNotIn(b"secret", payload)

    def test_duplicate_length_and_transfer_encoding_are_rejected(self):
        body = b'{"repository_url":"https://github.com/example/project"}'
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        self.addCleanup(conn.close)
        conn.putrequest("POST", "/api/providers/hermes-brc/onboarding-preview", skip_host=True)
        for key, value in (("Host", "localhost:9133"), ("Origin", ORIGIN),
                           ("Cookie", "hermes_cc_session=test_owner"),
                           ("Content-Type", "application/json"),
                           ("X-Hermes-Onboarding-Intent", "owner-interactive"),
                           ("Content-Length", str(len(body))),
                           ("Content-Length", str(len(body)))):
            conn.putheader(key, value)
        conn.endheaders(body)
        self.assertEqual(conn.getresponse().status, 413)
        self.assertEqual(self.post(headers={"Transfer-Encoding": "chunked"})[0], 413)

    def test_proxy_mode_does_not_enable_preview(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(
            auth_config=AuthConfig(mode="proxy")))
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 3)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        port, self.server = self.server, server
        try:
            self.assertEqual(self.post()[0], 403)
        finally:
            self.server = port


if __name__ == "__main__":
    unittest.main()
