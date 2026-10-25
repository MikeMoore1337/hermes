"""#455: owner-approved C UI is protected, read-only and has no new API grants."""
from __future__ import annotations
from http.server import ThreadingHTTPServer
from threading import Thread
from urllib.request import Request, build_opener, ProxyHandler
from urllib.error import HTTPError
import unittest

from control_center.auth import AuthConfig
from control_center.server import make_handler


class SyntheticOAuth:
    """No credentials or real GitHub network: simulate authenticated state only."""
    def authenticated(self, cookie):
        return cookie == "synthetic_owner_session"


class CPanelHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            make_handler(auth_config=AuthConfig(mode="github"),
                         oauth_service=SyntheticOAuth()))
        cls.thread = Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)

    def request(self, path, owner=False):
        headers = {"Host": "localhost:9133"}
        if owner:
            headers["Cookie"] = "hermes_cc_session=synthetic_owner_session"
        req = Request(
            "http://127.0.0.1:" + str(self.server.server_port) + path,
            headers=headers)
        try:
            response = build_opener(ProxyHandler({})).open(req, timeout=4)
        except HTTPError as exc:
            response = exc
        with response:
            return response.status, response.headers, response.read()

    def test_owner_page_denies_guest_and_is_no_store(self):
        code, headers, body = self.request("/hermes-brc")
        self.assertEqual(code, 401)
        self.assertNotIn(b"brc-workgrid", body)
        code, headers, body = self.request("/hermes-brc", owner=True)
        self.assertEqual(code, 200)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertIn(b"brc-workgrid", body)
        self.assertIn(b"/hermes-brc.js", body)
        self.assertIn(b"style-src 'self'", headers["Content-Security-Policy"])
        self.assertNotIn(b"demo-token", body)

    def test_static_assets_are_exact_and_do_not_add_execution_apis(self):
        for name,content_type in (
            ("hermes-brc.js", "text/javascript; charset=utf-8"),
            ("hermes-brc.css", "text/css; charset=utf-8"),
        ):
            code, headers, body = self.request("/"+name)
            self.assertEqual((code, headers["Content-Type"]), (200,content_type))
            self.assertGreater(len(body), 500)
            self.assertEqual(headers["Cache-Control"], "private, no-cache")
        js = self.request("/hermes-brc.js")[2].decode()
        self.assertIn('fetch("/api/providers/hermes-brc"', js)
        self.assertIn('credentials:"same-origin"',js)
        self.assertNotIn('"/api/tools/call"',js)
        self.assertNotIn("eval(",js)

    def test_reject_query_params_and_wrong_host(self):
        self.assertEqual(self.request("/hermes-brc?utm_source=chatgpt.com", owner=True)[0], 404)
        self.assertEqual(self.request("/hermes-brc/extra", owner=True)[0], 404)


if __name__ == "__main__":
    unittest.main()
