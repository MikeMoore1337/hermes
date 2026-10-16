"""Exact static asset routes for the React/Vite read-only UI."""
from http.server import ThreadingHTTPServer
from pathlib import Path
import tempfile
from threading import Thread
import unittest
from urllib.request import Request, urlopen
from urllib.error import HTTPError

from control_center.server import make_handler


class StaticContracts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.server = ThreadingHTTPServer(
            ("127.0.0.1", 0), make_handler(Path(self.tmp.name) / "does-not-exist"))
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.tmp.cleanup()

    def get(self, path, host="hermes.mikemoore.top", method="GET"):
        req = Request(f"http://127.0.0.1:{self.server.server_port}{path}",
                      method=method, headers={"Host": host})
        try:
            result = urlopen(req, timeout=2)
        except HTTPError as exc:
            result = exc
        with result:
            return result.status, result.headers, result.read()

    def test_raster_branded_assets_are_locally_served(self):
        for route, mime, signature in (
            ("/brand.webp", "image/webp", b"RIFF"),
            ("/favicon.png", "image/png", b"\x89PNG"),
            ("/apple-touch-icon.png", "image/png", b"\x89PNG"),
        ):
            status, headers, body = self.get(route)
            self.assertEqual(status, 200, route)
            self.assertEqual(headers["Content-Type"], mime)
            self.assertTrue(body.startswith(signature))
            self.assertEqual(headers["Cache-Control"], "no-store")
            self.assertIn("default-src 'none'", headers["Content-Security-Policy"])

    def test_third_party_licence_notices_are_exact_local_assets(self):
        status, headers, body = self.get("/third-party-notices.txt")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "text/plain; charset=utf-8")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertIn(b"lucide-react 0.468.0", body)
        self.assertIn(b"react-dom 19.2.0", body)
        self.assertIn(b"ISC License", body)
        self.assertIn(b"MIT License", body)
        # No arbitrary query strings, package files or directories.
        self.assertEqual(self.get("/third-party-notices.txt?utm=1")[0], 404)

    def test_login_preview_has_same_static_shell(self):
        a = self.get("/")
        b = self.get("/?preview=login")
        self.assertEqual(a[0], 200)
        self.assertEqual(b[0], 200)
        self.assertEqual(a[2], b[2])

    def test_no_unlisted_files_or_query_allowed(self):
        for path in ("/src/main.jsx", "/package.json", "/.env",
                     "/api/overview?test=1", "/?next=https://evil.invalid",
                     "/brand.webp?utm=1", "/assets/secret.js"):
            self.assertEqual(self.get(path)[0], 404, path)
        self.assertEqual(self.get("/", host="attacker.example")[0], 400)

    def test_write_endpoints_are_not_implemented(self):
        self.assertEqual(self.get("/", method="POST")[0], 501)
        self.assertEqual(self.get("/", method="PUT")[0], 501)


if __name__ == "__main__":
    unittest.main()
