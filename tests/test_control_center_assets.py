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

    def get(self, path, host="hermes.mikemoore.top", method="GET", headers=None):
        request_headers = {"Host": host, **(headers or {})}
        req = Request(f"http://127.0.0.1:{self.server.server_port}{path}",
                      method=method, headers=request_headers)
        try:
            result = urlopen(req, timeout=2)
        except HTTPError as exc:
            result = exc
        with result:
            return result.status, result.headers, result.read()

    def test_raster_branded_assets_are_locally_served(self):
        for route, mime, signature in (
            ("/brand.webp", "image/webp", b"RIFF"),
            ("/orbit-brand.svg", "image/svg+xml", b"<svg"),
            ("/favicon.svg", "image/svg+xml", b"<svg"),
            ("/pwa-orbit.svg", "image/svg+xml", b"<svg"),
            ("/pwa-maskable-192.png", "image/png", b"\x89PNG"),
            ("/pwa-maskable-512.png", "image/png", b"\x89PNG"),
            ("/favicon.png", "image/png", b"\x89PNG"),
            ("/apple-touch-icon.png", "image/png", b"\x89PNG"),
        ):
            status, headers, body = self.get(route)
            self.assertEqual(status, 200, route)
            self.assertEqual(headers["Content-Type"], mime)
            self.assertTrue(body.startswith(signature))
            self.assertEqual(headers["Cache-Control"], "private, no-cache")
            self.assertIn("default-src 'none'", headers["Content-Security-Policy"])

    def test_third_party_licence_notices_are_exact_local_assets(self):
        status, headers, body = self.get("/third-party-notices.txt")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "text/plain; charset=utf-8")
        self.assertEqual(headers["Cache-Control"], "private, no-cache")
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
        self.assertIn(b'data-auth-mode="proxy" data-authenticated="true"', a[2])
        self.assertIn(b'data-auth-mode="proxy" data-authenticated="true"', b[2])
        self.assertNotIn(b'/desktop-commander.js', a[2])
        self.assertNotIn(b'/desktop-commander.js', b[2])
        self.assertNotIn(b'/provider-quota.js', b[2])

    def test_brc_deep_link_reuses_authenticated_react_shell(self):
        home_status, home_headers, home = self.get("/")
        brc_status, brc_headers, brc = self.get("/hermes-brc")
        self.assertEqual((home_status, brc_status), (200, 200))
        self.assertEqual(brc, home)
        self.assertEqual(brc_headers["Content-Type"], "text/html; charset=utf-8")
        self.assertEqual(brc_headers["Cache-Control"], "no-store")
        self.assertIn(b'data-auth-mode="proxy" data-authenticated="true"', brc)
        self.assertIn(b'/app.js', brc)
        self.assertNotIn(b'/hermes-brc.js', brc)
        self.assertNotIn(b'brc-shell', brc)
        self.assertIn("default-src 'none'", brc_headers["Content-Security-Policy"])

    def test_unified_orbit_icons_are_local_and_owner_only_on_the_document(self):
        status, headers, body = self.get("/orbit-ui-icons.js")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "text/javascript; charset=utf-8")
        self.assertEqual(headers["Cache-Control"], "private, no-cache")
        self.assertIn(b"HermesOrbitIcons", body)
        self.assertNotIn(b"fetch(", body)
        self.assertNotIn(b"eval(", body)
        self.assertIn("script-src 'self'", headers["Content-Security-Policy"])
        status, headers, root = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn(b'src="/orbit-ui-icons.js" defer', root)
        self.assertLess(root.index(b'/orbit-ui-icons.js'), root.index(b'/ai-analytics.js'))
        preview = self.get("/?preview=login")[2]
        self.assertNotIn(b'/orbit-ui-icons.js', preview)
        self.assertEqual(self.get("/orbit-ui-icons.js?debug=1")[0], 404)

    def test_static_assets_revalidate_without_caching_html_or_sw(self):
        status, headers, body = self.get("/app.js")
        self.assertEqual(status, 200)
        self.assertGreater(len(body), 1000)
        tag = headers["ETag"]
        self.assertEqual(headers["Cache-Control"], "private, no-cache")
        status, headers, body = self.get("/app.js", headers={"If-None-Match": tag})
        self.assertEqual((status, body), (304, b""))
        self.assertEqual(headers["ETag"], tag)
        self.assertEqual(headers["Cache-Control"], "private, no-cache")
        self.assertIn("default-src 'none'", headers["Content-Security-Policy"])
        for path in ("/", "/?preview=login", "/hermes-brc", "/desktop-commander-archive", "/sw.js", "/offline.html"):
            status, headers, _ = self.get(path, headers={"If-None-Match": tag})
            self.assertEqual(status, 200, path)
            self.assertEqual(headers["Cache-Control"], "no-store", path)

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
