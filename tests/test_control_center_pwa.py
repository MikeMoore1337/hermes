"""PWA routes are explicit and never expose private content or SPA fallbacks."""
import json
import struct
import unittest
from pathlib import Path
from control_center.server import ASSETS, WEB, CSP

class PwaRoutesTests(unittest.TestCase):
    def test_exact_public_allowlist_and_mime(self):
        for route, mime in {
            "/manifest.webmanifest": "application/manifest+json",
            "/sw.js": "text/javascript; charset=utf-8",
            "/offline.html": "text/html; charset=utf-8",
            "/pwa-192.png": "image/png",
            "/pwa-512.png": "image/png",
            "/pwa-maskable-192.png": "image/png",
            "/pwa-maskable-512.png": "image/png",
        }.items():
            self.assertEqual(ASSETS[route][1], mime)
            self.assertTrue((WEB / ASSETS[route][0]).is_file())
        self.assertNotIn("/oauth/client-secret", ASSETS)
        self.assertNotIn("/api/overview", ASSETS)

    def test_manifest_local_standalone_icons(self):
        data=json.loads((WEB/"manifest.webmanifest").read_text(encoding="utf8"))
        self.assertEqual(data["start_url"], "/")
        self.assertEqual(data["scope"], "/")
        self.assertEqual(data["id"], "/")
        self.assertEqual(data["display"], "standalone")
        self.assertEqual(data["lang"], "ru")
        self.assertEqual({x["sizes"] for x in data["icons"]},{"192x192","512x512"})
        self.assertTrue(all(x["src"].startswith("/") for x in data["icons"]))
        for icon in data["icons"]:
            raw=(WEB / icon["src"].lstrip("/")).read_bytes()
            self.assertTrue(raw.startswith(b"\x89PNG\r\n\x1a\n"))

    def test_manifest_icon_dimensions_match_actual_png_header(self):
        """A forged or mismatched install icon must fail CI before release."""
        data = json.loads((WEB / "manifest.webmanifest").read_text(encoding="utf8"))
        declared_paths = set()
        for icon in data["icons"]:
            self.assertEqual(icon["type"], "image/png")
            self.assertIn(icon["purpose"], {"any", "maskable"})
            self.assertEqual(type(icon["sizes"]), str)
            self.assertRegex(icon["sizes"], r"^[1-9][0-9]*x[1-9][0-9]*$")
            width, height = (int(value) for value in icon["sizes"].split("x"))
            self.assertEqual(width, height)
            self.assertIn(width, {192, 512})
            self.assertRegex(icon["src"], r"^/[a-z0-9-]+\.png$")
            self.assertNotIn(icon["src"], declared_paths)
            declared_paths.add(icon["src"])
            blob = (WEB / icon["src"].lstrip("/")).read_bytes()
            self.assertGreaterEqual(len(blob), 33)
            self.assertEqual(blob[:8], b"\x89PNG\r\n\x1a\n")
            self.assertEqual(blob[12:16], b"IHDR")
            self.assertEqual(struct.unpack(">II", blob[16:24]), (width, height))
            self.assertEqual(blob[24], 8)  # PNG bit depth
            self.assertIn(blob[25], (2, 6))  # RGB or RGBA, no indexed palette
        self.assertEqual(declared_paths, {"/pwa-192.png", "/pwa-512.png",
                                          "/pwa-maskable-192.png", "/pwa-maskable-512.png"})
        self.assertEqual({(icon["sizes"], icon["purpose"]) for icon in data["icons"]},
                         {("192x192", "any"), ("512x512", "any"),
                          ("192x192", "maskable"), ("512x512", "maskable")})

    def test_privacy_policy_in_sw_is_narrow(self):
        sw=(WEB/"sw.js").read_text(encoding="utf8")
        self.assertIn('const OFFLINE_URL = "/offline.html"',sw)
        self.assertNotIn("cache.put(",sw)
        self.assertNotIn("localStorage",sw)
        self.assertIn('request.mode !== "navigate"',sw)
        self.assertIn('url.pathname.startsWith("/auth/")',sw)
        self.assertIn('url.pathname.startsWith("/api/")',sw)
        self.assertIn("worker-src 'self'",CSP)
        self.assertIn("manifest-src 'self'",CSP)

    def test_offline_page_contains_no_operational_metrics(self):
        html=(WEB/"offline.html").read_text(encoding="utf8")
        self.assertNotIn("Ops Watch",html)
        self.assertNotIn("Research Scout",html)
        self.assertNotIn("Bearer ",html)

if __name__ == "__main__":
    unittest.main()
