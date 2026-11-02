"""Hermes Aero branding / PWA asset contract. No browser or real credentials."""
import json
import struct
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PUBLIC = ROOT / "control_center" / "frontend" / "public"
WEB = ROOT / "control_center" / "web"
PNG_SIZES = {
    "favicon.png": (32, 32),
    "apple-touch-icon.png": (180, 180),
    "pwa-192.png": (192, 192),
    "pwa-512.png": (512, 512),
    "pwa-maskable-192.png": (192, 192),
    "pwa-maskable-512.png": (512, 512),
}
SVG_SOURCES = {
    "orbit-brand.svg": PUBLIC / "orbit-brand.svg",
    "favicon.svg": PUBLIC / "favicon.svg",
    "pwa-orbit.svg": PUBLIC / "pwa-orbit.svg",
    "maskable": ROOT / "assets/branding/hermes-aero-maskable.svg",
    "wide": ROOT / "assets/branding/hermes-aero-wide.svg",
    "horizontal": ROOT / "assets/branding/hermes-aero-horizontal.svg",
}


class TestAeroAssets(unittest.TestCase):
    def test_svg_assets_are_local_and_have_viewbox(self):
        ns = "{http://www.w3.org/2000/svg}"
        for name, path in SVG_SOURCES.items():
            with self.subTest(name=name):
                content = path.read_text(encoding="utf-8")
                root = ET.fromstring(content)
                self.assertEqual(root.tag, ns + "svg")
                self.assertIn("viewBox", root.attrib)
                self.assertNotIn("<script", content.lower())
                self.assertNotIn("http://", content.replace("http://www.w3.org/2000/svg", ""))
                self.assertNotIn("https://", content)

    def test_metallic_mark_has_four_feathers_per_wing_and_no_embedded_images(self):
        mark = (PUBLIC / "orbit-brand.svg").read_text(encoding="utf-8")
        self.assertIn("Four separated feathers", mark)
        self.assertEqual(mark.count("M10 15 L116 55 L116 79"), 2)
        self.assertEqual(mark.count("M82 115 L116 127 L116 140"), 2)
        self.assertIn("crossTop", mark)
        self.assertIn("crossFront", mark)
        self.assertNotIn("data:image", mark)
        self.assertNotIn("<image", mark)
        self.assertNotIn("<foreignObject", mark)

    def test_maskable_wings_fit_inside_android_safe_circle(self):
        import math
        import re
        svg = (ROOT / "assets/branding/hermes-aero-maskable.svg").read_text(encoding="utf-8")
        transform = re.search(r'transform="translate\\((\\d+(?:\\.\\d+)?) (\\d+(?:\\.\\d+)?)\\) scale\\((\\d+(?:\\.\\d+)?)\\)"', svg)
        self.assertIsNotNone(transform, "maskable emblem transform missing")
        tx, ty, scale = map(float, transform.groups())
        # Outer wing tips and the two bottom H facets are the bounding extremes.
        extremities = ((10, 15), (310, 15), (111, 175), (209, 175))
        max_radius = max(math.hypot(x * scale + tx - 256, y * scale + ty - 256)
                         for x, y in extremities)
        self.assertLessEqual(max_radius, 512 * .4, "mark may be cropped by maskable icon")

    def test_raster_sizes_and_signatures(self):
        for name, size in PNG_SIZES.items():
            with self.subTest(name=name):
                data = (PUBLIC / name).read_bytes()
                self.assertTrue(data.startswith(b"\x89PNG\r\n\x1a\n"))
                self.assertEqual(struct.unpack(">II", data[16:24]), size)
                self.assertIn(data[25], (2, 6), 'PWA assets must use RGB/RGBA, not a palette')
        brand = (PUBLIC / "brand.webp").read_bytes()
        self.assertEqual(brand[:4], b"RIFF")
        self.assertEqual(brand[8:12], b"WEBP")

    def test_manifest_preserves_install_contract(self):
        manifest = json.loads((PUBLIC / "manifest.webmanifest").read_text(encoding="utf-8"))
        icons = {(item["src"], item["purpose"]) for item in manifest["icons"]}
        self.assertEqual(icons, {
            ("/pwa-192.png", "any"), ("/pwa-512.png", "any"),
            ("/pwa-maskable-192.png", "maskable"),
            ("/pwa-maskable-512.png", "maskable"),
        })
        self.assertEqual(manifest["display"], "standalone")

    def test_build_output_asset_parity(self):
        for name in ["orbit-brand.svg", "favicon.svg", "pwa-orbit.svg",
                     "brand.webp", *PNG_SIZES]:
            with self.subTest(name=name):
                self.assertEqual((PUBLIC / name).read_bytes(), (WEB / name).read_bytes())


if __name__ == "__main__":
    unittest.main()
