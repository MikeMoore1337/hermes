"""Offline contracts for the future native Hermes Web Dashboard extension.

These tests intentionally do not start the autonomous Agent or external providers.
"""
from __future__ import annotations

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "plugins" / "hermes-control-center" / "dashboard"


class NativeDashboardPluginTests(unittest.TestCase):
    def test_manifest_and_required_assets(self):
        manifest = json.loads((DASHBOARD / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["name"], "hermes-control-center")
        self.assertEqual(manifest["label"], "Центр управления")
        self.assertEqual(manifest["tab"]["path"], "/control-center")
        self.assertEqual(manifest["tab"]["position"], "after:skills")
        self.assertEqual(manifest["icon"], "Activity")
        self.assertEqual(manifest["api"], "plugin_api.py")
        self.assertTrue((DASHBOARD / manifest["entry"]).is_file())
        self.assertTrue((DASHBOARD / manifest["api"]).is_file())

    def test_ui_uses_dashboard_auth_token_aware_sdk(self):
        js = (DASHBOARD / "dist" / "index.js").read_text(encoding="utf-8")
        self.assertIn("SDK.fetchJSON(", js)
        self.assertIn('"/api/plugins/hermes-control-center/overview"', js)
        self.assertIn('registry.register("hermes-control-center"', js)
        self.assertNotIn('fetch("/api/plugins/', js)
        self.assertNotIn("innerHTML", js)
        self.assertNotIn("eval(", js)
        self.assertNotIn("XMLHttpRequest", js)

    def test_backend_is_read_only_and_fixed_path(self):
        py = (DASHBOARD / "plugin_api.py").read_text(encoding="utf-8")
        self.assertIn('@router.get("/overview")', py)
        self.assertIn("SNAPSHOT = Path(", py)
        self.assertIn("snapshot_unavailable", py)
        self.assertIn("stale snapshot", py)
        self.assertNotIn("@router.post(", py)
        self.assertNotIn("subprocess", py)
        self.assertNotIn("os.system", py)


if __name__ == "__main__":
    unittest.main()
