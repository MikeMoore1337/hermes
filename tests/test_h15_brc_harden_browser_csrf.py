"""Negative safety tests for exact pinned BRC browser CSRF patch."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.h15_brc_harden_browser_csrf import (
    APP, APP_MARKER, APP_GUARD, E2E_REWRITES, apply
)
from scripts.h15_remote_commander_candidate_audit import AuditError


class BrowserOriginGuardTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.root = Path(t.name)
        p = self.root / APP
        p.parent.mkdir(parents=True)
        p.write_text("const app = express();\n" + APP_MARKER + "\n", encoding="utf-8")
        for name, (old, _) in E2E_REWRITES.items():
            f = self.root / name
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text("fixture " + old + "\n", encoding="utf-8")
        patcher = patch("scripts.h15_brc_harden_browser_csrf.evaluate",
                        return_value={"status": "SOURCE_PIN_VERIFIED"})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_enforces_origin_on_all_owner_mutation_paths(self):
        result = apply(self.root)
        source = (self.root / APP).read_text(encoding="utf-8")
        self.assertIn(APP_GUARD, source)
        self.assertIn("origin !== ownerOrigin", source)
        self.assertIn("fetchSite !== 'same-origin'", source)
        for route in ("'/auth/consent'", "'/device/approve'",
                      "'/admin/device'", "'/auth/apikeys/revoke'"):
            self.assertIn(route, source)
        self.assertEqual(result["missing_origin"], "DENIED")
        self.assertFalse(result["production_ready"])
        for name, (_, new) in E2E_REWRITES.items():
            self.assertIn(new, (self.root / name).read_text(encoding="utf-8"))

    def test_missing_upstream_fixture_fails_without_partial_write(self):
        name = "scripts/e2e-admin.mjs"
        (self.root / name).write_text("unreviewed", encoding="utf-8")
        before = (self.root / APP).read_text(encoding="utf-8")
        with self.assertRaisesRegex(AuditError, "csrf_fixture_changed"):
            apply(self.root)
        self.assertEqual((self.root / APP).read_text(encoding="utf-8"), before)

    def test_repeat_patch_refused(self):
        apply(self.root)
        with self.assertRaises(AuditError):
            apply(self.root)

    def test_symlinked_script_is_refused(self):
        f = self.root / "scripts/e2e-oauth.mjs"
        content = f.read_text(encoding="utf-8")
        f.unlink()
        victim = self.root / "victim"
        victim.write_text(content, encoding="utf-8")
        f.symlink_to(victim)
        with self.assertRaisesRegex(AuditError, "csrf_fixture_source_unsafe"):
            apply(self.root)
        self.assertEqual(victim.read_text(encoding="utf-8"), content)

    def test_unapproved_upstream_rejected(self):
        with self.assertRaisesRegex(AuditError, "unreviewed_upstream_sha"):
            apply(self.root, sha="0" * 40)


if __name__ == "__main__":
    unittest.main()
