"""#455 observer patch: isolated pinned-source regression checks, no activation."""
from __future__ import annotations
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.h15_brc_observer_gateway import (
    APP, MODULE, IMPORT_ANCHOR, OBSERVER_IMPORT, START, TIMER,
    SHUTDOWN, OBSERVER_SHUTDOWN, apply,
)
from scripts.h15_remote_commander_candidate_audit import AuditError


class ObserverGatewayTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.app = self.root / APP
        self.app.parent.mkdir(parents=True, exist_ok=True)
        self.app.write_text(
            IMPORT_ANCHOR + "\n" + START + "\n" +
            SHUTDOWN + "\n", encoding="utf-8"
        )
        p = patch("scripts.h15_brc_observer_gateway.evaluate")
        p.start()
        self.addCleanup(p.stop)

    def test_one_opt_in_timer_no_http_or_new_tools(self):
        result = apply(self.root)
        self.assertEqual(result["status"], "DISPOSABLE_OBSERVER_PATCHED")
        self.assertFalse(result["production_activated"])
        updated = self.app.read_text()
        self.assertEqual(updated.count(OBSERVER_IMPORT), 1)
        self.assertEqual(updated.count(TIMER), 1)
        self.assertEqual(updated.count(OBSERVER_SHUTDOWN), 1)
        self.assertIn("observerEnabled()", updated)
        module = (self.root / MODULE).read_text()
        self.assertIn("hub.list(userId)", module)
        self.assertIn("store.listDevices(userId)", module)
        self.assertIn("fs.renameSync", module)
        self.assertIn("fs.fsyncSync", module)
        self.assertNotIn("registerTool", module)
        self.assertNotIn("http.createServer", module)

    def test_duplicate_application_denied_atomically(self):
        apply(self.root)
        before = self.app.read_bytes()
        source = (self.root / MODULE).read_bytes()
        with self.assertRaisesRegex(AuditError, "observer_source_not_ready"):
            apply(self.root)
        self.assertEqual(self.app.read_bytes(), before)
        self.assertEqual((self.root / MODULE).read_bytes(), source)

    def test_marker_drift_fails_without_written_module(self):
        self.app.write_text(self.app.read_text().replace(START, "unknown startup"))
        before = self.app.read_bytes()
        with self.assertRaisesRegex(AuditError, "observer_upstream_marker_drift"):
            apply(self.root)
        self.assertEqual(self.app.read_bytes(), before)
        self.assertFalse((self.root / MODULE).exists())

    def test_symlink_target_and_wrong_source_denied(self):
        private = self.root / "private"
        private.write_text("NO_CHANGE")
        target = self.root / MODULE
        target.symlink_to(private)
        with self.assertRaisesRegex(AuditError, "observer_source_symlink"):
            apply(self.root)
        self.assertEqual(private.read_text(), "NO_CHANGE")
        with self.assertRaisesRegex(AuditError, "unreviewed_upstream_sha"):
            apply(self.root, sha="f" * 40)

    def test_module_requires_existing_app(self):
        self.app.unlink()
        with self.assertRaisesRegex(AuditError, "observer_source_not_ready"):
            apply(self.root)

if __name__ == "__main__":
    unittest.main()
