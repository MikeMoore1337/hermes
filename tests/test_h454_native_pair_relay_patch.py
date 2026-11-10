"""H454 device-code relay hardening patch on disposable pinned-source fixtures."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.h454_native_pair_relay_patch import apply, BLOCK, ANCHOR
from scripts.h15_remote_commander_candidate_audit import AuditError
from scripts.h15_brc_harden_relay import ROTATE_PATCH

SOURCE = ("// dummy fake source pinned by test\n"
          "    const dev = token ? store.getDeviceByToken(token) : undefined;\n"
          + ANCHOR + "someCode;\n" + ROTATE_PATCH + "\n")


class NativePairingRelayPatchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = self.root = Path(self.tmp.name)
        self.app = root / "packages/relay/src/app.ts"
        self.app.parent.mkdir(parents=True)
        self.app.write_text(SOURCE, encoding="utf-8")
        p = patch("scripts.h454_native_pair_relay_patch.evaluate")
        p.start()
        self.addCleanup(p.stop)

    def test_new_device_id_must_come_from_approved_pending_row(self):
        before = self.app.read_text()
        result = apply(self.root)
        self.assertFalse(result["production_modified"])
        self.assertEqual(result["native_devices"], 3)
        after = self.app.read_text()
        self.assertNotEqual(after, before)
        self.assertEqual(after.count(BLOCK), 1)
        self.assertLess(after.index(BLOCK), after.index(ANCHOR))
        self.assertIn("device_id !== undefined", after)
        self.assertIn("row.device_id", after)
        self.assertIn("store.getDevice(row.device_id)", after)
        self.assertIn("native_pairing_scope_denied", after)
        self.assertIn("h454-win-native-", after)
        self.assertIn("h454-linux-hermes-", after)
        self.assertIn("h454-linux-yfc-", after)
        self.assertIn(ROTATE_PATCH, after)

    def test_double_patch_and_drift_never_apply_partial_modification(self):
        apply(self.root)
        signed = self.app.read_bytes()
        with self.assertRaises(AuditError):
            apply(self.root)
        self.assertEqual(signed, self.app.read_bytes())
        self.app.write_text(SOURCE.replace(ANCHOR, "UNREVIEWED"))
        before = self.app.read_bytes()
        with self.assertRaises(AuditError):
            apply(self.root)
        self.assertEqual(before, self.app.read_bytes())

    def test_wrong_sha_and_symlink_escape_denied(self):
        with self.assertRaises(AuditError):
            apply(self.root, sha="0"*40)
        original = self.app.read_bytes()
        out = self.root / "foreign"
        out.write_bytes(original)
        self.app.unlink()
        self.app.symlink_to(out)
        with self.assertRaises(AuditError):
            apply(self.root)
        self.assertEqual(out.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
