"""Offline tests of pinned H-15 native READ gateway (#454); no live relay changes."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.h15_brc_native_read_gateway import (
    apply, MCP, IMPORT, LIST, CALL, NATIVE_IMPORT, NATIVE_CALL
)
from scripts.h15_remote_commander_candidate_audit import AuditError

class NativeReadGatewayTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.folder = self.root / MCP
        self.folder.mkdir(parents=True)
        self.server = self.folder / "server.ts"
        self.server.write_text(
            IMPORT + "\n" + LIST + "\n" + CALL + "\n", encoding="utf-8")
        for f in ("hermes-workspaces.ts","hermes-policy.ts",
                  "hermes-tool-catalog.ts","invoke.ts"):
            (self.folder / f).write_text("export {};\n", encoding="utf-8")
        p = patch("scripts.h15_brc_native_read_gateway.evaluate")
        p.start()
        self.addCleanup(p.stop)

    def test_exact_only_tools_injected_before_generic_invocation(self):
        result = apply(self.root)
        self.assertEqual(result["status"], "DISPOSABLE_NATIVE_READ_RELAY_PATCHED")
        self.assertFalse(result["production_activation"])
        actual = self.server.read_text()
        self.assertIn(NATIVE_IMPORT, actual)
        self.assertIn("...NATIVE_TOOLS", actual)
        self.assertEqual(actual.count(NATIVE_CALL), 1)
        self.assertLess(actual.index(NATIVE_CALL), actual.index(CALL))
        self.assertIn("invokeOwnerNativeRead", (self.folder / "hermes-native-read.ts").read_text())
        self.assertNotIn("deviceId: { type", (self.folder / "hermes-native-read.ts").read_text())

    def test_double_patch_denied_without_further_modifications(self):
        apply(self.root)
        before = self.server.read_bytes()
        target = (self.folder / "hermes-native-read.ts").read_bytes()
        with self.assertRaises(AuditError):
            apply(self.root)
        self.assertEqual(before, self.server.read_bytes())
        self.assertEqual(target, (self.folder / "hermes-native-read.ts").read_bytes())

    def test_source_drift_rejected_before_any_write(self):
        self.server.write_text(self.server.read_text().replace(CALL, "UNREVIEWED()"))
        original = self.server.read_bytes()
        with self.assertRaisesRegex(AuditError, "native_relay_marker_drift"):
            apply(self.root)
        self.assertFalse((self.folder / "hermes-native-read.ts").exists())
        self.assertEqual(self.server.read_bytes(), original)

    def test_missing_hardened_modules_denied(self):
        (self.folder / "hermes-policy.ts").unlink()
        with self.assertRaisesRegex(AuditError, "native_relay_source_not_ready"):
            apply(self.root)
        self.assertFalse((self.folder / "hermes-native-read.ts").exists())

    def test_wrong_upstream_ref_denied(self):
        with self.assertRaisesRegex(AuditError, "unreviewed_upstream_sha"):
            apply(self.root, sha="f"*40)

    def test_target_symlink_denied_without_writing_target(self):
        outside = self.root / "outside-secret.ts"
        outside.write_text("SECRET_SENTINEL")
        (self.folder / "hermes-native-read.ts").symlink_to(outside)
        with self.assertRaisesRegex(AuditError, "native_relay_source_symlink"):
            apply(self.root)
        self.assertEqual(outside.read_text(), "SECRET_SENTINEL")

    def test_unreviewed_generic_dispatch_never_modified(self):
        apply(self.root)
        self.assertEqual((self.folder / "invoke.ts").read_text(), "export {};\n")
        self.assertEqual((self.folder / "hermes-policy.ts").read_text(), "export {};\n")
        s = self.server.read_text()
        self.assertIn(CALL, s)
        self.assertIn(NATIVE_CALL, s)

if __name__ == "__main__":
    unittest.main()
