"""H454: patch BRC owner-current status endpoint on synthetic upstream only."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.h454_native_brc_status_patch import apply, ROUTE, ANCHOR
from scripts.h15_remote_commander_candidate_audit import AuditError

SOURCE = ("  // synthetic previously hardened relay\n"
          "const hermesAuthTokenHash = 'test';\n"
          "native_pairing_scope_denied\n"
          + ANCHOR + " more source;\n")


class NativeStatusPatcherTests(unittest.TestCase):
    def setUp(self):
        folder=tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.repo=Path(folder.name)
        self.path=self.repo/"packages/relay/src/app.ts"
        self.path.parent.mkdir(parents=True)
        self.path.write_text(SOURCE)
        p=patch("scripts.h454_native_brc_status_patch.evaluate")
        p.start()
        self.addCleanup(p.stop)

    def test_adds_owner_checked_live_bearer_status_and_no_new_mcp(self):
        result=apply(self.repo)
        self.assertFalse(result["live_relay_modified"])
        data=self.path.read_text()
        self.assertEqual(data.count(ROUTE),1)
        self.assertLess(data.index(ROUTE),data.index(ANCHOR))
        for token in ("store.getDeviceByToken", "row.paused === 0",
                      "row.user_id === owner.id", "cfg.adminUser",
                      "native_device_denied", "/device/native-status",
                      "Cache-Control", "owner_bound:true"):
            self.assertIn(token,data)
        self.assertNotIn("start_process",ROUTE)
        self.assertNotIn("write_file",ROUTE)

    def test_drift_symlink_and_reapplication_refused_without_source_damage(self):
        apply(self.repo)
        after=self.path.read_bytes()
        with self.assertRaises(AuditError):apply(self.repo)
        self.assertEqual(self.path.read_bytes(),after)
        self.path.write_text(SOURCE.replace(ANCHOR,"FORKED_CALL()"))
        before=self.path.read_bytes()
        with self.assertRaises(AuditError):apply(self.repo)
        self.assertEqual(self.path.read_bytes(),before)
        self.path.unlink()
        foreign=self.repo/"foreign"
        foreign.write_text(SOURCE)
        self.path.symlink_to(foreign)
        with self.assertRaises(AuditError):apply(self.repo)
        self.assertEqual(foreign.read_text(),SOURCE)


if __name__=="__main__":
    unittest.main()
