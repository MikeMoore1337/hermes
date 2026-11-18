"""H454: reject a WSS reconciler race while sidecar-only pins inode changes.

All files are synthetic temporary fixtures. No owner VPS, Docker or secrets.
"""
from __future__ import annotations

import inspect
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from scripts import h454_wss_native_status_sidecar_cutover as operator
from scripts import h454_wss_relay_reconcile as installed


class LegacyReconcilerCoordinationTests(unittest.TestCase):
    def setUp(self):
        self.saved = {
            "old-pins.json": b'{"schema":1,"test":"synthetic"}\n',
            "candidate-proxy.mjs": b"synthetic-status-script",
            "relay-id.txt": ("a" * 64 + "\n").encode("ascii"),
            "sidecar-id.txt": ("b" * 64 + "\n").encode("ascii"),
        }

    def test_installed_reconciler_has_a_prepare_pending_hard_stop(self):
        source = inspect.getsource(installed.reconcile)
        self.assertIn("'prepare.pending'", source)
        self.assertIn("raise Hold('PENDING')", source)

    def test_guard_is_exactly_bound_to_transaction_old_pins_and_cids(self):
        data = json.loads(operator.reconcile_guard_bytes(self.saved))
        self.assertEqual(data["schema"], 1)
        self.assertEqual(data["scope"], "H454-WSS-NATIVE-STATUS-SIDECAR-ONLY")
        self.assertEqual(data["old_pins_sha256"],
                         operator.digest(self.saved["old-pins.json"]))
        self.assertEqual(data["relay_id"], "a" * 64)
        self.assertEqual(data["old_sidecar_id"], "b" * 64)
        self.assertEqual(data["candidate_proxy_sha256"],
                         operator.digest(self.saved["candidate-proxy.mjs"]))
        other = dict(self.saved, **{"old-pins.json": b"foreign-pins"})
        self.assertNotEqual(operator.reconcile_guard_bytes(self.saved),
                            operator.reconcile_guard_bytes(other))

    def fixture(self):
        directory = TemporaryDirectory(prefix="h454-prepare-pending-test-")
        marker = Path(directory.name) / "prepare.pending"
        def check(path, *, mode, limit=100000):
            self.assertEqual(mode, 0o600)
            self.assertEqual(path, marker)
            return path.read_bytes()
        def write_once(path, data):
            self.assertEqual(path, marker)
            with path.open("xb") as stream:
                stream.write(data)
        return directory, marker, check, write_once

    def test_guard_creation_and_release_under_same_exact_saved_identity(self):
        scratch, marker, checked, write_once = self.fixture()
        with scratch, patch.object(operator, "RECONCILER_MARKER", marker), \
             patch.object(operator, "checked_file", side_effect=checked), \
             patch.object(operator.stage1, "write_once", side_effect=write_once), \
             patch.object(operator.stage1, "sync_pin_directory") as sync:
            operator.acquire_reconcile_guard(self.saved)
            self.assertTrue(marker.is_file())
            self.assertEqual(marker.read_bytes(),
                             operator.reconcile_guard_bytes(self.saved))
            operator.release_reconcile_guard(self.saved)
            self.assertFalse(marker.exists())
            self.assertEqual(sync.call_count, 2)

    def test_cutover_refuses_to_adopt_preexisting_valid_guard(self):
        scratch, marker, checked, write_once = self.fixture()
        with scratch, patch.object(operator, "RECONCILER_MARKER", marker), \
             patch.object(operator, "checked_file", side_effect=checked), \
             patch.object(operator.stage1, "write_once", side_effect=write_once), \
             patch.object(operator.stage1, "sync_pin_directory"):
            marker.write_bytes(operator.reconcile_guard_bytes(self.saved))
            with self.assertRaisesRegex(operator.Refused,
                                        "FOREIGN_WSS_PREPARE_MARKER"):
                operator.acquire_reconcile_guard(self.saved)
            self.assertTrue(marker.exists())

    def test_owner_recovery_can_accept_only_the_original_matching_guard(self):
        scratch, marker, checked, write_once = self.fixture()
        with scratch, patch.object(operator, "RECONCILER_MARKER", marker), \
             patch.object(operator, "checked_file", side_effect=checked), \
             patch.object(operator.stage1, "write_once", side_effect=write_once) as create, \
             patch.object(operator.stage1, "sync_pin_directory"):
            marker.write_bytes(operator.reconcile_guard_bytes(self.saved))
            operator.acquire_reconcile_guard(self.saved, existing_ok=True)
            create.assert_not_called()
            marker.write_bytes(b"foreign-owner-proxy-transaction")
            with self.assertRaisesRegex(operator.Refused,
                                        "FOREIGN_WSS_PREPARE_MARKER"):
                operator.acquire_reconcile_guard(self.saved, existing_ok=True)
            with self.assertRaisesRegex(operator.Refused,
                                        "FOREIGN_WSS_PREPARE_MARKER"):
                operator.release_reconcile_guard(self.saved)
            self.assertTrue(marker.exists())

    def test_foreign_or_dangling_symlink_guard_denied_without_following(self):
        scratch, marker, checked, write_once = self.fixture()
        with scratch, patch.object(operator, "RECONCILER_MARKER", marker), \
             patch.object(operator, "checked_file", side_effect=checked), \
             patch.object(operator.stage1, "write_once", side_effect=write_once), \
             patch.object(operator.stage1, "sync_pin_directory"):
            marker.symlink_to("missing-foreign-file")
            with self.assertRaises(operator.Refused):
                operator.acquire_reconcile_guard(self.saved)
            self.assertTrue(marker.is_symlink())

    def test_readback_failure_leaves_marker_for_operator_recovery(self):
        scratch, marker, checked, write_once = self.fixture()
        with scratch, patch.object(operator, "RECONCILER_MARKER", marker), \
             patch.object(operator, "checked_file", return_value=b"unexpected-bytes"), \
             patch.object(operator.stage1, "write_once", side_effect=write_once), \
             patch.object(operator.stage1, "sync_pin_directory"):
            with self.assertRaisesRegex(operator.Refused,
                                        "WSS_PREPARE_READBACK_FAILED"):
                operator.acquire_reconcile_guard(self.saved)
            self.assertTrue(marker.exists())


if __name__ == "__main__":
    unittest.main()
