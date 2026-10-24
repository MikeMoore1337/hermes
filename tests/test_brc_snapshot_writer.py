"""#455 fail-closed, atomic sanitized observer writer — synthetic inputs only."""
from __future__ import annotations

import copy
import datetime as dt
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from control_center.brc_snapshot import SnapshotRejected, read_snapshot
from control_center.brc_snapshot_writer import publish_snapshot
from tests.test_brc_snapshot import NOW, fixtures


class SnapshotWriterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.parent = Path(self.temp.name) / "observer"
        self.parent.mkdir(mode=0o700)
        self.path = self.parent / "status.json"
        self.owner_uid = self.parent.stat().st_uid
        self.uid_patch = patch("control_center.brc_snapshot_writer.os.geteuid",
                               return_value=self.owner_uid if self.owner_uid != 0 else 1001)
        self.uid_patch.start()
        self.addCleanup(self.uid_patch.stop)
        if self.owner_uid == 0:
            # In rare root-runner tests, simulate a service-owned directory.
            self.uid_patch.stop()
            self.uid_patch = patch("control_center.brc_snapshot_writer.os.geteuid",
                                   return_value=1001)
            self.uid_patch.start()
            with patch("control_center.brc_snapshot_writer.Path.lstat") as fake:
                # Root-runner file identity differs from the simulated user:
                # rely on ordinary Actions non-root runner for filesystem tests.
                pass
            self.skipTest("filesystem ownership acceptance requires non-root runner")

    def tearDown(self):
        self.temp.cleanup()

    def test_atomic_write_round_trip_no_credentials(self):
        dev, cat = fixtures()
        dev["devices"][0]["access_token"] = "TOKEN_NEVER_PUBLISH"
        dev["devices"].append({
            "name": "H15 Windows native read-only",
            "deviceId": "h454-win-01335a1f6e6705b4",
            "platform": "win32", "online": False, "paused": True,
            "lastSeen": NOW - 2000, "token_hash": "SECRET_HASH",
        })
        output = publish_snapshot(dev, cat, path=self.path, now_ms=NOW)
        current = read_snapshot(
            self.path, now=dt.datetime.fromtimestamp(NOW / 1000, dt.timezone.utc)
        )
        self.assertEqual(current, output)
        self.assertEqual(len(output["devices"]), 3)
        self.assertFalse(output["native_host_access"])
        stored = self.path.read_text()
        self.assertNotIn("TOKEN_NEVER_PUBLISH", stored)
        self.assertNotIn("SECRET_HASH", stored)
        self.assertNotIn("h454-win-", stored)
        self.assertNotIn("deviceId", stored)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o640)
        self.assertEqual(list(self.parent.glob(".brc-snapshot-*")), [])

    def test_bad_input_never_replaces_valid_snapshot(self):
        dev, cat = fixtures()
        publish_snapshot(dev, cat, path=self.path, now_ms=NOW)
        before = self.path.read_bytes()
        corrupted = copy.deepcopy(cat)
        corrupted["workspaces"][0]["root"] = "/host-private"
        with self.assertRaises(SnapshotRejected):
            publish_snapshot(dev, corrupted, path=self.path, now_ms=NOW)
        self.assertEqual(self.path.read_bytes(), before)

    def test_existing_symlink_must_not_be_followed_or_replaced(self):
        dev, cat = fixtures()
        marker = self.parent / "private.txt"
        marker.write_text("protected")
        self.path.symlink_to(marker)
        with self.assertRaisesRegex(SnapshotRejected, "untrusted_existing_snapshot"):
            publish_snapshot(dev, cat, path=self.path, now_ms=NOW)
        self.assertEqual(marker.read_text(), "protected")
        self.assertTrue(self.path.is_symlink())

    def test_world_writable_parent_denied(self):
        dev, cat = fixtures()
        self.parent.chmod(0o777)
        with self.assertRaisesRegex(SnapshotRejected, "untrusted_snapshot_directory"):
            publish_snapshot(dev, cat, path=self.path, now_ms=NOW)
        self.assertFalse(self.path.exists())

    def test_missing_parent_refused_without_creation(self):
        dev, cat = fixtures()
        missing = self.parent / "missing" / "status.json"
        with self.assertRaises(SnapshotRejected):
            publish_snapshot(dev, cat, path=missing, now_ms=NOW)
        self.assertFalse(missing.parent.exists())

    def test_noncanonical_filename_and_root_execution_denied(self):
        dev, cat = fixtures()
        with self.assertRaisesRegex(SnapshotRejected, "unexpected_snapshot_name"):
            publish_snapshot(dev, cat, path=self.parent / "other.json", now_ms=NOW)
        with patch("control_center.brc_snapshot_writer.os.geteuid", return_value=0):
            with self.assertRaisesRegex(SnapshotRejected, "nonroot_publisher_required"):
                publish_snapshot(dev, cat, path=self.path, now_ms=NOW)


if __name__ == "__main__":
    unittest.main()
