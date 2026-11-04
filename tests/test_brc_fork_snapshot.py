import copy
import datetime as dt
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from control_center.brc_snapshot import MAX_SNAPSHOT_BYTES, SnapshotRejected, read_snapshot
from control_center.brc_source_check import source_check


NOW = dt.datetime(2027, 1, 15, 8, 0, tzinfo=dt.timezone.utc)


def snapshot():
    return {
        "schema": 2, "source": "hermes_brc_fork", "observed_at": NOW.isoformat(),
        "status": "partial", "execution_verified": False, "native_host_access": "not_verified",
        "onboarding_enabled": False,
        "devices": [
            {"name": "Laptop", "status": "online", "last_seen_age_seconds": 1, "command_execution": "not_verified"},
            {"name": "Sandbox", "status": "paused", "last_seen_age_seconds": 3, "command_execution": "not_verified"},
        ],
        "workspaces": [
            {"name": "alpha", "root": "/workspace/projects/alpha", "branch": "main", "device_name": "Laptop", "git_verified": False, "state": "reachable_not_git_verified"},
            {"name": "beta", "root": "/workspace/projects/beta", "branch": "dev", "device_name": "Sandbox", "git_verified": False, "state": "not_ready"},
        ],
    }


class ForkSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "status.json"

    def read(self, value):
        self.path.write_text(json.dumps(value), encoding="utf-8")
        return read_snapshot(self.path, now=NOW)

    def test_current_owner_metadata_and_source_check(self):
        value = snapshot()
        self.assertEqual(self.read(value), value)
        checked = source_check(self.path, now=NOW)
        self.assertEqual(checked["schema"], 2)
        self.assertEqual(checked["verification"]["git"], "not_probed")
        self.assertEqual(checked["verification"]["onboarding"], "disabled")
        self.assertEqual(checked["verification"]["native_host"], "not_probed")

    def test_forged_permissions_unknown_devices_and_secrets_are_rejected(self):
        changes = [
            lambda v: v.update(execution_verified=True),
            lambda v: v["devices"][0].update(deviceId="private"),
            lambda v: v["workspaces"][0].update(device_name="Other"),
            lambda v: v["workspaces"][1].update(state="reachable_not_git_verified"),
            lambda v: v["workspaces"][0].update(root="/etc/secrets"),
            lambda v: v["workspaces"][0].update(branch="../production"),
            lambda v: v["workspaces"][0].update(git_verified=True),
            lambda v: v["devices"][1].update(name="Laptop"),
            lambda v: v.update(status="online"),
            lambda v: v["devices"][0].update(last_seen_age_seconds=301),
            lambda v: v.update(native_host_access=False),
            lambda v: v.update(observed_at="2000-01-01T00:00:00Z"),
        ]
        for change in changes:
            with self.subTest(change=change):
                value = copy.deepcopy(snapshot())
                change(value)
                with self.assertRaises(SnapshotRejected):
                    self.read(value)

    @unittest.skipUnless(os.name == "posix", "requires POSIX symlinks")
    def test_snapshot_replaced_by_symlink_during_read_is_refused(self):
        private = self.path.parent / "private.json"
        secret = snapshot()
        secret["devices"][0]["name"] = "SYNTHETIC_PRIVATE_NAME"
        secret["workspaces"][0]["device_name"] = "SYNTHETIC_PRIVATE_NAME"
        private.write_text(json.dumps(secret), encoding="utf-8")
        original_lstat = Path.lstat
        for nofollow in (getattr(os, "O_NOFOLLOW", 0), 0):
            with self.subTest(nofollow=nofollow):
                self.path.unlink(missing_ok=True)
                self.path.write_text(json.dumps(snapshot()), encoding="utf-8")
                swapped = False

                def swap_after_lstat(path, *args, **kwargs):
                    nonlocal swapped
                    info = original_lstat(path, *args, **kwargs)
                    if path == self.path and not swapped:
                        swapped = True
                        path.unlink()
                        path.symlink_to(private)
                    return info

                with patch.object(os, "O_NOFOLLOW", nofollow, create=True), \
                     patch.object(Path, "lstat", swap_after_lstat):
                    with self.assertRaises(SnapshotRejected):
                        read_snapshot(self.path, now=NOW)
                self.assertTrue(swapped)

    @unittest.skipUnless(os.name == "posix", "requires POSIX hard links")
    def test_hardlinked_snapshot_is_refused(self):
        private = self.path.parent / "private.json"
        private.write_text(json.dumps(snapshot()), encoding="utf-8")
        os.link(private, self.path)
        with self.assertRaises(SnapshotRejected):
            read_snapshot(self.path, now=NOW)

    def test_snapshot_that_grows_after_open_is_refused(self):
        self.path.write_text(json.dumps(snapshot()), encoding="utf-8")
        original_fstat = os.fstat
        grown = False

        def grow_after_fstat(fd):
            nonlocal grown
            info = original_fstat(fd)
            if not grown:
                grown = True
                with self.path.open("ab") as stream:
                    stream.write(b" " * (MAX_SNAPSHOT_BYTES + 1))
            return info

        with patch.object(os, "fstat", grow_after_fstat):
            with self.assertRaises(SnapshotRejected):
                read_snapshot(self.path, now=NOW)
        self.assertTrue(grown)


if __name__ == "__main__":
    unittest.main()
