"""#455: credential-free local observer bridge test — disposable filesystem only."""
from __future__ import annotations
import datetime as dt
import json
import os
from pathlib import Path
import tempfile
import unittest

from control_center.brc_snapshot import SnapshotRejected, normalize, read_snapshot
from control_center.brc_snapshot_bridge import bridge_once
from tests.test_brc_snapshot import NOW, fixtures


class BrcSnapshotBridgeTests(unittest.TestCase):
    def setUp(self):
        if os.geteuid() == 0:
            self.skipTest("nonroot service-identity filesystem acceptance")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        parent = Path(self.tmp.name)
        self.state = parent / "state"
        self.state.mkdir(mode=0o700)
        self.outdir = parent / "out"
        self.outdir.mkdir(mode=0o750)
        self.source = self.state / "hermes-brc-observation.json"
        self.marker = self.state / ".hermes-brc-observer-enable"
        self.target = self.outdir / "status.json"
        self.marker.write_bytes(b"enabled\n")
        self.marker.chmod(0o600)
        dev, catalog = fixtures()
        dev["devices"].append({
            "name": "H15 Windows native read-only",
            "deviceId": "h454-win-01335a1f6e6705b4",
            "platform": "win32", "paused": True, "online": False,
            "lastSeen": NOW - 2000, "token_hash": "DO_NOT_PUBLISH",
        })
        self.good = normalize(dev, catalog, now_ms=NOW)
        self.source.write_text(json.dumps(self.good))
        self.source.chmod(0o640)
        self.now = dt.datetime.fromtimestamp(NOW/1000, dt.timezone.utc)

    def invoke(self):
        return bridge_once(source=self.source, marker=self.marker,
                           target=self.target, shared_gid=os.getegid(),
                           now=self.now)

    def test_round_trip_no_sensitive_content_and_permissions(self):
        result = self.invoke()
        self.assertEqual(result["status"], "PUBLISHED")
        self.assertEqual((result["devices"], result["workspaces"]), (3, 4))
        self.assertEqual(read_snapshot(self.target, now=self.now), self.good)
        body = self.target.read_text()
        self.assertNotIn("DO_NOT_PUBLISH", body)
        self.assertNotIn("h454-win-", body)
        self.assertNotIn("deviceId", body)
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o640)
        self.assertEqual(list(self.outdir.glob(".brc-status-*")), [])

    def test_missing_or_bad_opt_in_refuses_without_old_snapshot_replacement(self):
        self.invoke()
        old = self.target.read_bytes()
        for value in (b"disabled\n", b"enabled", b"enabled\nmalicious"):
            with self.subTest(value=value):
                self.marker.write_bytes(value)
                with self.assertRaises(SnapshotRejected):
                    self.invoke()
                self.assertEqual(self.target.read_bytes(), old)
        self.marker.unlink()
        with self.assertRaises(SnapshotRejected):
            self.invoke()

    def test_stale_and_forged_payload_are_denied(self):
        self.invoke()
        baseline = self.target.read_bytes()
        with self.assertRaises(SnapshotRejected):
            bridge_once(source=self.source, marker=self.marker, target=self.target,
                        shared_gid=os.getegid(), now=self.now+dt.timedelta(minutes=8))
        forged = dict(self.good, execution_verified=True)
        self.source.write_text(json.dumps(forged))
        self.source.chmod(0o640)
        with self.assertRaises(SnapshotRejected):
            self.invoke()
        self.assertEqual(self.target.read_bytes(), baseline)

    def test_source_and_target_symlink_refused(self):
        other = self.state / "private"
        other.write_text("SECRET")
        self.source.unlink()
        self.source.symlink_to(other)
        with self.assertRaises(SnapshotRejected):
            self.invoke()
        self.assertEqual(other.read_text(), "SECRET")
        self.source.unlink()
        self.source.write_text(json.dumps(self.good))
        self.source.chmod(0o640)
        self.target.symlink_to(other)
        with self.assertRaises(SnapshotRejected):
            self.invoke()
        self.assertEqual(other.read_text(), "SECRET")

    def test_world_writable_directory_refused(self):
        self.outdir.chmod(0o777)
        with self.assertRaisesRegex(SnapshotRejected, "observer_directory_untrusted"):
            self.invoke()
        self.assertFalse(self.target.exists())

    def test_root_rejected_and_does_not_create_destination(self):
        from unittest.mock import patch
        with patch("control_center.brc_snapshot_bridge.os.geteuid", return_value=0):
            with self.assertRaisesRegex(SnapshotRejected, "observer_root_forbidden"):
                self.invoke()
        self.assertFalse(self.target.exists())


if __name__ == "__main__":
    unittest.main()
