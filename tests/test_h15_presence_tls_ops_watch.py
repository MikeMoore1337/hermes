"""Expiry alerts follow the approved active TLS certificate, not stale pilot bytes."""
from __future__ import annotations

from datetime import UTC, datetime
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from ops_watch import device_fabric_alerts as alerts


class RotatedCertificateAlertTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.legacy = root / "cert.pem"
        self.legacy.write_text("synthetic old cert", encoding="utf-8")
        self.rotated = root / "active" / "cert.pem"
        self.gate = root / "opt.json"
        self.gate.write_text(json.dumps({
            "schema": 1, "devices": ["windows-pc", "linux-vps"],
            "enabled_at": "2026-10-20T00:00:00+00:00",
        }), encoding="utf-8")
        self.now = datetime(2026, 10, 20, 12, tzinfo=UTC)

    def sample(self, expiry):
        return subprocess.CompletedProcess(["openssl"], 0,
            stdout="notAfter=" + expiry + "\n", stderr="")

    def test_legacy_mode_preserved_before_activation(self):
        with patch.object(alerts, "CERT", self.legacy), \
             patch.object(alerts, "ROTATED_CERT", self.rotated), \
             patch.object(alerts.subprocess, "run", return_value=self.sample("Oct 29 12:00:00 2026 GMT")) as run:
            self.assertEqual(alerts.certificate_status(self.legacy, self.gate, now=self.now), "healthy")
            self.assertIn(str(self.legacy), run.call_args.args[0])

    def test_expiry_alert_observes_rotated_leaf(self):
        leaf = "leaf-" + "a" * 32
        directory = self.legacy.parent / "generations" / leaf
        directory.mkdir(parents=True)
        (directory / "cert.pem").write_text("new cert", encoding="utf-8")
        (self.legacy.parent / "active").symlink_to("generations/" + leaf)
        with patch.object(alerts, "CERT", self.legacy), \
             patch.object(alerts, "ROTATED_CERT", self.rotated), \
             patch.object(alerts.subprocess, "run", return_value=self.sample("Oct 21 12:00:00 2026 GMT")) as run:
            self.assertEqual(alerts.certificate_status(self.legacy, self.gate, now=self.now), "expiring")
            self.assertIn(str(self.rotated), run.call_args.args[0])

    def test_forged_active_pointer_is_unknown(self):
        (self.legacy.parent / "active").symlink_to("/tmp/forged")
        with patch.object(alerts, "CERT", self.legacy), \
             patch.object(alerts, "ROTATED_CERT", self.rotated), \
             patch.object(alerts.subprocess, "run") as run:
            self.assertEqual(alerts.certificate_status(self.legacy, self.gate, now=self.now), "unknown")
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
