"""Expiry alerts follow the approved active TLS certificate, not stale pilot bytes."""
from __future__ import annotations

from datetime import UTC, datetime
import json
import os
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
        # Production may have a TLS-only consent marker enabled. Synthetic
        # tests must resolve only their own explicit fixture, never /etc.
        self.missing_tls_only = root / "tls-only-absent.json"
        tls_patch = patch.object(alerts, "TLS_OPT_IN", self.missing_tls_only)
        tls_patch.start()
        self.addCleanup(tls_patch.stop)

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

    def test_tls_only_gate_reports_expired_without_enabling_device_monitoring(self):
        from unittest.mock import patch
        tls_gate = self.legacy.parent / "tls-opt.json"
        tls_gate.write_text(json.dumps({
            "schema": 1, "purpose": "tls-expiry",
            "enabled_at": "2026-10-20T00:00:00+00:00",
        }), encoding="utf-8")
        os.chmod(tls_gate, 0o600)
        self.gate.unlink()
        with patch.object(alerts, "TLS_OPT_IN", tls_gate), \
             patch.object(alerts.subprocess, "run",
                          return_value=self.sample("Oct 19 12:00:00 2026 GMT")):
            self.assertEqual(alerts.certificate_status(
                self.legacy, self.gate, now=self.now), "expired")
            observed = alerts.observe(self.legacy.parent / "absent-db", self.gate,
                                      now=self.now)
            self.assertEqual(
                [item["status"] for item in observed.values()],
                ["not_configured", "not_configured"])
            from ops_watch.core import analyze
            from datetime import UTC
            snap = {
                "schema": "hermes-ops-snapshot-v1",
                "observed_at": self.now.isoformat(),
                "news": {
                    "timer_enabled": True, "timer_active": True,
                    "last_successful_discovery_at": self.now.isoformat(),
                    "consecutive_discovery_failures": 0,
                    "consecutive_drain_failures": 0, "pending_jobs": 0,
                    "oldest_pending_age_seconds": 0,
                    "recent_provider_rate_limits": 0,
                },
                "device_fabric": observed,
                "device_fabric_tls": "expired",
            }
            findings = {f["code"] for f in analyze(snap, now=self.now)}
            self.assertEqual(findings, {"device_tls_expired"})

    def test_malformed_tls_gate_does_not_fall_back_to_presence_consent(self):
        tls_gate = self.legacy.parent / "tls-opt.json"
        tls_gate.write_text('{"schema":1,"purpose":"untrusted"}', encoding="utf-8")
        os.chmod(tls_gate, 0o600)
        with patch.object(alerts, "TLS_OPT_IN", tls_gate), \
             patch.object(alerts.subprocess, "run") as run:
            self.assertEqual(alerts.certificate_status(
                self.legacy, self.gate, now=self.now), "unknown")
            run.assert_not_called()

    def test_tls_gate_symlink_fails_closed(self):
        tls_gate = self.legacy.parent / "tls-opt.json"
        tls_gate.symlink_to(self.gate)
        with patch.object(alerts, "TLS_OPT_IN", tls_gate), \
             patch.object(alerts.subprocess, "run") as run:
            self.assertEqual(alerts.certificate_status(
                self.legacy, self.gate, now=self.now), "unknown")
            run.assert_not_called()

    def test_tls_only_future_consent_fails_closed(self):
        tls_gate = self.legacy.parent / "tls-opt.json"
        tls_gate.write_text(json.dumps({
            "schema": 1, "purpose": "tls-expiry",
            "enabled_at": "2026-10-25T00:00:00+00:00",
        }), encoding="utf-8")
        os.chmod(tls_gate, 0o600)
        with patch.object(alerts, "TLS_OPT_IN", tls_gate), \
             patch.object(alerts.subprocess, "run") as run:
            self.assertEqual(alerts.certificate_status(
                self.legacy, self.gate, now=self.now), "unknown")
            run.assert_not_called()

    def test_tls_only_gate_requires_private_permissions(self):
        tls_gate = self.legacy.parent / "tls-opt.json"
        tls_gate.write_text(json.dumps({
            "schema": 1, "purpose": "tls-expiry",
            "enabled_at": "2026-10-20T00:00:00+00:00",
        }), encoding="utf-8")
        os.chmod(tls_gate, 0o644)
        with patch.object(alerts, "TLS_OPT_IN", tls_gate), \
             patch.object(alerts.subprocess, "run") as run:
            self.assertEqual(alerts.certificate_status(
                self.legacy, self.gate, now=self.now), "unknown")
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
