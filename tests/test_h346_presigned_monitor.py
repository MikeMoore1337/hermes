"""Hermes #346 finite CA batch runway: strictly public, read-only Ops Watch."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from ops_watch import device_fabric_alerts as alerts
from ops_watch.core import analyze
from ops_watch.incident_preview import ACTIONS, TITLES
from ops_watch.advisor_adapter import CODE_MAPPING


class FiniteCaBatchMonitorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.material = tempfile.TemporaryDirectory()
        cls.ca = Path(cls.material.name) / "synthetic-ca.pem"
        key = Path(cls.material.name) / "synthetic-ca.key"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-days", "450", "-keyout", str(key), "-out", str(cls.ca),
            "-subj", "/CN=Synthetic H346 CA",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        ], capture_output=True, timeout=18, check=True)
        cls.ca_pin = hashlib.sha256(
            ssl.PEM_cert_to_DER_cert(cls.ca.read_text())).hexdigest()

    @classmethod
    def tearDownClass(cls):
        cls.material.cleanup()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.tls = self.base / "tls"
        self.tls.mkdir(mode=0o750)
        self.tls.chmod(0o750)
        self.archive = self.tls / "presigned-batch"
        self.archive.mkdir(mode=0o700)
        self.archive.chmod(0o700)
        self.ca_path = self.tls / "ca-public.pem"
        self.ca_path.write_bytes(self.ca.read_bytes())
        self.ca_path.chmod(0o640)
        self.consent = self.base / "tls-only.json"
        self.consent.write_text(json.dumps({
            "schema": 1, "purpose": "tls-expiry",
            "enabled_at": "2026-10-25T00:00:00+00:00",
        }))
        self.consent.chmod(0o600)
        self.base.chmod(0o700)
        self.start = datetime.now(UTC).replace(microsecond=0) - timedelta(days=1)
        self.last_end = self.start + timedelta(days=355)
        self.slots = [{
            "slot": name,
            "der_sha256": f"{i+1:064x}",
            "not_before": (self.start + timedelta(days=25 * i)).isoformat(),
            "not_after": (self.start + timedelta(days=25 * i + 30)).isoformat(),
        } for i, name in enumerate(alerts.BATCH_SLOTS)]
        self.manifest = self.archive / "manifest.json"
        self.write_manifest()
        self.pin = patch.object(alerts, "BATCH_CA_SHA256", self.ca_pin)
        self.opt = patch.object(alerts, "TLS_OPT_IN", self.consent)
        self.pin.start()
        self.opt.start()
        self.addCleanup(self.opt.stop)
        self.addCleanup(self.pin.stop)

    def write_manifest(self):
        self.manifest.write_text(json.dumps({
            "schema": "hermes-h346-presigned-batch-v1",
            "ca_der_sha256": self.ca_pin,
            "slots": self.slots,
        }))
        self.manifest.chmod(0o600)

    def status(self, when=None):
        return alerts.presigned_batch_status(
            root=self.tls, now=when or datetime.now(UTC))

    def test_healthy_issuance_runway_initially(self):
        self.assertEqual(self.status(), "healthy")

    def test_90_day_warning_exact_boundary(self):
        self.assertEqual(self.status(self.last_end - timedelta(days=90)), "renewal_due")
        self.assertEqual(self.status(self.last_end - timedelta(days=91)), "healthy")

    def test_30_day_critical_exact_boundary(self):
        self.assertEqual(self.status(self.last_end - timedelta(days=30)), "renewal_critical")
        self.assertEqual(self.status(self.last_end - timedelta(days=31)), "renewal_due")

    def test_end_of_signed_batch_is_not_safe(self):
        self.assertEqual(self.status(self.last_end), "expired")
        self.assertEqual(self.status(self.last_end + timedelta(days=1)), "expired")

    def test_absent_tls_only_owner_opt_in_fails_quietly(self):
        self.consent.unlink()
        self.assertEqual(self.status(), "not_configured")

    def test_corrupt_tls_only_opt_in_is_not_healthy(self):
        self.consent.write_text('{"purpose":"untrusted"}')
        self.assertEqual(self.status(), "unknown")

    def test_missing_archive_is_not_reported_healthy(self):
        self.archive.rename(self.tls / "saved-archive")
        self.assertEqual(self.status(), "not_configured")

    def test_untrusted_manifest_symlink_is_unknown(self):
        saved = self.archive / "saved.json"
        self.manifest.rename(saved)
        self.manifest.symlink_to(saved.name)
        self.assertEqual(self.status(), "unknown")

    def test_untrusted_manifest_mode_is_unknown(self):
        self.manifest.chmod(0o644)
        self.assertEqual(self.status(), "unknown")

    def test_fake_ca_pin_is_unknown(self):
        with patch.object(alerts, "BATCH_CA_SHA256", "0" * 64):
            self.assertEqual(self.status(), "unknown")

    def test_corrupt_public_pem_is_unknown_not_exception(self):
        self.ca_path.write_text(
            "-----BEGIN CERTIFICATE-----\n@@@invalid@@@\n-----END CERTIFICATE-----\n")
        self.assertEqual(self.status(), "unknown")

    def test_invalid_future_start_spacing_is_unknown(self):
        self.slots[8]["not_before"] = (
            self.start + timedelta(days=203)).isoformat()
        self.write_manifest()
        self.assertEqual(self.status(), "unknown")

    def test_inconsistent_leaf_validity_is_unknown(self):
        self.slots[-1]["not_after"] = (
            self.last_end + timedelta(days=1)).isoformat()
        self.write_manifest()
        self.assertEqual(self.status(), "unknown")

    def test_rejects_manifest_hardlink(self):
        os.link(self.manifest, self.archive / "other.json")
        self.assertEqual(self.status(), "unknown")

    def test_never_reads_presigned_private_keys(self):
        secret = self.archive / "future-13.key"
        secret.write_text("TEST_ONLY_CANNOT_BE_READ")
        secret.chmod(0o000)
        self.assertEqual(self.status(), "healthy")

    def test_incident_severity_and_fixed_catalogs(self):
        codes = {
            "renewal_due": ("device_ca_batch_renewal_due", "warning"),
            "renewal_critical": ("device_ca_batch_renewal_critical", "critical"),
            "expired": ("device_ca_batch_expired", "critical"),
        }
        for status, (code, severity) in codes.items():
            with self.subTest(status=status):
                now = datetime.now(UTC)
                snapshot = {
                    "schema": "hermes-ops-snapshot-v1",
                    "observed_at": now.isoformat(),
                    "news": {
                        "timer_enabled": True, "timer_active": True,
                        "last_successful_discovery_at": now.isoformat(),
                        "consecutive_discovery_failures": 0,
                        "consecutive_drain_failures": 0, "pending_jobs": 0,
                        "oldest_pending_age_seconds": 0,
                        "recent_provider_rate_limits": 0,
                    },
                    "device_ca_batch": status,
                }
                actual = analyze(snapshot, now=now)
                self.assertEqual(
                    [(f["code"], f["severity"]) for f in actual],
                    [(code, severity)])
                self.assertIn(code, TITLES)
                self.assertIn(code, ACTIONS)
                self.assertIn(code, CODE_MAPPING)

    def test_missing_monitor_source_is_not_renewal_incident(self):
        now = datetime.now(UTC)
        snapshot = {
            "schema": "hermes-ops-snapshot-v1", "observed_at": now.isoformat(),
            "news": {
                "timer_enabled": True, "timer_active": True,
                "last_successful_discovery_at": now.isoformat(),
                "consecutive_discovery_failures": 0,
                "consecutive_drain_failures": 0,
                "pending_jobs": 0, "oldest_pending_age_seconds": 0,
                "recent_provider_rate_limits": 0,
            },
            "device_ca_batch": "not_configured",
        }
        self.assertEqual(analyze(snapshot, now=now), [])


if __name__ == "__main__":
    unittest.main()
