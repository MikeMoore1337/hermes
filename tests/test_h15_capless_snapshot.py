"""Regression for #295: provider snapshots under a CAP_CHOWN-free systemd sandbox.

No network, credentials, model inference or production filesystem writes.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from datetime import datetime, timedelta, timezone

from control_center import cloudflare_billing as cf
from control_center import github_rate_limit as gh
from control_center import github_rate_history as history


ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 18, 17, tzinfo=timezone.utc)


class CaplessProviderStateTests(unittest.TestCase):
    def github_sample(self):
        return gh.parse(json.dumps({"resources": {
            "core": {"limit": 5000, "used": 1, "remaining": 4999,
                     "reset": int((NOW + timedelta(hours=1)).timestamp())}
        }}).encode(), now=NOW)

    def test_units_delegate_group_to_systemd_without_capabilities(self):
        for unit in ("hermes-github-rate-limit", "hermes-cloudflare-billing-read"):
            with self.subTest(unit=unit):
                raw = (ROOT / "deploy" / f"{unit}.service").read_text()
                self.assertIn("\nUser=root\n", raw)
                self.assertIn("\nGroup=hermes-control\n", raw)
                self.assertIn("\nStateDirectory=hermes-provider-quota\n", raw)
                self.assertIn("\nStateDirectoryMode=0750\n", raw)
                self.assertIn("\nCapabilityBoundingSet=\n", raw)
                self.assertIn("\nNoNewPrivileges=true\n", raw)

    def test_snapshots_and_history_write_without_any_chown(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o750)
            github_path = root / "github.json"
            billing_path = root / "billing.json"
            history_path = root / "history.sqlite3"
            owner_group = SimpleNamespace(gr_gid=os.getegid())
            with patch("grp.getgrnam", return_value=owner_group), \
                 patch.object(os, "chown", side_effect=AssertionError("CAP_CHOWN forbidden")):
                gh.save(self.github_sample(), github_path, group="hermes-control")
                cf.save(cf.error("unknown", NOW), billing_path, group="hermes-control")
                history.append(self.github_sample(), history_path, group="hermes-control")
            for path in (github_path, billing_path, history_path):
                with self.subTest(path=path.name):
                    info = path.stat()
                    self.assertEqual(info.st_uid, os.geteuid())
                    self.assertEqual(info.st_gid, os.getegid())
                    self.assertEqual(info.st_mode & 0o777, 0o640)
            self.assertEqual(gh.snapshot(github_path, now=NOW)["status"], "ok")
            self.assertEqual(len(history.read(history_path, resource="core", now=NOW)["points"]), 1)

    def test_untrusted_directory_fails_closed_without_writing_snapshot(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            # Uncontrolled directory permissions must not be silently chmod/chowned.
            root.chmod(0o700)
            owner_group = SimpleNamespace(gr_gid=os.getegid())
            with patch("grp.getgrnam", return_value=owner_group), \
                 patch.object(os, "chown", side_effect=AssertionError("CAP_CHOWN forbidden")):
                with self.assertRaises(gh.GitHubQuotaError):
                    gh.save(self.github_sample(), root / "github.json", group="hermes-control")
                with self.assertRaises(cf.BillingError):
                    cf.save(cf.error("unknown", NOW), root / "billing.json", group="hermes-control")
            self.assertFalse((root / "github.json").exists())
            self.assertFalse((root / "billing.json").exists())

    def test_mismatched_primary_group_is_denied(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o750)
            other_gid = os.getegid() + 1
            with patch("grp.getgrnam", return_value=SimpleNamespace(gr_gid=other_gid)):
                with self.assertRaises(gh.GitHubQuotaError):
                    gh.save(self.github_sample(), root / "github.json", group="hermes-control")
                with self.assertRaises(cf.BillingError):
                    cf.save(cf.error("unknown", NOW), root / "billing.json", group="hermes-control")


if __name__ == "__main__":
    unittest.main()
