"""H-453 free-account local attestation regression, no secrets or network."""
from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import os
import stat
import unittest
from unittest.mock import patch

from agent_budget.pilot import load_account_status, PilotError
from scripts import h453_account_preflight as preflight
from scripts.cloudflare_text_probe import ProbeError

ENDPOINT = "https://api.cloudflare.com/client/v4/accounts/" + ("b" * 32) + "/ai/v1"
FAKE_TOKEN = "a" * 32


class OwnerAccountPreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory(prefix="h453-account-preflight-")
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name) / "private" / "account-status.json"

    def prepare(self, **kwargs):
        defaults = dict(remaining=10000, workers_free=True, no_gateways=True,
                        output=self.output, write=True)
        defaults.update(kwargs)
        with patch.object(preflight, "read_env", return_value=(FAKE_TOKEN, ENDPOINT)) as env:
            outcome = preflight.prepare(**defaults)
            env.assert_called_once()
            return outcome

    def test_valid_private_status_and_bind_account(self):
        result = self.prepare()
        self.assertEqual(result["status"], "OWNER_ACCOUNT_STATUS_READY")
        status = load_account_status(self.output)
        self.assertEqual(status["plan"], "WORKERS_FREE")
        self.assertEqual(status["daily_neurons_remaining"], 10000)
        self.assertEqual(status["ai_gateway_unified_billing"], False)
        self.assertEqual(len(status["account_id_sha256"]), 64)
        self.assertNotIn("b" * 32, self.output.read_text())
        self.assertNotIn(FAKE_TOKEN, self.output.read_text())
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.output.parent.stat().st_mode), 0o700)

    def test_default_dry_run_never_creates_status(self):
        result = self.prepare(write=False)
        self.assertEqual(result["status"], "PREFLIGHT_PASS")
        self.assertFalse(self.output.exists())

    def test_owner_free_confirmation_required(self):
        with self.assertRaisesRegex(PilotError, "owner_dashboard_confirmation_required"):
            self.prepare(workers_free=False)
        self.assertFalse(self.output.exists())

    def test_owner_gateway_confirmation_required(self):
        with self.assertRaisesRegex(PilotError, "owner_dashboard_confirmation_required"):
            self.prepare(no_gateways=False)
        self.assertFalse(self.output.exists())

    def test_quota_below_safe_reserve_denied(self):
        with self.assertRaisesRegex(PilotError, "account_quota_reserve_not_available"):
            self.prepare(remaining=999)
        self.assertFalse(self.output.exists())

    def test_out_of_range_quota_denied(self):
        with self.assertRaisesRegex(PilotError, "account_quota_invalid"):
            self.prepare(remaining=10001)
        self.assertFalse(self.output.exists())

    def test_existing_private_record_is_not_overwritten(self):
        self.output.parent.mkdir(mode=0o700, parents=True)
        self.output.write_text("old-evidence", encoding="utf-8")
        with self.assertRaisesRegex(PilotError, "preflight_output_exists"):
            self.prepare()
        self.assertEqual(self.output.read_text(), "old-evidence")

    def test_symlink_output_denied(self):
        target = Path(self.temp.name) / "target"
        target.write_text("protected", encoding="utf-8")
        self.output.parent.mkdir(mode=0o700)
        self.output.symlink_to(target)
        with self.assertRaisesRegex(PilotError, "preflight_output_exists"):
            self.prepare()
        self.assertEqual(target.read_text(), "protected")

    def test_unsafe_parent_denied(self):
        self.output.parent.mkdir(mode=0o755)
        with self.assertRaisesRegex(PilotError, "preflight_unsafe_directory"):
            self.prepare()
        self.assertFalse(self.output.exists())

    def test_no_credentials_fails_closed(self):
        with patch.object(preflight, "read_env", side_effect=ProbeError("credentials_missing")):
            with self.assertRaisesRegex(ProbeError, "credentials_missing"):
                preflight.prepare(remaining=10000, workers_free=True,
                                  no_gateways=True, output=self.output, write=True)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
