"""P0 security regressions: stale/free billing evidence never starts a request."""
from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from agent_budget.pilot import (
    PRIMARY_MODEL,
    CloudflareFreeProvider,
    PilotError,
    load_account_status,
    validate_account_status,
)

ACCOUNT_ID = "0123456789abcdef0123456789abcdef"
BASE_URL = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/ai/v1"


def attestation(when: datetime) -> dict[str, object]:
    return {
        "schema": "hermes-cloudflare-account-status-v1",
        "plan": "WORKERS_FREE",
        "account_id_sha256": hashlib.sha256(ACCOUNT_ID.encode()).hexdigest(),
        "model": PRIMARY_MODEL,
        "daily_neurons_remaining": 9000,
        "ai_gateway_unified_billing": False,
        "checked_at": when.isoformat(),
    }


class NoNetwork:
    def __init__(self) -> None:
        self.calls = 0

    def open(self, *_: object, **__: object) -> None:
        self.calls += 1
        raise AssertionError("network must never be contacted")


class AccountFreshnessTests(unittest.TestCase):
    def test_fresh_attestation_is_only_locally_eligible(self):
        row = attestation(datetime.now(UTC))
        self.assertEqual(validate_account_status(row), row)

    def test_stale_and_future_accounts_fail_closed_from_disk(self):
        now = datetime.now(UTC)
        for when in (now - timedelta(hours=2), now + timedelta(minutes=2)):
            with self.subTest(when=when), tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / "status.json"
                path.write_text(json.dumps(attestation(when)), encoding="utf-8")
                with self.assertRaisesRegex(PilotError, "account_status_stale_or_future"):
                    load_account_status(path)

    def test_missing_timezone_is_not_account_proof(self):
        row = attestation(datetime.now(UTC))
        row["checked_at"] = datetime.now(UTC).replace(tzinfo=None).isoformat()
        with self.assertRaisesRegex(PilotError, "checked_at_timezone_required"):
            validate_account_status(row)

    def test_direct_provider_constructor_cannot_bypass_stale_check(self):
        opener = NoNetwork()
        with self.assertRaisesRegex(PilotError, "account_status_stale_or_future"):
            CloudflareFreeProvider(
                token="synthetic-test-token-without-network",
                base_url=BASE_URL,
                account_status=attestation(datetime.now(UTC) - timedelta(days=1)),
                opener=opener,
            )
        self.assertEqual(opener.calls, 0)

    def test_attestation_expired_between_init_and_request_is_denied(self):
        now = datetime.now(UTC)
        opener = NoNetwork()
        provider = CloudflareFreeProvider(
            token="synthetic-test-token-without-network",
            base_url=BASE_URL,
            account_status=attestation(now),
            opener=opener,
        )
        with patch("agent_budget.pilot.datetime", wraps=datetime) as clock:
            clock.now.return_value = now + timedelta(hours=2)
            with self.assertRaisesRegex(PilotError, "account_status_stale_or_future"):
                provider.complete("SYNTHETIC_NO_NETWORK")
        self.assertEqual(opener.calls, 0)
        self.assertEqual(provider.calls, 0)

    def test_paid_plan_cannot_be_rescued_by_fresh_timestamp(self):
        row = attestation(datetime.now(UTC))
        row["plan"] = "WORKERS_PAID"
        with self.assertRaisesRegex(PilotError, "account_free_not_confirmed"):
            validate_account_status(row)


if __name__ == "__main__":
    unittest.main()
