"""H-10 regression tests: role drift, cumulative quota and error telemetry.

All provider traffic is synthetic; no Cloudflare connection is opened.
"""
from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

from agent_budget.pilot import (
    PRIMARY_MODEL,
    CloudflareFreeProvider,
    PilotError,
    _run_case,
    run_pilot,
)
from agent_budget.policy import BudgetDenied, load, validate


ACCOUNT_ID = "0123456789abcdef0123456789abcdef"
BASE_URL = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/ai/v1"


def free_status(remaining: int = 9_000) -> dict[str, object]:
    return {
        "schema": "hermes-cloudflare-account-status-v1",
        "plan": "WORKERS_FREE",
        "account_id_sha256": hashlib.sha256(ACCOUNT_ID.encode()).hexdigest(),
        "model": PRIMARY_MODEL,
        "daily_neurons_remaining": remaining,
        "ai_gateway_unified_billing": False,
        "checked_at": datetime.now(UTC).isoformat(),
    }


class RejectingOpener:
    def __init__(self, failure: BaseException) -> None:
        self.failure = failure
        self.requests = 0

    def open(self, *_: object, **__: object) -> None:
        self.requests += 1
        raise self.failure


class NeverCalled:
    calls = 0

    def complete(self, _: str) -> None:
        self.calls += 1
        raise AssertionError("provider must not receive a request")


class H10DispatchTests(unittest.TestCase):
    def test_roles_cannot_be_reassigned_by_mutating_policy(self) -> None:
        original = load()
        for role, other_action in (
            ("analyst", "plan_from_public_metadata"),
            ("analyst", "draft_without_delivery"),
            ("planner", "classify_sanitized_codes"),
            ("proposer", "plan_from_public_metadata"),
        ):
            with self.subTest(role=role, action=other_action):
                data = copy.deepcopy(original)
                data["roles"][role] = [other_action]
                with self.assertRaisesRegex(BudgetDenied, "role_permission_denied"):
                    validate(data)

    def test_quota_snapshot_must_cover_total_reserved_calls(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            account = root / "account.json"
            account.write_text(json.dumps(free_status(1_000)), encoding="utf-8")
            fake = NeverCalled()
            with (
                patch.dict(os.environ, {"HERMES_AI_LIVE_APPROVED": "1"}, clear=True),
                patch("agent_budget.pilot.CloudflareFreeProvider.from_environment", return_value=fake),
            ):
                with self.assertRaisesRegex(PilotError, "local_neuron_reserve_exceeded"):
                    run_pilot(
                        engine="live",
                        cases=["ops:provider_http_429", "research:whey_gut_brain"],
                        owner_approved=True, account_status=account,
                        state=root / "state.json", output=root / "results.json",
                    )
            self.assertEqual(fake.calls, 0)

    def test_prior_local_reservations_reduce_fresh_quota_capacity(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            account = root / "account.json"
            account.write_text(json.dumps(free_status(1_000)), encoding="utf-8")
            state = root / "state.json"
            state.write_text(json.dumps({
                "date": datetime.now(UTC).date().isoformat(), "calls": 1,
            }), encoding="utf-8")
            fake = NeverCalled()
            with (
                patch.dict(os.environ, {"HERMES_AI_LIVE_APPROVED": "1"}, clear=True),
                patch("agent_budget.pilot.CloudflareFreeProvider.from_environment", return_value=fake),
            ):
                with self.assertRaisesRegex(PilotError, "local_neuron_reserve_exceeded"):
                    run_pilot(
                        engine="live", cases=["ops:provider_http_429"],
                        owner_approved=True, account_status=account, state=state,
                    )
            self.assertEqual(fake.calls, 0)
            self.assertEqual(json.loads(state.read_text(encoding="utf-8"))["calls"], 1)

    def test_http_error_metrics_are_measured_without_leaking_body(self) -> None:
        error = HTTPError(BASE_URL, 429, "quota", {},
                          io.BytesIO(b"Bearer forbidden-test-secret"))
        opener = RejectingOpener(error)
        provider = CloudflareFreeProvider(
            token="synthetic-token-with-no-network", base_url=BASE_URL,
            account_status=free_status(), opener=opener,
        )
        record = _run_case("ops:provider_http_429", engine="live", provider=provider)
        self.assertEqual(record["status"], "BLOCKED")
        self.assertEqual(record["reason"], "provider_http_429")
        self.assertEqual(record["metrics"]["http_status"], 429)
        self.assertEqual(record["metrics"]["attempts"], 1)
        self.assertIsInstance(record["metrics"]["provider_response_seconds"], float)
        self.assertEqual(record["metrics"]["provider_cost_usd"], "NOT_REPORTED")
        self.assertNotIn("forbidden-test-secret", str(record))
        self.assertEqual(opener.requests, 1)
        error.close()

    def test_network_timeout_has_one_attempt_no_assumed_status(self) -> None:
        opener = RejectingOpener(TimeoutError("synthetic timeout"))
        provider = CloudflareFreeProvider(
            token="synthetic-token-with-no-network", base_url=BASE_URL,
            account_status=free_status(), opener=opener,
        )
        record = _run_case("ops:provider_http_429", engine="live", provider=provider)
        self.assertEqual(record["reason"], "provider_timeout")
        self.assertEqual(record["metrics"]["attempts"], 1)
        self.assertEqual(record["metrics"]["http_status"], "NOT_REPORTED")
        self.assertEqual(opener.requests, 1)


if __name__ == "__main__":
    unittest.main()
