"""H-10 zero-expense agent role contracts and fail-closed telemetry."""
from __future__ import annotations

import copy
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_budget.policy import (
    CONTRACT, BudgetDenied, authorize, load, main, validate, verify_metrics,
)


class BudgetGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.data = copy.deepcopy(load())

    def test_existing_policy_has_no_runtime_or_billing_approval(self):
        self.assertFalse(self.data["runtime_enabled"])
        self.assertFalse(self.data["provider_billing_verified"])
        self.assertEqual(self.data["daily_spend_cap_usd"], 0)
        self.assertEqual(self.data["retries_per_job"], 0)
        self.assertEqual(set(self.data["roles"]), {"analyst", "planner", "proposer"})

    def test_all_three_offline_roles_execute_no_side_effect(self):
        pairs = {
            "analyst": "classify_sanitized_codes",
            "planner": "plan_from_public_metadata",
            "proposer": "draft_without_delivery",
        }
        for role, action in pairs.items():
            with self.subTest(role=role):
                admitted = authorize(
                    self.data, role=role, action=action, kind="offline",
                    expected_calls=0, estimated_cost_usd=0, quota_remaining=None,
                    owner_approved=False,
                )
                self.assertEqual(admitted["status"], "ALLOWED_OFFLINE")
                self.assertEqual(admitted["side_effect"], "none")

    def test_explicit_privilege_escalation_and_role_crossovers_denied(self):
        operations = [
            "shell", "browser", "mcp", "git_write", "github_write",
            "telegram_send", "publish", "deploy", "database_write",
            "read_private_vault", "restart_service", "new_provider",
            "paid_fallback",
        ]
        operations += [
            "plan_from_public_metadata", "draft_without_delivery",
        ]
        for action in operations:
            with self.subTest(action=action):
                with self.assertRaisesRegex(BudgetDenied, "permission_denied"):
                    authorize(self.data, role="analyst", action=action,
                              kind="offline", expected_calls=0,
                              estimated_cost_usd=0, quota_remaining=None,
                              owner_approved=True)

    def test_runtime_model_denied_with_any_unverified_bill(self):
        for cost, quota in ((0, 1000), (None, 1000), (0.01, 1000), (0, None), (0, 0)):
            with self.subTest(cost=cost, quota=quota):
                with self.assertRaisesRegex(BudgetDenied, "runtime_or_billing_gate_closed"):
                    authorize(self.data, role="analyst",
                              action="classify_sanitized_codes", kind="model",
                              expected_calls=1, estimated_cost_usd=cost,
                              quota_remaining=quota, owner_approved=True)

    def test_test_only_local_eligibility_does_not_imply_runtime_permitted(self):
        activated = copy.deepcopy(self.data)
        activated["runtime_enabled"] = True
        activated["provider_billing_verified"] = True
        for input_cost, quota, expected in (
            (None, 1, "unknown_or_nonzero_provider_cost"),
            (0.01, 1, "unknown_or_nonzero_provider_cost"),
            (0, None, "unknown_or_exhausted_provider_quota"),
            (0, 0, "unknown_or_exhausted_provider_quota"),
        ):
            with self.subTest(cost=input_cost, quota=quota):
                with self.assertRaisesRegex(BudgetDenied, expected):
                    authorize(activated, role="analyst",
                              action="classify_sanitized_codes", kind="model",
                              expected_calls=1, estimated_cost_usd=input_cost,
                              quota_remaining=quota, owner_approved=True)

        approved = authorize(activated, role="analyst",
                             action="classify_sanitized_codes", kind="model",
                             expected_calls=1, estimated_cost_usd=0,
                             quota_remaining=1, owner_approved=True)
        self.assertEqual(approved["status"], "ELIGIBLE_BY_LOCAL_POLICY_ONLY")
        self.assertEqual(approved["side_effect"], "none")

    def test_invalid_kind_type_denied_with_fixed_code(self):
        for kind in ([], {}, None, 1, True):
            with self.subTest(kind=repr(kind)):
                with self.assertRaisesRegex(BudgetDenied,
                                             "execution_kind_denied"):
                    authorize(self.data, role="analyst",
                              action="classify_sanitized_codes", kind=kind,
                              expected_calls=0, estimated_cost_usd=0,
                              quota_remaining=None, owner_approved=False)

    def test_invalid_roles_retries_budget_and_timing_denied(self):
        invalid = [
            ("daily_spend_cap_usd", 0.01),
            ("daily_spend_cap_usd", -1),
            ("daily_spend_cap_usd", True),
            ("retries_per_job", 1),
            ("retries_per_job", -1),
            ("model_calls_per_job", 2),
            ("model_calls_per_job", True),
            ("timeout_seconds", 206),
            ("timeout_seconds", 0),
            ("runtime_enabled", "true"),
            ("provider_billing_verified", "true"),
            ("roles", {"admin": ["shell"]}),
            ("allowed_actions", ["shell"]),
            ("roles", {"analyst": ["publish"], "planner": [], "proposer": []}),
        ]
        for key, value in invalid:
            with self.subTest(key=key, value=value):
                mutated = copy.deepcopy(self.data)
                mutated[key] = value
                with self.assertRaises(BudgetDenied):
                    validate(mutated)

    def test_call_limits_and_retry_attempts_are_bounded(self):
        with self.assertRaisesRegex(BudgetDenied, "call_limit_exceeded"):
            authorize(self.data, role="analyst",
                      action="classify_sanitized_codes", kind="offline",
                      expected_calls=2, estimated_cost_usd=0,
                      quota_remaining=None, owner_approved=True)
        with self.assertRaisesRegex(BudgetDenied, "offline_must_have_zero_cost_and_calls"):
            authorize(self.data, role="analyst",
                      action="classify_sanitized_codes", kind="offline",
                      expected_calls=1, estimated_cost_usd=0,
                      quota_remaining=None, owner_approved=True)

    def test_provider_rejections_never_trigger_auto_retry(self):
        base = {
            "duration_seconds": 1.2, "attempts": 1, "input_tokens": None,
            "output_tokens": None, "provider_neurons": None,
            "provider_cost_usd": 0, "http_status": 200,
        }
        for status in (100, 201, 204, 301, 302, 307, 308,
                       400, 401, 402, 403, 404, 408, 422, 429,
                       500, 503, 599):
            with self.subTest(status=status):
                current = {**base, "http_status": status}
                self.assertEqual(verify_metrics(current)["status"], "STOP_NO_RETRY")

    def test_provider_unknown_spend_is_not_auto_success(self):
        data = {
            "duration_seconds": 113.4, "attempts": 1,
            "input_tokens": None, "output_tokens": None,
            "provider_neurons": None, "provider_cost_usd": None, "http_status": None,
        }
        self.assertEqual(verify_metrics(data)["status"], "UNKNOWN_PROVIDER_STATUS")
        self.assertEqual(verify_metrics({**data, "provider_cost_usd": 0})["status"],
                         "UNKNOWN_PROVIDER_STATUS")
        success={**data,"http_status":200}
        self.assertEqual(verify_metrics(success)["status"], "UNKNOWN_SPEND")
        self.assertEqual(verify_metrics({**success, "provider_cost_usd": 1})["status"],
                         "STOP_NONZERO_COST")
        self.assertEqual(verify_metrics({**success, "provider_cost_usd": 0})["status"],
                         "MEASURED_ZERO_RECORDED")
        with self.assertRaisesRegex(BudgetDenied, "attempts_invalid"):
            verify_metrics({**data, "attempts": 2})

    def test_no_duplicate_policy_keys_symlink_or_secret_dump(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            unsafe = root / "policy.json"
            unsafe.write_text('{"schema":"x","schema":"y"}', encoding="utf-8")
            with self.assertRaisesRegex(BudgetDenied, "duplicate_policy_key"):
                load(unsafe)
            unsafe.unlink()
            unsafe.symlink_to(CONTRACT)
            with self.assertRaisesRegex(BudgetDenied, "unsafe_policy_file"):
                load(unsafe)

    def test_cli_reports_only_status_no_network(self):
        with patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(main(), 0)
        self.assertEqual(json.loads(output.getvalue())["status"], "VALID_OFFLINE")
        self.assertFalse(json.loads(output.getvalue())["resident_agent_enabled"])


if __name__ == "__main__":
    unittest.main()
