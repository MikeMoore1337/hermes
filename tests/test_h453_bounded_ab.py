"""Offline, no-network regression for H-453 temporary Workers Free request comparison."""
from __future__ import annotations

from datetime import UTC, datetime
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Lock
import unittest
from unittest.mock import patch

from agent_budget.pilot import ModelResponse, PilotError, _prepared_case
from ops_watch.incident_advisor import mock_result
from scripts import h453_bounded_ab as ab


class FakeClient:
    def __init__(self, output: str, *, cost=0.0, calls=None):
        self.output = output
        self.cost = cost
        self.calls = calls

    def complete(self, prompt: str) -> ModelResponse:
        if self.calls is not None:
            self.calls.append(prompt)
        return ModelResponse(self.output, 200, 1, 0.001, input_tokens=10,
                             output_tokens=20, provider_neurons=5, provider_cost_usd=self.cost)


class BoundedComparisonTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory(prefix="h453-ab-unit-")
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.account = base / "account-status.json"
        self.state = base / "state.json"
        self.output = base / "output.json"
        self.attestation = {
            "schema": "hermes-cloudflare-account-status-v1",
            "plan": "WORKERS_FREE",
            "account_id_sha256": "a" * 64,
            "model": "@cf/openai/gpt-oss-20b",
            "daily_neurons_remaining": 10_000,
            "ai_gateway_unified_billing": False,
            "checked_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        }
        self.account.write_text(json.dumps(self.attestation), encoding="utf-8")
        _, _, _, context, _, _ = _prepared_case(ab.CASES[0])
        self.output_json = json.dumps(mock_result(context), ensure_ascii=False)

    def invoke(self, *, allow=True, fake_cost=0.0):
        fake = lambda _: FakeClient(self.output_json, cost=fake_cost)
        with patch.object(ab, "_client", side_effect=fake):
            with patch.dict(os.environ, {"HERMES_AI_LIVE_APPROVED": "1" if allow else "0"}):
                return ab.run(case=ab.CASES[0], account_status=self.account,
                              state=self.state, output=self.output, owner_approved=allow)

    def test_gated_without_approval_before_io(self):
        with self.assertRaisesRegex(PilotError, "owner_approval_required"):
            self.invoke(allow=False)
        self.assertFalse(self.state.exists())

    def test_gateway_billing_fails_closed(self):
        self.attestation["ai_gateway_unified_billing"] = True
        self.account.write_text(json.dumps(self.attestation), encoding="utf-8")
        with self.assertRaisesRegex(PilotError, "paid_gateway_not_allowed"):
            self.invoke()
        self.assertFalse(self.state.exists())

    def test_missing_status_fails_without_call(self):
        self.account.unlink()
        with self.assertRaisesRegex(PilotError, "account_status_unavailable"):
            self.invoke()
        self.assertFalse(self.state.exists())

    def test_undercap_quota_prevents_reservation(self):
        self.attestation["daily_neurons_remaining"] = 2_999
        self.account.write_text(json.dumps(self.attestation), encoding="utf-8")
        with self.assertRaisesRegex(PilotError, "insufficient_free_quota"):
            self.invoke()
        self.assertFalse(self.state.exists())

    def test_success_two_independent_calls_and_one_baseline(self):
        report = self.invoke()
        self.assertEqual(report["execution"], "LIVE_TOOL_FREE_REQUESTS_NOT_NATIVE_DELEGATION")
        self.assertEqual(report["provider_dispatches_reserved"], 3)
        self.assertEqual([x["role"] for x in report["b_independent_requests"]], ["signal", "safety"])
        invocations = [report["a_single"], *report["b_independent_requests"]]
        self.assertEqual(len(set(x["local_invocation_id"] for x in invocations)), 3)
        self.assertTrue(all(x["metrics"]["attempts"] == 1 for x in invocations))
        self.assertEqual(json.loads(self.state.read_text())["calls"], 3)
        self.assertEqual(json.loads(self.output.read_text())["schema"], ab.SCHEMA)
        self.output = self.output.with_name("second-attempt.json")
        with self.assertRaisesRegex(PilotError, "daily_local_call_cap"):
            self.invoke()

    def test_unknown_cost_blocks_parallel_before_calls(self):
        with self.assertRaisesRegex(PilotError, "cost_not_verified_zero"):
            self.invoke(fake_cost=None)
        self.assertEqual(json.loads(self.state.read_text())["calls"], 3)
        receipt = json.loads(self.output.read_text())
        self.assertEqual(receipt["status"], "BLOCKED")
        self.assertEqual(receipt["stage"], "A_MAY_HAVE_REQUESTED")
        self.assertEqual(receipt["actual_provider_requests"], "NOT_VERIFIED")
        self.assertEqual(receipt["provider_cost_usd"], "NOT_MEASURED")
        self.assertEqual(receipt["automatic_retries"], 0)

    def test_nonzero_cost_blocks_parallel_before_calls(self):
        with self.assertRaisesRegex(PilotError, "cost_not_verified_zero"):
            self.invoke(fake_cost=0.1)
        self.assertEqual(json.loads(self.state.read_text())["calls"], 3)
        receipt = json.loads(self.output.read_text())
        self.assertEqual(receipt["status"], "BLOCKED")
        self.assertEqual(receipt["stage"], "A_MAY_HAVE_REQUESTED")
        self.assertEqual(receipt["failure_reason"], "cost_not_verified_zero")

    def test_wrong_case_is_refused_before_file_read(self):
        with self.assertRaisesRegex(PilotError, "case_not_allowlisted"):
            with patch.dict(os.environ, {"HERMES_AI_LIVE_APPROVED": "1"}):
                ab.run(case="research:unexpected", account_status=self.account,
                       state=self.state, output=self.output, owner_approved=True)
        self.assertFalse(self.state.exists())

    def test_parallel_child_failure_creates_uncertain_b_receipt(self):
        class ChildError:
            def complete(self, prompt):
                raise PilotError("provider_http_429", attempts=1)
        clients = [FakeClient(self.output_json), FakeClient(self.output_json), ChildError()]
        with patch.object(ab, "_client", side_effect=clients):
            with patch.dict(os.environ, {"HERMES_AI_LIVE_APPROVED": "1"}):
                with self.assertRaisesRegex(PilotError, "provider_http_429"):
                    ab.run(case=ab.CASES[0], account_status=self.account,
                           state=self.state, output=self.output, owner_approved=True)
        receipt = json.loads(self.output.read_text())
        self.assertEqual(receipt["status"], "BLOCKED")
        self.assertEqual(receipt["stage"], "B_MAY_HAVE_REQUESTED")
        self.assertEqual(receipt["requests_reserved"], 3)
        self.assertEqual(receipt["actual_provider_requests"], "NOT_VERIFIED")
        self.assertEqual(json.loads(self.state.read_text())["calls"], 3)

    def test_existing_evidence_is_never_overwritten(self):
        self.output.write_text("immutable", encoding="utf-8")
        with self.assertRaisesRegex(PilotError, "unsafe_state_output"):
            self.invoke()
        self.assertEqual(self.output.read_text(), "immutable")
        self.assertFalse(self.state.exists())

    def test_account_evidence_cannot_be_output(self):
        with self.assertRaisesRegex(PilotError, "unsafe_state_output"):
            with patch.dict(os.environ, {"HERMES_AI_LIVE_APPROVED": "1"}):
                ab.run(case=ab.CASES[0], account_status=self.account,
                       state=self.state, output=self.account, owner_approved=True)
        self.assertFalse(self.state.exists())

    def test_account_evidence_cannot_be_state(self):
        with self.assertRaisesRegex(PilotError, "unsafe_state_output"):
            with patch.dict(os.environ, {"HERMES_AI_LIVE_APPROVED": "1"}):
                ab.run(case=ab.CASES[0], account_status=self.account,
                       state=self.account, output=self.output, owner_approved=True)
        self.assertFalse(self.output.exists())

    def test_same_state_and_output_denied(self):
        with self.assertRaisesRegex(PilotError, "unsafe_state_output"):
            with patch.dict(os.environ, {"HERMES_AI_LIVE_APPROVED": "1"}):
                ab.run(case=ab.CASES[0], account_status=self.account,
                       state=self.state, output=self.state, owner_approved=True)
        self.assertFalse(self.state.exists())


if __name__ == "__main__":
    unittest.main()
