"""Hermes H-15 #349: strictly offline one-shot protocol and denial matrix."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from eval_lane.protocol import (
    AdmissionDenied, OperatorGates, digest, issue_test_grant,
    validate_job, verify_grant, verify_operator_gates,
)
from eval_lane.one_shot import OneShotLedger
from eval_lane.fixed_plan import fixed_plan

NOW = 1800000000.0
KEY = b"synthetic-test-only-approval-not-for-live-use-0123456789abcdef"


def stamp(offset: float) -> str:
    return datetime.fromtimestamp(NOW + offset, timezone.utc).isoformat()


def job() -> dict:
    return {
        "schema_version": 1, "kind": "adt_skill_eval_pilot_v1",
        "job_id": "eval-job-123456789", "approval_id": "owner-grant-123456789",
        "toolkit_sha": "a" * 40, "provider": "codex", "model": "approved-model",
        "case_ids": ["python-api", "javascript-ui"], "trials": 2,
        "timeout_seconds": 150,
        "resource_limits": {
            "memory_mb": 512, "cpu_seconds": 300, "output_bytes": 65536,
        },
        "budget": {
            "maximum_usd": "1.00", "provider_hard_cap_id": "hard-cap-12345678",
        },
        "issued_at": stamp(-10), "expires_at": stamp(600),
    }


def gates() -> OperatorGates:
    return OperatorGates(
        isolated_identity_verified=True, os_sandbox_verified=True,
        egress_acl_verified=True, provider_cost_hard_stop_verified=True,
        artifact_scope_verified=True, owner_runtime_go=True,
    )


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.payload = job()
        self.grant = issue_test_grant(self.payload, KEY)

    def admit(self, payload=None, grant=None, **kw):
        value = self.payload if payload is None else payload
        validated = validate_job(value, clock=NOW)
        verify_grant(self.grant if grant is None else grant,
                     validated, key=KEY, clock=NOW, **kw)
        return validated

    def test_exact_signed_one_purpose_contract(self):
        self.assertEqual(self.admit()["kind"], "adt_skill_eval_pilot_v1")
        self.assertEqual(self.grant["job_sha256"], digest(self.payload))
        self.assertEqual(self.admit(), self.payload)

    def test_unknown_fields_shell_urls_and_paths_are_forbidden(self):
        for key, value in (
            ("command", "rm -rf /"), ("argv", ["sh", "-c", "echo unsafe"]),
            ("url", "https://example.com"), ("repository_path", "/private"),
            ("environment", {"OPENAI_API_KEY": "synthetic"}),
            ("status", "approved"),
        ):
            with self.subTest(field=key):
                payload = {**self.payload, key: value}
                with self.assertRaisesRegex(AdmissionDenied, "unknown_job_schema"):
                    validate_job(payload, clock=NOW)

    def test_wrong_kind_model_provider_case_sha_and_limits_fail(self):
        mutations = {
            "kind": "remote_shell",
            "provider": "bash",
            "model": "model; echo unsafe",
            "case_ids": ["python-api", "../private"],
            "toolkit_sha": "main",
            "trials": 0,
            "timeout_seconds": 1800,
            "resource_limits": {"memory_mb": 1, "cpu_seconds": 30, "output_bytes": 4096},
            "budget": {"maximum_usd": "Infinity", "provider_hard_cap_id": "hard-cap-12345678"},
        }
        for key, value in mutations.items():
            with self.subTest(field=key), self.assertRaises(AdmissionDenied):
                validate_job({**self.payload, key: value}, clock=NOW)

    def test_expired_jobs_invalid_timestamps_and_replays_fail(self):
        for changes in (
            {"expires_at": stamp(-1)},
            {"issued_at": stamp(100)},
            {"expires_at": stamp(7200)},
            {"issued_at": "2026-10-18"},
            {"job_id": "../something"},
        ):
            with self.subTest(changes=changes), self.assertRaises(AdmissionDenied):
                validate_job({**self.payload, **changes}, clock=NOW)

    def test_approval_is_exact_scope_and_owner_bound(self):
        for key, value in (
            ("owner", "forged"), ("job_sha256", "f" * 64),
            ("approval_id", "another-approval-12345"),
            ("signature", "1" * 64),
        ):
            with self.subTest(field=key):
                mutated = {**self.grant, key: value}
                with self.assertRaises(AdmissionDenied):
                    self.admit(grant=mutated)
        changed = deepcopy(self.payload)
        changed["case_ids"] = ["go-cli"]
        with self.assertRaisesRegex(AdmissionDenied, "approval_scope_mismatch"):
            self.admit(payload=changed)
        with self.assertRaisesRegex(AdmissionDenied, "approval_revoked"):
            self.admit(revoked=frozenset({self.payload["approval_id"]}))
        with self.assertRaisesRegex(AdmissionDenied, "trusted_approval_key"):
            verify_grant(self.grant, self.payload, key=b"short", clock=NOW)

    def test_fake_claimed_isolation_is_not_default_permission(self):
        with self.assertRaisesRegex(AdmissionDenied, "runtime_proofs_not_verified"):
            verify_operator_gates(OperatorGates())
        with self.assertRaisesRegex(AdmissionDenied, "runtime_proofs_not_verified"):
            verify_operator_gates({name: True for name in OperatorGates.__dataclass_fields__})


class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "isolated-receipts"
        self.root.mkdir(mode=0o700)
        os.chmod(self.root, 0o700)
        self.payload = job()
        self.grant = issue_test_grant(self.payload, KEY)
        self.callbacks = []

    def invoke(self, *, enabled=True, runner=None, grant=None, revoked=frozenset(),
               approved_gates=None):
        return OneShotLedger(self.root, enabled=enabled).run_once(
            self.payload, self.grant if grant is None else grant,
            approval_key=KEY, revoked_approvals=revoked,
            gates=gates() if approved_gates is None else approved_gates,
            runner=runner, clock=NOW,
        )

    def test_disabled_is_zero_write_and_never_calls_runner(self):
        def forbidden(_):
            self.fail("must never invoke")
        with self.assertRaisesRegex(AdmissionDenied, "execution_disabled"):
            self.invoke(enabled=False, runner=forbidden)
        self.assertEqual([], list(self.root.iterdir()))

    def test_success_consumes_idempotency_key_before_running(self):
        def fake(payload):
            self.callbacks.append(payload["job_id"])
            return {"outcome": "succeeded", "artifact_sha256": "f" * 64}
        actual = self.invoke(runner=fake)
        self.assertEqual(actual["state"], "succeeded")
        self.assertEqual(self.callbacks, [self.payload["job_id"]])
        self.assertEqual(OneShotLedger(self.root).state(self.payload["job_id"]), "succeeded")
        with self.assertRaisesRegex(AdmissionDenied, "no_replay"):
            self.invoke(runner=fake)
        self.assertEqual(len(self.callbacks), 1)
        receipt = self.root / (self.payload["job_id"] + ".json")
        self.assertEqual(receipt.stat().st_mode & 0o777, 0o600)
        self.assertNotIn("f" * 64, repr(self.payload))

    def test_crash_or_disconnect_is_uncertain_and_non_retryable(self):
        count = []
        def crash(_):
            count.append(1)
            raise ConnectionError("synthetic lost result ACK")
        with self.assertRaises(ConnectionError):
            self.invoke(runner=crash)
        self.assertEqual(OneShotLedger(self.root).state(self.payload["job_id"]),
                         "uncertain_do_not_retry")
        with self.assertRaisesRegex(AdmissionDenied, "no_replay"):
            self.invoke(runner=crash)
        self.assertEqual(len(count), 1)

    def test_expired_revoked_missing_proofs_never_claim(self):
        for kwargs in (
            {"revoked": frozenset({self.payload["approval_id"]})},
            {"approved_gates": OperatorGates()},
            {"runner": None},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(AdmissionDenied):
                self.invoke(runner=lambda _: {"outcome": "succeeded", "artifact_sha256": "f" * 64},
                            **kwargs)
        self.assertEqual([], list(self.root.iterdir()))

    def test_invalid_runner_receipt_is_never_reported_success(self):
        with self.assertRaisesRegex(AdmissionDenied, "executor_receipt_invalid"):
            self.invoke(runner=lambda _: {"outcome": "succeeded", "artifact_sha256": "token"})
        self.assertEqual(OneShotLedger(self.root).state(self.payload["job_id"]),
                         "uncertain_do_not_retry")

    def test_untrusted_root_or_symlink_rejected(self):
        os.chmod(self.root, 0o777)
        with self.assertRaisesRegex(AdmissionDenied, "permissions"):
            self.invoke(runner=lambda _: {"outcome": "failed", "artifact_sha256": "a" * 64})
        self.assertFalse((self.root / (self.payload["job_id"] + ".json")).exists())


class FixedPlanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.kit = self.root / "kit"
        (self.kit / "scripts").mkdir(parents=True)
        (self.kit / "scripts" / "agent_eval_runner.py").write_text("# trusted placeholder")
        (self.kit / ".git").mkdir()
        self.evidence = self.root / "evidence"
        self.evidence.mkdir(mode=0o700)
        os.chmod(self.evidence, 0o700)
        self.interpreter = self.root / "python3"
        self.interpreter.write_text("synthetic binary, never executed")
        self.payload = job()

    def test_exact_argv_never_contains_shell_or_untrusted_paths(self):
        with patch("eval_lane.fixed_plan.pinned_toolkit") as pin:
            plan = fixed_plan(
                self.payload, toolkit_root=self.kit,
                python_binary=self.interpreter, evidence_root=self.evidence,
                approved_models=frozenset({"approved-model"}), clock=NOW)
        self.assertEqual(plan.argv[0], str(self.interpreter))
        self.assertIn("--execute", plan.argv)
        self.assertEqual(plan.argv[plan.argv.index("--provider") + 1], "codex")
        self.assertEqual(plan.argv[plan.argv.index("--model") + 1], "approved-model")
        self.assertNotIn("sh", plan.argv)
        self.assertNotIn("--yolo", plan.argv)
        self.assertEqual(plan.output_dir, self.evidence / self.payload["job_id"])
        pin.assert_called_once()

    def test_unapproved_model_runtime_and_output_rejected(self):
        with self.assertRaisesRegex(AdmissionDenied, "model_not_preapproved"):
            fixed_plan(self.payload, toolkit_root=self.kit, python_binary=self.interpreter,
                       evidence_root=self.evidence, approved_models=frozenset(), clock=NOW)
        longer = {**self.payload, "timeout_seconds": 600, "trials": 3,
                  "case_ids": ["python-api", "javascript-ui", "go-cli"]}
        with self.assertRaisesRegex(AdmissionDenied, "aggregate_runtime_limit"):
            fixed_plan(longer, toolkit_root=self.kit, python_binary=self.interpreter,
                       evidence_root=self.evidence,
                       approved_models=frozenset({"approved-model"}), clock=NOW)
        (self.evidence / self.payload["job_id"]).mkdir()
        with patch("eval_lane.fixed_plan.pinned_toolkit"):
            with self.assertRaisesRegex(AdmissionDenied, "evidence_already_exists"):
                fixed_plan(self.payload, toolkit_root=self.kit, python_binary=self.interpreter,
                           evidence_root=self.evidence,
                           approved_models=frozenset({"approved-model"}), clock=NOW)


if __name__ == "__main__":
    unittest.main()
