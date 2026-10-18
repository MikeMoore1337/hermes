"""Offline-only tests for the dormant scoped local executor (no subprocess spawned)."""
from __future__ import annotations

from pathlib import Path
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch
from subprocess import TimeoutExpired

from eval_lane.fixed_plan import FixedPlan
from eval_lane.local_executor import LocalBoundedExecutor
from eval_lane.protocol import AdmissionDenied
from datetime import datetime, timezone


def job() -> dict:
    timestamp = datetime.fromtimestamp(1800000000, timezone.utc).isoformat()
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
        "issued_at": timestamp, "expires_at": timestamp,
    }


class BoundedExecutorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.kit, self.home, self.evidence = (
            root / "kit", root / "home", root / "evidence",
        )
        for directory in (self.kit, self.home, self.evidence):
            directory.mkdir(mode=0o700)
            directory.chmod(0o700)
        self.binary = root / "python-isolated"
        self.binary.write_text("synthetic placeholder; never executed")
        self.payload = job()
        self.runpath = self.evidence / self.payload["job_id"]

    def worker(self, *, enabled=False, probe=None, cancel=None):
        return LocalBoundedExecutor(
            toolkit_root=self.kit, python_binary=self.binary,
            evidence_root=self.evidence, isolated_home=self.home,
            approved_models=frozenset({"approved-model"}), enabled=enabled,
            isolation_probe=probe, cancellation_requested=cancel,
        )

    @patch("eval_lane.local_executor.subprocess.Popen")
    def test_default_disabled_never_calls_any_process(self, popen):
        with self.assertRaisesRegex(AdmissionDenied, "local_execution_disabled"):
            self.worker()(self.payload)
        popen.assert_not_called()

    @patch("eval_lane.local_executor.subprocess.Popen")
    def test_unknown_isolation_never_calls_any_process(self, popen):
        instance = self.worker(enabled=True, probe=None)
        with patch.object(os, "geteuid", return_value=os.getuid()):
            if os.getuid() == 0:
                with self.assertRaises(AdmissionDenied):
                    instance(self.payload)
            else:
                with self.assertRaisesRegex(AdmissionDenied, "isolation_attestation"):
                    instance(self.payload)
        popen.assert_not_called()

    @patch("eval_lane.local_executor.subprocess.Popen")
    @patch("eval_lane.local_executor.fixed_plan")
    def test_narrow_no_shell_argv_and_no_environment_secrets(self, make_plan, popen):
        self.runpath.mkdir(mode=0o700)
        (self.runpath / "observations.json").write_text(
            '{"schema_version":1,"executed":true}', encoding="utf-8",
        )
        make_plan.return_value = FixedPlan(
            argv=(str(self.binary), "agent_eval_runner.py", "--execute"),
            cwd=self.kit, output_dir=self.runpath,
        )
        child = MagicMock()
        child.wait.return_value = 0
        popen.return_value = child
        instance = self.worker(enabled=True, probe=lambda: True)
        with patch.object(instance, "_preflight", return_value=None):
            result = instance(self.payload)
        self.assertEqual(result["outcome"], "succeeded")
        self.assertEqual(len(result["artifact_sha256"]), 64)
        args, kwargs = popen.call_args
        self.assertEqual(args[0][0], str(self.binary))
        self.assertNotIn("shell", kwargs)
        self.assertEqual(kwargs["cwd"], self.kit)
        self.assertTrue(kwargs["start_new_session"])
        self.assertTrue(kwargs["close_fds"])
        self.assertIn("preexec_fn", kwargs)
        self.assertNotIn("OPENAI_API_KEY", kwargs["env"])
        self.assertNotIn("ANTHROPIC_API_KEY", kwargs["env"])
        self.assertEqual(kwargs["stdin"], -3)  # subprocess.DEVNULL
        self.assertEqual(kwargs["stdout"], -3)
        self.assertEqual(kwargs["stderr"], -3)

    @patch("eval_lane.local_executor.subprocess.Popen")
    @patch("eval_lane.local_executor.fixed_plan")
    def test_owner_cancel_before_subprocess(self, make_plan, popen):
        make_plan.return_value = FixedPlan(
            argv=(str(self.binary),), cwd=self.kit, output_dir=self.runpath,
        )
        instance = self.worker(enabled=True, probe=lambda: True, cancel=lambda: True)
        with patch.object(instance, "_preflight", return_value=None):
            with self.assertRaisesRegex(AdmissionDenied, "cancelled_before_launch"):
                instance(self.payload)
        popen.assert_not_called()

    @patch("eval_lane.local_executor.os.killpg")
    @patch("eval_lane.local_executor.subprocess.Popen")
    @patch("eval_lane.local_executor.fixed_plan")
    def test_owner_cancel_during_run_kills_process_group(self, make_plan, popen, killpg):
        make_plan.return_value = FixedPlan(
            argv=(str(self.binary),), cwd=self.kit, output_dir=self.runpath,
        )
        child = MagicMock()
        child.pid = 12345
        child.wait.side_effect = [TimeoutExpired("synthetic", 1), 0]
        popen.return_value = child
        counter = [0]
        def cancelled():
            counter[0] += 1
            return counter[0] >= 3
        instance = self.worker(enabled=True, probe=lambda: True, cancel=cancelled)
        with patch.object(instance, "_preflight", return_value=None):
            with self.assertRaisesRegex(AdmissionDenied, "cancelled_during_execution"):
                instance(self.payload)
        killpg.assert_called_once()

    @patch("eval_lane.local_executor.subprocess.Popen")
    @patch("eval_lane.local_executor.fixed_plan")
    def test_world_readable_evidence_result_is_rejected(self, make_plan, popen):
        self.runpath.mkdir(mode=0o700)
        (self.runpath / "observations.json").write_text('{"fake":true}', encoding="utf-8")
        self.runpath.chmod(0o755)
        make_plan.return_value = FixedPlan(
            argv=(str(self.binary),), cwd=self.kit, output_dir=self.runpath,
        )
        child = MagicMock()
        child.wait.return_value = 0
        popen.return_value = child
        instance = self.worker(enabled=True, probe=lambda: True)
        with patch.object(instance, "_preflight", return_value=None):
            with self.assertRaisesRegex(AdmissionDenied, "evidence_root_unsafe"):
                instance(self.payload)

    @patch("eval_lane.local_executor.os.umask")
    @patch("eval_lane.local_executor.resource.setrlimit")
    def test_process_resource_guard_uses_private_umask(self, limit, umask):
        LocalBoundedExecutor._resources(self.payload)()
        umask.assert_called_once_with(0o077)
        self.assertEqual(limit.call_count, 4)

    @patch("eval_lane.local_executor.subprocess.Popen")
    @patch("eval_lane.local_executor.fixed_plan")
    def test_success_without_artifact_fails_closed(self, make_plan, popen):
        # A real runner creates its private output directory before the report.
        self.runpath.mkdir(mode=0o700)
        make_plan.return_value = FixedPlan(
            argv=(str(self.binary),), cwd=self.kit, output_dir=self.runpath,
        )
        child = MagicMock()
        child.wait.return_value = 0
        popen.return_value = child
        instance = self.worker(enabled=True, probe=lambda: True)
        with patch.object(instance, "_preflight", return_value=None):
            with self.assertRaisesRegex(AdmissionDenied, "evidence_missing"):
                instance(self.payload)


if __name__ == "__main__":
    unittest.main()
