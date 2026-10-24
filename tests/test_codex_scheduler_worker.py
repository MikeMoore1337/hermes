"""H-15: synthetic-only checks for the opt-in production scheduler tick."""
from datetime import datetime, timedelta, timezone
from contextlib import redirect_stderr
from io import StringIO
from types import SimpleNamespace
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from control_center.codex_scheduler import Scheduler, ValidationError
from control_center import codex_scheduler_worker as worker


class WorkerRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.uid = os.getuid()
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.home = self.root / "home"
        self.home.mkdir()
        self.binary = self.root / "codex"
        self.binary.write_text("not executable - synthetic only")
        self.grants = self.root / "grants"
        self.grants.mkdir(mode=0o700)
        self.conf = self.root / "runtime.json"
        self.db = self.root / "state" / "jobs.sqlite3"
        self.artifacts = self.root / "state" / "artifacts"
        self.quota = self.root / "unconfigured-usage.json"
        self.config = {
            "schema": 1, "enabled": False, "owner": "MikeMoore1337",
            "models": ["mock-model"],
            "repository_roots": {"MikeMoore1337/hermes": str(self.repo)},
            "codex_binary": str(self.binary), "codex_home": str(self.home),
            "grants_directory": str(self.grants),
        }
        self.write_config()

    def write_config(self):
        self.conf.write_text(json.dumps(self.config))
        self.conf.chmod(0o600)

    def grant(self):
        now = datetime.now(timezone.utc)
        expires = (now + timedelta(hours=1)).isoformat()
        limits = {
            "max_runtime_seconds": 60,
            "max_memory_mb": 256,
            "max_output_bytes": 4096,
        }
        approval = {
            "approval_id": "owner-canary-1234",
            "initiator": "MikeMoore1337",
            "repository": "MikeMoore1337/hermes",
            "allowed_operations": ["inspect"],
            "model": "mock-model", "effort": "low",
            "resource_limits": limits,
            "expires_at": expires,
        }
        task = {
            "schema_version": 1, "requested_at": now.isoformat(),
            "expires_at": expires, "initiator": "MikeMoore1337",
            "approval_id": approval["approval_id"], "repository": approval["repository"],
            "allowed_operations": ["inspect"], "model": "mock-model",
            "effort": "low", "resource_limits": limits,
            "idempotency_key": "canary-inspection-1234",
        }
        path = self.grants / "canary.json"
        path.write_text(json.dumps({"schema": 1, "approval": approval,
                                    "task": task, "instruction": "Inspect only."}))
        path.chmod(0o600)
        return path

    def invoke(self, run):
        with patch.object(worker, "DEFAULT_DB", self.db), \
             patch.object(worker, "ARTIFACT_DIR", self.artifacts), \
             patch.object(worker, "DEFAULT_OUTPUT", self.quota), \
             patch.object(worker, "host_ready", return_value=True):
            return worker.run_once(self.conf, uid=self.uid, run=run)

    def test_off_by_default_even_with_approved_grant(self):
        self.grant()
        self.assertEqual(self.invoke(False)["mode"], "preflight")
        self.assertEqual(self.invoke(True), {"mode": "disabled"})
        self.assertFalse(self.db.exists())

    def test_disabled_cli_run_does_not_touch_missing_state_directory(self):
        from contextlib import redirect_stdout
        import io
        output = io.StringIO()
        with patch.object(worker.sys, "argv",
                          ["codex_scheduler_worker", "--config", str(self.conf), "--run"]), \
             patch.object(worker, "run_once", return_value={"mode": "disabled"}) as execute, \
             patch.object(worker, "publish_worker_status") as heartbeat, \
             redirect_stdout(output):
            self.assertEqual(worker.main(), 0)
        execute.assert_called_once_with(self.conf, run=True)
        heartbeat.assert_not_called()
        self.assertEqual(json.loads(output.getvalue()), {"mode": "disabled"})
        self.assertFalse(self.db.exists())

    def test_live_gate_with_missing_quota_never_runs_model(self):
        self.grant()
        self.config["enabled"] = True
        self.write_config()
        result = self.invoke(True)
        self.assertEqual(result["decision"], "UNKNOWN")
        self.assertTrue(self.db.exists())
        journal = Scheduler(self.db, repositories={"MikeMoore1337/hermes"},
                            models={"mock-model"})
        with journal._connect() as conn:
            row = conn.execute("SELECT status,attempt_count FROM jobs").fetchone()
        self.assertEqual((row["status"], row["attempt_count"]), ("deferred", 0))
        self.assertEqual(self.invoke(True)["decision"], "UNKNOWN")
        with journal._connect() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM jobs").fetchone()[0], 1)

    def test_capacity_gate_reports_only_failed_static_checks(self):
        mem = (
            "MemAvailable: 2000000 kB\n"
            "SwapTotal: 2000000 kB\n"
            "SwapFree: 2000000 kB\n"
        )
        output = StringIO()
        with patch.object(worker.Path, "read_text", return_value=mem), \
             patch.object(worker.shutil, "disk_usage",
                          return_value=SimpleNamespace(free=4995 * 1024 * 1024)), \
             patch.object(worker.os, "getloadavg", return_value=(1.6, 0.0, 0.0)), \
             redirect_stderr(output):
            self.assertFalse(worker.host_ready())
        self.assertEqual(json.loads(output.getvalue()), {
            "event": "codex_scheduler_capacity_deferral",
            "failed_checks": ["cpu_load", "disk"],
        })
        self.assertNotIn("4995", output.getvalue())
        self.assertNotIn("2000000", output.getvalue())

    def test_capacity_unreadable_is_fail_closed_and_redacted(self):
        output = StringIO()
        with patch.object(worker.Path, "read_text", side_effect=OSError(
            "private_host_path_should_not_appear"
        )), redirect_stderr(output):
            self.assertFalse(worker.host_ready())
        self.assertEqual(json.loads(output.getvalue()), {
            "event": "codex_scheduler_capacity_deferral",
            "failed_checks": ["measurement_unavailable"],
        })
        self.assertNotIn("private_host_path", output.getvalue())

    def test_host_pressure_defers_without_claiming(self):
        self.grant()
        self.config["enabled"] = True
        self.write_config()
        with patch.object(worker, "host_ready", return_value=False):
            result = self.invoke(False)
            self.assertEqual(result["mode"], "preflight")
        with patch.object(worker, "host_ready", return_value=False), \
             patch.object(worker, "DEFAULT_DB", self.db):
            result = worker.run_once(self.conf, uid=self.uid, run=True)
        self.assertEqual(result, {"mode": "deferred", "reason": "host_capacity"})
        self.assertFalse(self.db.exists())

    def test_manifest_change_cannot_change_immutable_authorization(self):
        path = self.grant()
        self.config["enabled"] = True
        self.write_config()
        self.invoke(True)
        content = json.loads(path.read_text())
        content["instruction"] = "A different prompt"
        path.write_text(json.dumps(content))
        with self.assertRaisesRegex(ValidationError, "grant_manifest_changed"):
            self.invoke(True)

    def test_untrusted_config_permissions_fail_closed(self):
        self.conf.chmod(0o666)
        with self.assertRaises(ValidationError):
            self.invoke(False)

    def test_bad_grant_is_rejected_even_before_activation(self):
        path = self.grant()
        content = json.loads(path.read_text())
        content["task"]["approval_id"] = "different-owner-111"
        path.write_text(json.dumps(content))
        with self.assertRaises(ValidationError):
            self.invoke(False)

    def test_empty_queue_no_inference(self):
        self.config["enabled"] = True
        self.write_config()
        self.assertEqual(self.invoke(True)["mode"], "idle")


if __name__ == "__main__":
    unittest.main()
