"""No real CLI calls: assert exact argv, sandbox, and dormant execution gate."""
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch, MagicMock

from control_center.codex_scheduler import ValidationError
from control_center.codex_scheduler_executor import (
    OfficialCodexExecutor, _effective_cgroup_memory_max,
)


class OfficialAdapterTests(TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        # CI never grants real model calls; simulate the trusted unit's
        # Linux cgroup-v2 256 MiB physical-memory hard limit.
        self.cgroup_patch = patch(
            "control_center.codex_scheduler_executor._effective_cgroup_memory_max",
            return_value=256 * 1024 * 1024)
        self.cgroup_mock = self.cgroup_patch.start()
        self.addCleanup(self.cgroup_patch.stop)
        root = Path(self.temp.name)
        self.repo = root / "repo"
        self.repo.mkdir()
        self.home = root / "codex-home"
        self.home.mkdir()
        self.binary = root / "codex"
        self.binary.write_text("only a mock binary, never run")
        self.job = {
            "repository": "MikeMoore1337/hermes",
            "approval_id": "approved-task-1234",
            "allowed_operations": ["inspect"],
            "model": "mock-model", "effort": "medium",
            "resource_limits": {"max_runtime_seconds": 30,
                                "max_memory_mb": 256, "max_output_bytes": 4096}
        }

    def tearDown(self):
        self.temp.cleanup()

    def adapter(self, enabled=False):
        return OfficialCodexExecutor(
            repo_roots={"MikeMoore1337/hermes": self.repo},
            approved_instructions={"approved-task-1234": "Review approved synthetic issue."},
            codex_home=self.home, binary=self.binary, enabled=enabled)

    @patch("control_center.codex_scheduler_executor.subprocess.Popen")
    def test_dormant_default_never_launches_cli(self, popen):
        with self.assertRaisesRegex(ValidationError, "live_worker_not_authorized"):
            self.adapter().execute(self.job)
        popen.assert_not_called()

    @patch("control_center.codex_scheduler_executor.subprocess.Popen")
    def test_only_fixed_argv_and_trusted_stdin(self, popen):
        process = MagicMock()
        process.returncode = 0
        popen.return_value = process
        adapter = self.adapter(enabled=True)
        okay, reference = adapter.execute(self.job)
        self.assertEqual(adapter.last_phase, "wait")
        self.assertTrue(okay)
        self.assertRegex(reference, "^sha256:[0-9a-f]{64}$")
        argv = popen.call_args.args[0]
        self.assertEqual(argv[:5], [str(self.binary), "--ask-for-approval", "never", "exec", "--json"])
        self.assertEqual(argv[argv.index("--sandbox") + 1], "read-only")
        self.assertIn("--skip-git-repo-check", argv)  # Immutable CD tar archive has no .git
        self.assertEqual(argv[-1], "-")
        self.assertEqual(argv[argv.index("--model") + 1], "mock-model")
        self.assertNotIn("shell", popen.call_args.kwargs)
        self.assertEqual(popen.call_args.kwargs["cwd"], self.repo)
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        self.assertEqual(popen.call_args.kwargs["env"]["CODEX_HOME"], str(self.home))
        self.assertNotIn("OPENAI_API_KEY", popen.call_args.kwargs["env"])
        self.assertEqual(process.communicate.call_args.kwargs["input"],
                         b"Review approved synthetic issue.")

    @patch("control_center.codex_scheduler_executor.subprocess.Popen")
    def test_unverified_or_oversized_memory_cgroup_blocks_all_execution(self, popen):
        for bound in (None, 768 * 1024 * 1024):
            with self.subTest(bound=bound):
                self.cgroup_mock.return_value = bound
                adapter = self.adapter(enabled=True)
                with self.assertRaisesRegex(
                    ValidationError, "memory_cgroup_unverified"
                ):
                    adapter.execute(self.job)
                self.assertEqual(adapter.last_phase, "preflight")
        popen.assert_not_called()

    def test_effective_cgroup_memory_max_including_parent_limits(self):
        from control_center import codex_scheduler_executor as module
        cgroot = Path(self.temp.name) / "cgroup"
        child = cgroot / "system.slice" / "hermes-codex-scheduler.service"
        child.mkdir(parents=True)
        (cgroot / "memory.max").write_text("max\n")
        (cgroot / "system.slice" / "memory.max").write_text(
            str(512 * 1024 * 1024))
        (child / "memory.max").write_text(str(256 * 1024 * 1024))
        proc = Path(self.temp.name) / "proc-cgroup"
        proc.write_text("0::/system.slice/hermes-codex-scheduler.service\n")
        with patch.object(module, "_CGROUP_ROOT", cgroot), patch.object(
            module, "_PROC_CGROUP", proc
        ):
            # A stricter child limit wins.
            self.assertEqual(_effective_cgroup_memory_max(),
                             256 * 1024 * 1024)
            (child / "memory.max").write_text("max\n")
            # An inherited parent cap remains mandatory.
            self.assertEqual(_effective_cgroup_memory_max(),
                             512 * 1024 * 1024)
            (cgroot / "system.slice" / "memory.max").write_text("max\n")
            self.assertIsNone(_effective_cgroup_memory_max())
            (child / "memory.max").write_text("invalid\n")
            self.assertIsNone(_effective_cgroup_memory_max())

    def test_cgroup_v2_root_without_memory_max_requires_real_descendant_limit(self):
        # Mirrors the actual production systemd sandbox:
        # /sys/fs/cgroup/memory.max is absent, system.slice=max, unit=256 MiB.
        from control_center import codex_scheduler_executor as module
        root = Path(self.temp.name) / "cgroup-v2"
        parent = root / "system.slice"
        leaf = parent / "h271-probe.service"
        leaf.mkdir(parents=True)
        proc = Path(self.temp.name) / "proc-cgroup-root-absent"
        proc.write_text("0::/system.slice/h271-probe.service\n")
        (parent / "memory.max").write_text("max\n")
        leaf_limit = leaf / "memory.max"
        leaf_limit.write_text(str(256 * 1024 * 1024) + "\n")
        self.assertFalse((root / "memory.max").exists())

        with patch.object(module, "_CGROUP_ROOT", root), patch.object(
            module, "_PROC_CGROUP", proc
        ):
            # Missing root file is normal; real, finite leaf bound is trusted.
            self.assertEqual(_effective_cgroup_memory_max(),
                             256 * 1024 * 1024)
            # The leaf may inherit a finite cap from a verified ancestor.
            (parent / "memory.max").write_text(str(192 * 1024 * 1024))
            self.assertEqual(_effective_cgroup_memory_max(),
                             192 * 1024 * 1024)
            (parent / "memory.max").write_text("max")
            leaf_limit.write_text("max")
            # No finite bound anywhere still fails closed.
            self.assertIsNone(_effective_cgroup_memory_max())
            leaf_limit.unlink()
            # Missing leaf file must NEVER be treated as a missing root file.
            self.assertIsNone(_effective_cgroup_memory_max())
            leaf_limit.write_text(str(256 * 1024 * 1024))
            (parent / "memory.max").unlink()
            # Intermediate missing file is also unacceptable.
            self.assertIsNone(_effective_cgroup_memory_max())
            (parent / "memory.max").write_text("max")
            (root / "memory.max").write_text("not_a_limit")
            self.assertIsNone(_effective_cgroup_memory_max())
            (root / "memory.max").unlink()
            # A path consisting only of the mount root with no limit is unbounded.
            proc.write_text("0::/\n")
            self.assertIsNone(_effective_cgroup_memory_max())

    @patch("control_center.codex_scheduler_executor.subprocess.Popen")
    def test_patch_requires_a_real_git_checkout(self, popen):
        writable = {**self.job, "allowed_operations": ["patch"]}
        with self.assertRaisesRegex(ValidationError, "writable_git_checkout_required"):
            self.adapter(enabled=True).execute(writable)
        popen.assert_not_called()
        (self.repo / ".git").mkdir()
        process = MagicMock()
        process.returncode = 0
        popen.return_value = process
        self.adapter(enabled=True).execute(writable)
        argv = popen.call_args.args[0]
        self.assertEqual(argv[argv.index("--sandbox") + 1], "workspace-write")
        self.assertNotIn("--skip-git-repo-check", argv)

    @patch("control_center.codex_scheduler_executor.subprocess.Popen")
    def test_successful_jsonl_is_durable_before_receipt(self, popen):
        process = MagicMock()
        process.returncode = 0

        def simulate(*, input, timeout):
            output = popen.call_args.kwargs["stdout"]
            output.write(b'{"type":"item.completed","summary":"synthetic"}\n')
            output.flush()

        process.communicate.side_effect = simulate
        popen.return_value = process
        artifacts = Path(self.temp.name) / "artifacts"
        artifacts.mkdir(mode=0o700)
        adapter = OfficialCodexExecutor(
            repo_roots={"MikeMoore1337/hermes": self.repo},
            approved_instructions={"approved-task-1234": "Review synthetic only."},
            codex_home=self.home, binary=self.binary,
            enabled=True, artifact_dir=artifacts)
        jid = "12345678-1111-2222-3333-123456789abc"
        success, receipt = adapter.execute({**self.job, "job_id": jid})
        self.assertTrue(success)
        self.assertEqual(adapter.last_phase, "complete")
        self.assertTrue(receipt.startswith("artifact:" + jid + ":"))
        stored = list(artifacts.glob("*.jsonl"))
        self.assertEqual(len(stored), 1)
        self.assertIn(b"synthetic", stored[0].read_bytes())
        self.assertEqual(stored[0].stat().st_mode & 0o777, 0o600)

    @patch("control_center.codex_scheduler_executor.subprocess.Popen")
    def test_unapproved_plan_and_unknown_operations_refused(self, popen):
        malformed = {**self.job, "approval_id": "unknown-approval-01"}
        with self.assertRaises(ValidationError):
            self.adapter(enabled=True).execute(malformed)
        malformed = {**self.job, "allowed_operations": ["shell"]}
        with self.assertRaises(ValidationError):
            self.adapter(enabled=True).execute(malformed)
        popen.assert_not_called()

    def test_installed_unit_has_real_256m_hard_cap(self):
        unit = (Path(__file__).resolve().parents[1] /
                "deploy/hermes-codex-scheduler.service").read_text()
        self.assertIn("MemoryAccounting=true", unit)
        self.assertIn("MemoryMax=256M", unit)
        self.assertIn("NoNewPrivileges=true", unit)

    def test_deploys_in_existing_control_center_package(self):
        root = Path(__file__).resolve().parents[1]
        for path in ("codex_scheduler.py", "codex_scheduler_status.py",
                     "codex_scheduler_executor.py"):
            self.assertTrue((root / "control_center" / path).is_file())
        deploy = (root / "deploy" / "hermes-main-deploy.sh").read_text()
        standalone = (root / "deploy" / "install-control-center.sh").read_text()
        self.assertIn('cp -a -- "$release/control_center" "$ui_release/"', deploy)
        self.assertIn('"$source_dir/control_center/"*.py', standalone)


if __name__ == "__main__":
    import unittest
    unittest.main()
