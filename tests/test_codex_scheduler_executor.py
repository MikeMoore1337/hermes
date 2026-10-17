"""No real CLI calls: assert exact argv, sandbox, and dormant execution gate."""
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch, MagicMock

from control_center.codex_scheduler import ValidationError
from control_center.codex_scheduler_executor import OfficialCodexExecutor


class OfficialAdapterTests(TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
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
        okay, reference = self.adapter(enabled=True).execute(self.job)
        self.assertTrue(okay)
        self.assertRegex(reference, "^sha256:[0-9a-f]{64}$")
        argv = popen.call_args.args[0]
        self.assertEqual(argv[:3], [str(self.binary), "exec", "--json"])
        self.assertEqual(argv[argv.index("--sandbox") + 1], "read-only")
        self.assertEqual(argv[argv.index("--model") + 1], "mock-model")
        self.assertNotIn("shell", popen.call_args.kwargs)
        self.assertEqual(popen.call_args.kwargs["cwd"], self.repo)
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        self.assertEqual(popen.call_args.kwargs["env"]["CODEX_HOME"], str(self.home))
        self.assertNotIn("OPENAI_API_KEY", popen.call_args.kwargs["env"])
        self.assertEqual(process.communicate.call_args.kwargs["input"],
                         b"Review approved synthetic issue.")

    @patch("control_center.codex_scheduler_executor.subprocess.Popen")
    def test_unapproved_plan_and_unknown_operations_refused(self, popen):
        malformed = {**self.job, "approval_id": "unknown-approval-01"}
        with self.assertRaises(ValidationError):
            self.adapter(enabled=True).execute(malformed)
        malformed = {**self.job, "allowed_operations": ["shell"]}
        with self.assertRaises(ValidationError):
            self.adapter(enabled=True).execute(malformed)
        popen.assert_not_called()

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
