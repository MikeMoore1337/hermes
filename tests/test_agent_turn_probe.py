"""The agent test must be fail-closed even if a provider returns apparently OK."""
from __future__ import annotations
import unittest
from unittest.mock import patch
from scripts import agent_turn_probe as probe


class BoundedAgentTurnTests(unittest.TestCase):
    def test_no_execute_never_calls_provider(self):
        with patch("sys.argv", ["agent_turn_probe.py"]), patch.object(probe, "guarded_turn") as call:
            self.assertEqual(probe.main(), 0)
            call.assert_not_called()

    @patch.object(probe.pwd, "getpwnam")
    def test_agent_permissions_and_free_only_model(self, account):
        account.return_value.pw_uid, account.return_value.pw_gid = 988, 981
        command = " ".join(probe.docker_args())
        for required in (
            "--network hermes-agent-isolated", "--ip 172.29.250.2", "--read-only",
            "--cap-drop ALL", "--memory 640m", "--cpus 0.30",
            "--env-file /var/lib/hermes-agent/.env",
            "--provider workers-ai", "-m @cf/openai/gpt-oss-20b",
            "-t todo", "--reasoning low", "-z Reply",
        ):
            with self.subTest(required=required):
                self.assertIn(required, command)
        for forbidden in ("--network host", "--privileged", "docker.sock",
                          "second-brain-vault", "openrouter", "groq", "latest"):
            self.assertNotIn(forbidden, command)

    def test_pass_requires_true_exit_and_exact_answer(self):
        self.assertEqual(probe.summarize("OK\n", 0, None, 4)["status"], "pass")
        for output, code in (("OK", 124), ("OK\nOTHER", 0), ("", 0), ("HTTP 401", 1)):
            with self.subTest(code=code, output=output):
                self.assertEqual(probe.summarize(output, code, None, 4)["status"], "incomplete")

    def test_budget_abort_never_returns_pass(self):
        for cause in ("news_load_pressure", "time_budget"):
            self.assertEqual(probe.summarize("OK", 0, cause, 12)["status"], "stopped")

    def test_never_repeat_untrusted_secrets_in_output(self):
        untrusted = "Bearer secret123 from account 01234567890123456789012345678901\nHTTP 401"
        serialized = str(probe.summarize(untrusted, 1, None, 3))
        self.assertNotIn("secret123", serialized)
        self.assertNotIn("01234567890123456789012345678901", serialized)
        self.assertTrue(probe.summarize(untrusted, 1, None, 3)["signals"]["auth"])

    def test_nonroot_fails_closed(self):
        with patch.object(probe.os, "geteuid", return_value=1000):
            with self.assertRaisesRegex(probe.Rejected, "root_required"):
                probe.preflight()


if __name__ == "__main__":
    unittest.main()
