"""The agent test must be fail-closed even if a provider returns apparently OK."""
from __future__ import annotations
import sqlite3
import tempfile
import unittest
from pathlib import Path
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


    @patch.object(probe.pwd, "getpwnam")
    def test_explicit_tool_prompt_stays_in_single_todo_toolset(self, account):
        account.return_value.pw_uid, account.return_value.pw_gid = 988, 981
        command = probe.docker_args(tool_test=True)
        self.assertIn("todo_list", " ".join(command))
        self.assertEqual(command[command.index("-t") + 1], "todo")
        self.assertEqual(command[command.index("-m") + 1], "@cf/openai/gpt-oss-20b")

    def test_claim_of_tool_use_without_real_persisted_event_fails(self):
        result = probe.summarize("TOOL_OK", 0, None, 45, tool_test=True, todo_delta=0)
        self.assertEqual(result["status"], "incomplete")
        verified = probe.summarize("TOOL_OK", 0, None, 45, tool_test=True, todo_delta=2)
        self.assertEqual(verified["status"], "pass")
        self.assertEqual(verified["todo_tool_calls_verified"], 2)

    def test_tool_event_counter_reads_only_aggregate_metadata(self):
        with tempfile.TemporaryDirectory() as folder:
            dbpath = Path(folder) / "state.db"
            with sqlite3.connect(dbpath) as db:
                db.execute("CREATE TABLE messages (role TEXT, tool_name TEXT, tool_calls TEXT, active INTEGER)")
                db.execute("INSERT INTO messages VALUES ('assistant',NULL,'[]',1)")
                db.execute("INSERT INTO messages VALUES ('assistant',NULL,'[{\"function\":{\"name\":\"todo_list\"}}]',1)")
                db.execute("INSERT INTO messages VALUES ('tool','todo_list',NULL,1)")
            self.assertEqual(probe._count_todo_tool_events(dbpath), 2)


    def test_two_concurrent_invocations_cannot_share_agent_proxy_or_ip(self):
        from pathlib import Path
        with tempfile.TemporaryDirectory() as folder:
            lock_path = Path(folder) / "hermes-agent.lock"
            with probe.exclusive_agent_lock(lock_path):
                with self.assertRaisesRegex(probe.Rejected, "agent_already_running"):
                    with probe.exclusive_agent_lock(lock_path):
                        self.fail("second request must never reach preflight")
            with probe.exclusive_agent_lock(lock_path):
                self.assertTrue(lock_path.is_file())

    def test_symlinked_lock_file_is_refused_without_following_target(self):
        from pathlib import Path
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "target"
            target.write_text("safe")
            link = Path(folder) / "hermes-agent.lock"
            link.symlink_to(target)
            with self.assertRaisesRegex(probe.Rejected, "agent_lock_unavailable"):
                with probe.exclusive_agent_lock(link):
                    self.fail("symlink must be denied")
            self.assertEqual(target.read_text(), "safe")

    def test_insecure_existing_lock_file_refuses_execution(self):
        from pathlib import Path
        with tempfile.TemporaryDirectory() as folder:
            file = Path(folder) / "hermes-agent.lock"
            file.write_text("x")
            file.chmod(0o644)
            with self.assertRaisesRegex(probe.Rejected, "agent_lock_permissions"):
                with probe.exclusive_agent_lock(file):
                    self.fail("unsafe lock must be denied")

    def test_proxy_is_stopped_even_when_start_command_reports_failure(self):
        with patch.object(probe, "preflight"), \
             patch.object(probe, "ok", return_value=False) as healthy, \
             patch.object(probe, "run_command") as command, \
             self.assertRaisesRegex(probe.Rejected, "proxy_start_failed"):
            probe._guarded_turn_locked()
        self.assertEqual(healthy.call_count, 1)
        self.assertEqual(command.call_args.args[0],
                         ["systemctl", "stop", "hermes-cloudflare-proxy.service"])

    def test_guarded_turn_holds_lock_before_preflight(self):
        with patch.object(probe, "exclusive_agent_lock") as lock, \
             patch.object(probe, "_guarded_turn_locked", return_value={"status": "pass"}) as inner:
            result = probe.guarded_turn(tool_test=True)
        self.assertEqual(result, {"status": "pass"})
        lock.assert_called_once_with()
        inner.assert_called_once_with(tool_test=True)

    def test_nonroot_fails_closed(self):
        with patch.object(probe.os, "geteuid", return_value=1000):
            with self.assertRaisesRegex(probe.Rejected, "root_required"):
                probe.preflight()


if __name__ == "__main__":
    unittest.main()
