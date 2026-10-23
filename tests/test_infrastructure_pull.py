"""Synthetic no-network contract for the YFC restricted SSH monitoring link."""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import Mock, patch

from control_center import infrastructure_pull as monitor
from tests.test_infrastructure_monitor import fixture


class PullContract(unittest.TestCase):
    def test_fixed_ssh_command_has_no_agent_proxy_forwarding(self):
        argv = monitor.command("yfc-monitor.example", 2222)
        self.assertEqual(argv[0], "/usr/bin/ssh")
        self.assertIn("StrictHostKeyChecking=yes", argv)
        self.assertIn("IdentitiesOnly=yes", argv)
        self.assertIn("IdentityAgent=none", argv)
        self.assertIn("ProxyCommand=none", argv)
        self.assertIn("ClearAllForwardings=yes", argv)
        self.assertEqual(argv[-2:], ["hermes-infra-read@yfc-monitor.example", "snapshot"])
        self.assertNotIn("sh", argv)
        self.assertNotIn("sudo", argv)

    def test_fresh_yfc_snapshot_is_sanitized_before_write(self):
        sample = fixture("yfc")
        sample["extra_provider_secret"] = "never-expose"
        sample["metrics"]["other_sensitive_field"] = "private"
        runner = Mock(return_value=Mock(returncode=0, stdout=json.dumps(sample)))
        with patch.object(monitor, "endpoint", return_value=("yfc-monitor.example", 22)), \
             patch.object(monitor, "require_file"), \
             patch.object(monitor, "save") as save:
            result = monitor.pull(runner=runner)
        self.assertEqual(result["status"], "received")
        self.assertEqual(save.call_args.args[0]["host"], "yfc")
        self.assertNotIn("extra_provider_secret", save.call_args.args[0])
        self.assertNotIn("other_sensitive_field", save.call_args.args[0]["metrics"])
        self.assertNotIn("network_interfaces", save.call_args.args[0]["metrics"])
        self.assertEqual(runner.call_args.kwargs["timeout"], 10)
        self.assertEqual(runner.call_args.kwargs["encoding"], "utf-8")
        self.assertEqual(runner.call_args.kwargs["errors"], "strict")

    def test_yfc_remote_false_green_ram_and_disk_denied_before_save(self):
        for field in ("ram_used_percent", "disk_used_percent"):
            sample = fixture("yfc")
            sample["metrics"][field] = 0
            runner = Mock(return_value=Mock(returncode=0, stdout=json.dumps(sample)))
            with self.subTest(field=field), \
                 patch.object(monitor, "endpoint", return_value=("example.test", 22)), \
                 patch.object(monitor, "require_file"), \
                 patch.object(monitor, "save") as save, \
                 self.assertRaises(monitor.PullError) as caught:
                monitor.pull(runner=runner)
            self.assertEqual(str(caught.exception), "invalid_or_out_of_order_remote_snapshot")
            self.assertEqual(runner.call_count, 1)
            save.assert_not_called()

    def test_wrong_host_or_source_denied_before_write(self):
        for sample in (
            fixture("hermes"),
            {**fixture("yfc"), "source": "forged"},
            {**fixture("yfc"), "observed_at": "2000-01-01T00:00:00Z"},
        ):
            runner = Mock(return_value=Mock(returncode=0, stdout=json.dumps(sample)))
            with patch.object(monitor, "endpoint", return_value=("example.test", 22)), \
                 patch.object(monitor, "require_file"), \
                 patch.object(monitor, "save") as save, \
                 self.assertRaises(monitor.PullError):
                monitor.pull(runner=runner)
            save.assert_not_called()

    def test_ssh_error_and_oversize_denied(self):
        for fake in (
            Mock(returncode=255, stdout="", stderr="PRIVATE-TOKEN"),
            Mock(returncode=0, stdout="z" * 30000),
            Mock(returncode=0, stdout="{garbage"),
        ):
            with patch.object(monitor, "endpoint", return_value=("example.test", 22)), \
                 patch.object(monitor, "require_file"), \
                 patch.object(monitor, "save") as save, \
                 self.assertRaises(monitor.PullError):
                monitor.pull(runner=Mock(return_value=fake))
            save.assert_not_called()

    def test_ssh_invalid_utf8_fails_closed_without_persisting_or_leaking(self):
        bad_decode = UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")
        for runner in (
            Mock(side_effect=bad_decode),
            Mock(return_value=Mock(
                returncode=0, stdout="\ud800", stderr="PRIVATE-TOKEN")),
        ):
            with self.subTest(kind="decode" if runner.side_effect else "encode"), \
                 patch.object(monitor, "endpoint", return_value=("example.test", 22)), \
                 patch.object(monitor, "require_file"), \
                 patch.object(monitor, "save") as save, \
                 self.assertRaises(monitor.PullError) as caught:
                monitor.pull(runner=runner)
            self.assertEqual(str(caught.exception), "ssh_invalid_encoding")
            self.assertEqual(runner.call_count, 1)
            save.assert_not_called()

    def test_network_timeout_and_failure(self):
        with patch.object(monitor, "endpoint", return_value=("example.test", 22)), \
             patch.object(monitor, "require_file"), \
             self.assertRaises(monitor.PullError):
            monitor.pull(runner=Mock(side_effect=subprocess.TimeoutExpired("ssh", 10)))

    def test_config_rejects_host_command_injection(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            for config in (
                {"host": "-oProxyCommand=sh", "port": 22},
                {"host": "example.org; touch /tmp/file", "port": 22},
                {"host": "example.org", "port": "22"},
                {"host": "example.org", "port": 22, "password": "secret"},
            ):
                path.write_text(json.dumps(config))
                with patch.object(monitor, "require_file"), \
                     self.assertRaises(monitor.PullError):
                    monitor.endpoint(path)


if __name__ == "__main__":
    unittest.main()
