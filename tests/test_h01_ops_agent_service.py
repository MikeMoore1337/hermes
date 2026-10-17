"""H-01 limited resident Ops AI must remain event-driven and fail closed."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from ops_watch.incident_advisor import SCENARIOS
from scripts import h01_ops_agent_service as agent


def candidate(event_id: int = 12) -> dict:
    return {
        "event_id": event_id, "phase": "new",
        "analysis": {"decision": "ADVISOR_CANDIDATE"},
        "event": SCENARIOS["notification_queue_stopped"],
    }


class H01OpsContractTests(unittest.TestCase):
    def test_runtime_has_fixed_free_provider_and_no_native_tools(self):
        self.assertEqual(agent.MODEL, "@cf/openai/gpt-oss-20b")
        self.assertEqual(agent.MAX_CALLS_PER_UTC_DAY, 1)
        self.assertIn("max_turns: 1", agent.CLI_CONFIG)
        self.assertIn("auto_recovery_cycles: 0", agent.CLI_CONFIG)
        self.assertIn("memory_enabled: false", agent.CLI_CONFIG)
        self.assertNotIn("paid", agent.CLI_CONFIG.lower())
        with patch.object(agent.pwd, "getpwnam", return_value=Mock(pw_uid=10000, pw_gid=10000)):
            args = agent.docker_command(Path("/tmp/a"), "sha256:" + "a" * 64, "test")
        joined = " ".join(args)
        for rule in ("--network hermes-agent-isolated", "--ip 172.29.250.2",
                     "--read-only", "--cap-drop ALL", "no-new-privileges",
                     "--memory 640m", "--cpus 0.30", "-t bot_room",
                     "--pull=never"):
            self.assertIn(rule, joined)
        for bad in ("--privileged", "--network host", "docker.sock", "second-brain"):
            self.assertNotIn(bad, joined)

    def test_image_pin_malformed_or_accessible_fails_before_docker(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = Path(d) / "pin.env"
            with self.assertRaisesRegex(agent.H01Denied, "image_config_unavailable"):
                agent.safe_image(cfg)
            cfg.write_text("HERMES_AGENT_RUNTIME_IMAGE=latest\n", encoding="utf-8")
            cfg.chmod(0o600)
            with self.assertRaisesRegex(agent.H01Denied, "image_pin_invalid"):
                agent.safe_image(cfg)
            cfg.write_text("HERMES_AGENT_RUNTIME_IMAGE=sha256:" + "a" * 64, encoding="utf-8")
            cfg.chmod(0o644)
            with self.assertRaisesRegex(agent.H01Denied, "image_config_unavailable"):
                agent.safe_image(cfg)

    def test_resource_preflight_is_a_skip_not_a_failed_service(self):
        import io
        from contextlib import redirect_stdout
        with patch.object(agent, "run", side_effect=agent.H01Denied("load_above_operating_limit")):
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(agent.main(), 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["status"], "SKIPPED_PRECHECK")

    def test_no_event_never_calls_provider(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(agent, "STATE", Path(tmp) / "agent"), \
                 patch.object(agent, "verify_host"), patch.object(agent, "verify_credentials"), \
                 patch.object(agent, "safe_image", return_value="sha256:" + "a" * 64), \
                 patch.object(agent, "read_events", return_value=[]), \
                 patch.object(agent, "model_once") as provider:
                outcome = agent.run()
            self.assertEqual(outcome["status"], "NO_ADVISOR_CANDIDATE")
            provider.assert_not_called()

    def test_event_is_reserved_before_call_and_never_repeated(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "agent"
            with patch.object(agent, "STATE", state), \
                 patch.object(agent, "verify_host"), patch.object(agent, "verify_credentials"), \
                 patch.object(agent, "safe_image", return_value="sha256:" + "a" * 64), \
                 patch.object(agent, "read_events", return_value=[candidate()]), \
                 patch.object(agent, "model_once",
                              return_value={"status": "PASS", "result": {"priority": "high"}, "quality": "PASS"}) as provider:
                first = agent.run()
                second = agent.run()
            self.assertEqual(first["status"], "PASS")
            self.assertEqual(second["status"], "EVENT_ALREADY_HANDLED")
            self.assertEqual(provider.call_count, 1)
            saved = json.loads((state / "state.json").read_text(encoding="utf-8"))
            self.assertEqual(saved["calls"], 1)
            self.assertEqual(saved["last_event_id"], 12)

    def test_failed_call_is_still_consumed_and_not_retried(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "agent"
            with patch.object(agent, "STATE", state), \
                 patch.object(agent, "verify_host"), patch.object(agent, "verify_credentials"), \
                 patch.object(agent, "safe_image", return_value="sha256:" + "a" * 64), \
                 patch.object(agent, "read_events", return_value=[candidate()]), \
                 patch.object(agent, "model_once", side_effect=agent.H01Denied("agent_result_unverified")) as provider:
                with self.assertRaises(agent.H01Denied):
                    agent.run()
                self.assertEqual(agent.run()["status"], "EVENT_ALREADY_HANDLED")
            self.assertEqual(provider.call_count, 1)
            saved = json.loads((state / "state.json").read_text(encoding="utf-8"))
            self.assertEqual(saved["last_status"], "agent_result_unverified")

    def test_install_smoke_and_timer_cannot_exhaust_hourly_start_limit(self):
        """The real 2026-10-17 third start was blocked by a 2/hour systemd gate."""
        import re

        root = Path(__file__).resolve().parents[1]
        unit = (root / "deploy/hermes-h01-ops-agent.service").read_text(encoding="utf-8")
        timer = (root / "deploy/hermes-h01-ops-agent.timer").read_text(encoding="utf-8")

        def seconds(key, content, suffix=""):
            match = re.search(rf"^{key}=(\d+){suffix}$", content, re.MULTILINE)
            self.assertIsNotNone(match, key)
            return int(match.group(1))

        window = seconds("StartLimitIntervalSec", unit)
        burst = seconds("StartLimitBurst", unit)
        initial = seconds("OnActiveSec", timer, "min") * 60
        repeat = seconds("OnUnitInactiveSec", timer, "min") * 60

        self.assertEqual((window, burst), (3600, 2))
        # An installer may run the one-shot once just before enabling the timer.
        starts = [0, initial]
        for _ in range(6):
            starts.append(starts[-1] + repeat)
        for index, end in enumerate(starts):
            in_window = sum(0 <= end - start < window for start in starts[:index + 1])
            self.assertLessEqual(in_window, burst, f"run at {end}s exceeds start limit")

    def test_unit_and_timer_never_run_scheduled_shell_as_model(self):
        root = Path(__file__).resolve().parents[1]
        unit = (root / "deploy/hermes-h01-ops-agent.service").read_text(encoding="utf-8")
        timer = (root / "deploy/hermes-h01-ops-agent.timer").read_text(encoding="utf-8")
        self.assertIn("Type=oneshot", unit)
        self.assertIn("Restart=no", unit)
        self.assertIn("TimeoutStartSec=220", unit)
        self.assertIn("ExecStart=/usr/bin/python3 -m scripts.h01_ops_agent_service", unit)
        self.assertIn("StartLimitIntervalSec=3600", unit)
        self.assertIn("StartLimitBurst=2", unit)
        self.assertIn("OnUnitInactiveSec=35min", timer)
        self.assertIn("OnActiveSec=35min", timer)
        self.assertNotIn("OnBootSec=", timer)
        self.assertIn("Persistent=false", timer)
        self.assertNotIn("ExecStart=/bin/sh", unit)


if __name__ == "__main__":
    unittest.main()
