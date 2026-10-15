"""Offline contract tests for the bounded Ops Incident Advisor."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ops_watch.incident_advisor import (
    CONTEXT_SCHEMA,
    SCENARIOS,
    AdvisorInputError,
    AdvisorOutputError,
    build_prompt,
    evaluate_result,
    mock_result,
    prepare_context,
    validate_result,
)
from scripts.ops_incident_advisor import _stage_files, docker_command, run_event


class IncidentAdvisorTests(unittest.TestCase):
    def test_valid_scenarios_are_bounded_and_preserve_only_input_facts(self) -> None:
        for name, event in SCENARIOS.items():
            if name in {"invalid_input", "prompt_injection"}:
                continue
            with self.subTest(name=name):
                context = prepare_context(event)
                self.assertEqual(context["schema"], CONTEXT_SCHEMA)
                self.assertTrue(context["evidence_catalog"])
                self.assertNotIn("operator_note", json.dumps(context))

    def test_invalid_and_prompt_injection_inputs_fail_before_agent(self) -> None:
        for name in ("invalid_input", "prompt_injection"):
            with self.subTest(name=name), self.assertRaises(AdvisorInputError):
                prepare_context(SCENARIOS[name])

    def test_prompt_has_no_free_text_or_secret_capability(self) -> None:
        context = prepare_context(SCENARIOS["provider_http_429"])
        prompt = build_prompt(context)
        self.assertIn("BEGIN_EVENT_CONTEXT", prompt)
        self.assertIn("HTTP_429", prompt)
        self.assertNotIn("Bearer", prompt)
        self.assertNotIn("operator_note", prompt)

    def test_mock_result_is_valid_and_reproducible(self) -> None:
        context = prepare_context(SCENARIOS["telegram_sender_down"])
        first = validate_result(json.dumps(mock_result(context), ensure_ascii=False), context)
        second = validate_result(json.dumps(mock_result(context), ensure_ascii=False), context)
        self.assertEqual(first, second)
        self.assertEqual(evaluate_result(context, first)["evidence_completeness"], 1.0)
        self.assertEqual(evaluate_result(context, first)["llm_quality"], "NOT_RUN")

    def test_evidence_not_in_event_is_rejected(self) -> None:
        context = prepare_context(SCENARIOS["systemd_timer_failed"])
        result = mock_result(context)
        result["evidence"] = ["invented log line"]
        with self.assertRaisesRegex(AdvisorOutputError, "evidence_not_in_event"):
            validate_result(result, context)

    def test_claimed_side_effect_is_rejected(self) -> None:
        context = prepare_context(SCENARIOS["systemd_timer_failed"])
        result = mock_result(context)
        result["recommendation"] = "Таймер перезапущен автоматически."
        with self.assertRaisesRegex(AdvisorOutputError, "unsafe_output_claim"):
            validate_result(result, context)

    def test_offline_engine_runs_the_same_contract_without_claiming_agent_execution(self) -> None:
        result = run_event(
            SCENARIOS["github_actions_failed"],
            scenario="github_actions_failed",
            engine="offline",
            image="unused",
        )
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["provider_status"], "MOCK_ONLY")
        self.assertEqual(result["model_calls"], 0)
        self.assertIn("NOT_RUN", result["agent_path"])

    def test_docker_command_is_loopback_only_and_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            _stage_files(Path(directory))
            command = " ".join(
                docker_command(Path(directory), "hermes-agent-v0221-native-tool-policy:20261015", "prompt")
            )
            config = (Path(directory) / "config.yaml").read_text(encoding="utf-8")
        self.assertIn("api_max_retries: 1", config)
        self.assertIn("auto_recovery_cycles: 0", config)
        self.assertIn("enabled: false", config)
        for expected in (
            "--network none",
            "--read-only",
            "--cap-drop ALL",
            "--security-opt no-new-privileges",
            "--pids-limit 96",
            "--cpus 0.30",
            "--memory 640m",
            "--memory-swap 896m",
            "--pull=never",
            "ops-incident-mock-v1",
            "-t",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, command)
        for forbidden in ("--network host", "docker.sock", "--env-file", "telegram", "second-brain"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, command.lower())

    @patch("scripts.ops_incident_advisor.subprocess.run")
    def test_docker_runner_requires_one_mock_request(self, runner) -> None:
        runner.return_value.returncode = 0
        runner.return_value.stdout = '{}\n__MOCK_REQUESTS__:2\n'
        runner.return_value.stderr = ""
        with self.assertRaisesRegex(RuntimeError, "model_call_budget_violation"):
            from scripts.ops_incident_advisor import _run_docker

            _run_docker(prepare_context(SCENARIOS["provider_http_429"]), "mock-image")


if __name__ == "__main__":
    unittest.main()
