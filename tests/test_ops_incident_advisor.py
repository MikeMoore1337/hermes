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
from scripts.bounded_subprocess import BoundedProcessError
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

    def test_status_and_priority_cannot_contradict_input(self) -> None:
        context = prepare_context(SCENARIOS["healthy_no_publications"])
        result = mock_result(context)
        result["status"] = "active"
        with self.assertRaisesRegex(AdvisorOutputError, "status_conflicts_with_event"):
            validate_result(result, context)

        result = mock_result(context)
        result["priority"] = "critical"
        with self.assertRaisesRegex(AdvisorOutputError, "priority_overstates_event"):
            validate_result(result, context)

    def test_unconfirmed_cause_cannot_claim_low_uncertainty(self) -> None:
        context = prepare_context(SCENARIOS["provider_http_429"])
        result = mock_result(context)
        result["probable_cause"]["uncertainty"] = "low"
        with self.assertRaisesRegex(AdvisorOutputError, "cause_not_confirmed_by_event"):
            validate_result(result, context)

    def test_semantic_guard_does_not_require_fixed_mock_wording(self) -> None:
        context = prepare_context(SCENARIOS["provider_http_429"])
        result = mock_result(context)
        result["what_happened"] = "Зафиксировано ограничение провайдера."
        result["impact"] = "Возможна задержка обработки."
        result["probable_cause"] = {
            "summary": "Причина по входным данным не установлена.",
            "uncertainty": "high",
        }
        result["checks"] = ["Сверить окно ограничения без нового запроса."]
        result["recommendation"] = "Проверить сигнал операционно; автоматических действий не делать."
        self.assertEqual(validate_result(result, context)["status"], "active")

    def test_unsafe_diagnostic_action_is_rejected(self) -> None:
        context = prepare_context(SCENARIOS["provider_http_429"])
        result = mock_result(context)
        result["checks"] = ["Перезапустить провайдер"]
        with self.assertRaisesRegex(AdvisorOutputError, "unsafe_diagnostic_check"):
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

    @patch("scripts.ops_incident_advisor.run_bounded")
    def test_docker_runner_requires_one_mock_request(self, runner) -> None:
        runner.return_value.returncode = 0
        runner.return_value.stdout = b'{}\n__MOCK_REQUESTS__:2\n'
        runner.return_value.stderr = b""
        with self.assertRaisesRegex(RuntimeError, "model_call_budget_violation"):
            from scripts.ops_incident_advisor import _run_docker

            _run_docker(prepare_context(SCENARIOS["provider_http_429"]), "mock-image")

    @patch("scripts.ops_incident_advisor.run_bounded")
    def test_docker_runner_exposes_only_sanitized_bounded_error(self, runner) -> None:
        runner.side_effect = BoundedProcessError("output_limit_exceeded")
        from scripts.ops_incident_advisor import _run_docker

        with self.assertRaisesRegex(RuntimeError, "output_limit_exceeded") as caught:
            _run_docker(prepare_context(SCENARIOS["provider_http_429"]), "mock-image")
        self.assertNotIn("SECRET", str(caught.exception))

    @patch("scripts.ops_incident_advisor.run_bounded")
    def test_docker_runner_passes_stdout_stderr_and_wall_clock_limits(self, runner) -> None:
        runner.return_value.returncode = 1
        runner.return_value.stdout = b'{}\n__MOCK_REQUESTS__:1\n'
        runner.return_value.stderr = b""
        from scripts.ops_incident_advisor import _run_docker

        with self.assertRaisesRegex(RuntimeError, "agent_process_failed"):
            _run_docker(prepare_context(SCENARIOS["provider_http_429"]), "mock-image")
        kwargs = runner.call_args.kwargs
        self.assertEqual(kwargs["timeout"], 45)
        self.assertEqual(kwargs["stdout_limit"], 64 * 1024)
        self.assertEqual(kwargs["stderr_limit"], 16 * 1024)


class RulesOnlyDisplayTests(unittest.TestCase):
    def test_single_rules_only_result_displays_real_recommendation(self) -> None:
        import io
        from contextlib import redirect_stdout
        from scripts.ops_incident_advisor import _report
        output = io.StringIO()
        with redirect_stdout(output):
            _report({
                "status": "rules_only",
                "scenario": "ops_watch_event_1",
                "rules": {
                    "status": "resolved",
                    "priority": "low",
                    "recommendation": "Дополнительные действия не требуются",
                },
            })
        value = output.getvalue()
        self.assertIn("Дополнительные действия не требуются", value)
        self.assertIn("AI не нужен", value)
        self.assertNotIn("unknown", value)


if __name__ == "__main__":
    unittest.main()
