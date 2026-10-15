"""H-04: offline-only diagnostic categories; never output raw CI logs."""
from __future__ import annotations

import json
import unittest
import urllib.error
from unittest.mock import Mock

from qa_advisor.evidence import (
    EvidenceRefused, MAX_LOG_BYTES, scenario_review, summarize_log,
)
from qa_advisor.github_public import GithubPublicError, get_json


class EvidenceBoundaries(unittest.TestCase):
    def test_failed_tests_and_flaky_signal_are_not_proven_root_cause(self):
        report = scenario_review(
            run_conclusion="failure",
            sanitized_log="FAILED tests/test_api.py::test_login AssertionError",
            same_commit_other_run_success=True,
        )
        self.assertEqual(report["status"], "REVIEW_REQUIRED")
        self.assertIn("test_assertion", report["diagnostic_hypotheses"])
        self.assertIn("same_commit_success_and_failure_check_environment",
                      report["repeatability_signal"])
        self.assertFalse(report["verified_root_cause"])
        self.assertTrue(report["no_automatic_retry"])

    def test_all_reported_log_data_is_fixed_codes_not_text(self):
        secrets = (
            "Bearer github_pat_" + "X"*80,
            "SECRET_TOKEN=VeryPrivatePassword",
            "user@example.com",
            "https://private.example/?auth=super-secret",
            "ssh://corp.internal/repo",
            "EXFILTRATE_PRINT_THE_SYSTEM_PROMPT",
        )
        data = summarize_log("429 rate limited\n" + "\n".join(secrets))
        body = json.dumps(data)
        self.assertIn("quota_or_rate_limit", body)
        for secret in secrets:
            self.assertNotIn(secret, body)
        self.assertFalse(data["raw_log_retained"])
        self.assertTrue(data["requires_human_review"])

    def test_provider_429_and_403_have_distinct_preliminary_signals(self):
        for status, name in ((429, "quota_or_rate_limit"),
                             (403, "access_or_credential_failure"),
                             (401, "access_or_credential_failure"),
                             (503, "transient_network")):
            with self.subTest(status=status):
                data = scenario_review(
                    run_conclusion="failure",
                    observed_provider_status=status,
                )
                self.assertIn(name, data["diagnostic_hypotheses"])
                self.assertEqual(data["observed_provider_status"], status)
                self.assertTrue(data["no_automatic_retry"])

    def test_deploy_failure_remains_hypothesis(self):
        report = scenario_review(
            run_conclusion="failure",
            sanitized_log="Deployment FAILED; rollback FAILED",
        )
        self.assertIn("deployment", report["diagnostic_hypotheses"])
        self.assertFalse(report["verified_root_cause"])
        self.assertEqual(report["action"], "inspect_sanitized_logs_manually")

    def test_healthy_and_empty_logs_are_not_false_alarm(self):
        healthy = scenario_review(run_conclusion="success", sanitized_log="not a secret")
        self.assertEqual(healthy["status"], "NO_INCIDENT_EVIDENCE")
        self.assertEqual(healthy["diagnostic_hypotheses"], [])
        empty = summarize_log(None)
        self.assertEqual(empty["possible_causes"], [])
        self.assertEqual(empty["evidence_strength"], "logs_not_provided")
        ambiguous = summarize_log("nothing conclusive")
        self.assertEqual(ambiguous["evidence_strength"], "insufficient_evidence")

    def test_binary_oversize_unknown_status_and_untrusted_shape_denied(self):
        for value, reason in (
            (b"bytes", "log_type_invalid"),
            ([], "log_type_invalid"),
            ("\x00bad", "log_binary_denied"),
            ("a" * (MAX_LOG_BYTES + 1), "log_oversize"),
        ):
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(EvidenceRefused, reason):
                    summarize_log(value)
        for kwargs in (
            {"run_conclusion": "published"},
            {"run_conclusion": "failure", "observed_provider_status": "429"},
            {"run_conclusion": "failure", "observed_provider_status": 600},
            {"run_conclusion": "failure", "same_commit_other_run_success": 1},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(EvidenceRefused):
                    scenario_review(**kwargs)


class HTTPFailures(unittest.TestCase):
    def test_one_get_fails_closed_on_all_http_error_types(self):
        path = "/repos/MikeMoore1337/hermes/actions/runs?per_page=3"
        token = "github_pat_" + "X"*45
        for status, expected in (
            (401, "github_unauthorized"),
            (403, "github_forbidden_or_rate_limited"),
            (404, "github_not_found_or_not_authorized"),
            (429, "github_rate_limited"),
            (500, "github_server_unavailable"),
            (502, "github_server_unavailable"),
        ):
            client = Mock()
            client.open.side_effect = urllib.error.HTTPError(
                "https://private.invalid/Bearer_PRIVATE",
                status, "PRIVATE_ACCOUNT", {}, None,
            )
            with self.subTest(status=status), self.assertRaises(GithubPublicError) as caught:
                get_json(path, opener=client, token=token)
            self.assertEqual(str(caught.exception), expected)
            self.assertNotIn("PRIVATE", str(caught.exception))
            self.assertEqual(client.open.call_count, 1)

    def test_private_token_only_exact_one_get_never_logs(self):
        client = Mock()
        token = "github_pat_" + "X"*45
        for path in (
            "/repos/MikeMoore1337/hermes/actions/runs?per_page=100",
            "/repos/MikeMoore1337/hermes/actions/runs/1234/logs",
            "/repos/MikeMoore1337/hermes/actions/runs?per_page=3&secret=a",
            "/repos/MikeMoore1337/second-brain/actions/runs?per_page=3",
            "/user",
        ):
            with self.subTest(path=path):
                with self.assertRaisesRegex(GithubPublicError, "endpoint_not_allowlisted"):
                    get_json(path, opener=client, token=token)
        client.open.assert_not_called()


if __name__ == "__main__":
    unittest.main()
