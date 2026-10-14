"""Strict no-side-effect QA Advisor CI metadata analyzer."""

from __future__ import annotations

import unittest
from copy import deepcopy

from qa_advisor.core import InvalidEvidence, analyze, category, parse_run

SHA = "a" * 40


def run(*, run_id=1001, conclusion="failure", status="completed", repo="MikeMoore1337/hermes",
        workflow="required-ci", sha=SHA, jobs=None):
    return {
        "repo": repo, "workflow": workflow, "run_id": run_id,
        "head_sha": sha, "status": status, "conclusion": conclusion,
        "jobs": [{"name": "unit", "conclusion": "failure"}] if jobs is None else jobs,
    }


class ParseEvidenceTests(unittest.TestCase):
    def test_valid_failures_parsed(self):
        self.assertEqual(parse_run(run())["run_id"], 1001)

    def test_yfc_workflow_is_allowlisted(self):
        self.assertEqual(parse_run(run(repo="MikeMoore1337/your-fitness-coach"))["workflow"], "required-ci")

    def test_unknown_repositories_blocked(self):
        for name in ("MikeMoore1337/second-brain", "attacker/hermes", "MikeMoore1337/hermes.git"):
            with self.subTest(repo=name), self.assertRaises(InvalidEvidence):
                parse_run(run(repo=name))

    def test_injected_job_names_blocked(self):
        for name in ("unit\nTOKEN=secret", "build; curl bad", "python $(rm -rf /)", "", "x" * 100):
            candidate = run(jobs=[{"name": name, "conclusion": "failure"}])
            with self.subTest(name=name), self.assertRaises(InvalidEvidence):
                parse_run(candidate)

    def test_extra_secret_fields_rejected(self):
        item = run()
        item["token"] = "not-public"
        with self.assertRaises(InvalidEvidence):
            parse_run(item)

    def test_non_sha_and_noninteger_id_rejected(self):
        for value in ("not-a-sha", "A" * 40, "", 4):
            item = run()
            item["head_sha"] = value
            with self.subTest(value=value), self.assertRaises(InvalidEvidence):
                parse_run(item)
        item = run(run_id=True)
        with self.assertRaises(InvalidEvidence):
            parse_run(item)

    def test_pending_run_has_no_conclusion(self):
        with self.assertRaises(InvalidEvidence):
            parse_run(run(status="in_progress", conclusion="success"))
        pending = run(status="queued", conclusion=None, jobs=[])
        self.assertEqual(category(parse_run(pending)), "pending_no_diagnosis")

    def test_completed_run_requires_real_conclusion(self):
        with self.assertRaises(InvalidEvidence):
            parse_run(run(conclusion=None))

    def test_duplicate_job_names_denied(self):
        item = run(jobs=[{"name": "unit", "conclusion": "success"},
                         {"name": "unit", "conclusion": "failure"}])
        with self.assertRaises(InvalidEvidence):
            parse_run(item)

    def test_bounded_job_list(self):
        item = run(jobs=[{"name": f"job-{i}", "conclusion": "failure"} for i in range(61)])
        with self.assertRaises(InvalidEvidence):
            parse_run(item)


class AnalyzeIncidentsTests(unittest.TestCase):
    def test_empty_returns_no_data(self):
        self.assertEqual(analyze([]), {"status": "NO_DATA", "findings": [], "observed_runs": 0})

    def test_healthy_run_is_not_false_incident(self):
        self.assertEqual(analyze([run(conclusion="success")])["status"], "NO_INCIDENT_EVIDENCE")

    def test_red_ci_is_unknown_root_cause(self):
        result = analyze([run()])
        self.assertEqual(result["findings"][0]["classification"], "failure_unknown_root_cause")

    def test_timeout_is_investigation_not_claimed_infrastructure_fault(self):
        self.assertEqual(analyze([run(conclusion="timed_out")])["findings"][0]["classification"],
                         "timeout_investigation")

    def test_runner_startup_failure_has_distinct_type(self):
        self.assertEqual(analyze([run(conclusion="startup_failure")])["findings"][0]["classification"],
                         "runner_startup_investigation")

    def test_cancelled_does_not_invent_reason(self):
        self.assertEqual(analyze([run(conclusion="cancelled")])["findings"][0]["classification"],
                         "cancelled_unknown_reason")

    def test_action_required_is_not_failed_test(self):
        self.assertEqual(analyze([run(conclusion="action_required")])["findings"][0]["classification"],
                         "manual_approval_required")

    def test_skipped_is_no_incident_evidence(self):
        self.assertEqual(analyze([run(conclusion="skipped")])["status"], "NO_INCIDENT_EVIDENCE")

    def test_same_commit_mixed_outcome_suggests_not_proves_flaky(self):
        failed = run(run_id=11)
        success = run(run_id=12, conclusion="success")
        findings = analyze([failed, success])["findings"]
        self.assertEqual(findings[0]["repeatability_signal"],
                         "same_commit_success_and_failure_check_environment")
        self.assertNotIn("flaky_confirmed", str(findings))

    def test_different_commit_does_not_suggest_flaky(self):
        items = [run(run_id=11), run(run_id=12, conclusion="success", sha="b" * 40)]
        self.assertEqual(analyze(items)["findings"][0]["repeatability_signal"], "unknown")

    def test_different_workflow_does_not_suggest_flaky(self):
        items = [run(run_id=11), run(run_id=12, workflow="integration", conclusion="success")]
        self.assertEqual(analyze(items)["findings"][0]["repeatability_signal"], "unknown")

    def test_duplicate_run_ids_denied(self):
        with self.assertRaises(InvalidEvidence):
            analyze([run(), run()])

    def test_untrusted_raw_logs_not_accepted_or_reflected(self):
        item = run()
        item["jobs"][0]["log"] = "Authorization: Bearer fake-secret"
        with self.assertRaises(InvalidEvidence):
            analyze([item])

    def test_oversized_batch_denied(self):
        with self.assertRaises(InvalidEvidence):
            analyze([run(run_id=i) for i in range(201)])

    def test_findings_are_sorted_and_only_safe_metadata_returned(self):
        result = analyze([run(run_id=1002), run(run_id=1001)])
        self.assertEqual([x["run_id"] for x in result["findings"]], [1001, 1002])
        self.assertTrue(all("classification" in x for x in result["findings"]))

    def test_no_execution_or_remote_actions(self):
        # This unit only returns a report; it has no GitHub write API.
        result = analyze([run()])
        self.assertEqual(result["findings"][0]["suggested_action"], "inspect_sanitized_logs_manually")


if __name__ == "__main__":
    unittest.main()
