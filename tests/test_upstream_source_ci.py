"""Upstream source CI passing is not a release-image attestation."""
from __future__ import annotations

import io
import json
import unittest
from unittest.mock import patch

from scripts import verify_upstream_source_ci as checker
from scripts.verify_upstream_release_ci import ReleaseCIDenied


def source_fixture():
    jobs = []
    for name in checker.MANDATORY:
        jobs.append({"id": len(jobs) + 1, "name": name, "conclusion": "success"})
    for name in checker.NOT_RUN:
        jobs.append({"id": len(jobs) + 1, "name": name, "conclusion": "skipped"})
    for i in range(checker.EXPECTED_TOTAL - len(jobs)):
        jobs.append({"id": len(jobs) + 1, "name": f"Extra job {i}", "conclusion": "success"})
    run = {"id": checker.RUN_ID, "head_sha": checker.SOURCE_SHA,
           "name": "CI", "event": "push", "status": "completed",
           "conclusion": "success"}
    def fetch(path):
        if path == checker.ROOT + str(checker.RUN_ID):
            return run
        if path == checker.ROOT + str(checker.RUN_ID) + "/jobs?per_page=100&page=1":
            return {"total_count": checker.EXPECTED_TOTAL, "jobs": jobs}
        raise AssertionError("unexpected network route")
    return fetch, run, jobs


class SourceCIEvidenceTests(unittest.TestCase):
    def test_source_commit_passed_tests_but_image_is_not_verified(self):
        fetch, _, _ = source_fixture()
        result = checker.review(fetcher=fetch)
        self.assertEqual(result["status"], "SOURCE_CORE_CI_PASS_IMAGE_UNVERIFIED")
        self.assertEqual(result["source_ci_run_id"], checker.RUN_ID)
        self.assertTrue(result["selected_core_checks_passed"])
        self.assertTrue(result["selected_optional_checks_not_all_run"])
        self.assertFalse(result["release_docker_integration_tests_verified"])
        self.assertFalse(result["image_source_parity_verified"])
        self.assertFalse(result["complete_sbom_verified"])
        self.assertFalse(result["resident_agent_allowed"])

    def test_source_sha_or_event_mismatch_is_rejected(self):
        for key, val in (("head_sha", "a" * 40), ("event", "pull_request"),
                         ("conclusion", "failure"), ("name", "Different CI")):
            fetch, run, _ = source_fixture()
            run[key] = val
            with self.subTest(key=key):
                with self.assertRaisesRegex(
                    ReleaseCIDenied, "source_ci_run_identity_invalid",
                ):
                    checker.review(fetcher=fetch)

    def test_skipped_core_check_is_not_reported_as_passed(self):
        fetch, _, jobs = source_fixture()
        jobs[0]["conclusion"] = "skipped"
        result = checker.review(fetcher=fetch)
        self.assertEqual(result["status"], "SOURCE_CORE_CI_INCOMPLETE")
        self.assertFalse(result["source_code_ci_observed"])

    def test_missing_duplicate_or_incomplete_jobs_rejected(self):
        for variation in ("duplicate_id", "duplicate_name",
                          "missing", "wrong_total", "missing_required"):
            fetch, _, jobs = source_fixture()
            if variation == "duplicate_id":
                jobs[1]["id"] = jobs[0]["id"]
            elif variation == "duplicate_name":
                jobs[1]["name"] = jobs[0]["name"]
            elif variation == "missing":
                jobs.pop()
            elif variation == "missing_required":
                jobs[0]["name"] = "Unrelated test"
            def wrapper(path):
                out = fetch(path)
                if variation == "wrong_total" and "/jobs?" in path:
                    return {"total_count": 41, "jobs": jobs}
                return out
            with self.subTest(variation=variation):
                with self.assertRaises(ReleaseCIDenied):
                    checker.review(fetcher=wrapper)

    def test_default_is_completely_offline(self):
        with patch.object(checker, "review") as review:
            with patch("sys.stdout", new_callable=io.StringIO) as output:
                self.assertEqual(checker.main([]), 0)
            review.assert_not_called()
        self.assertEqual(json.loads(output.getvalue())["status"], "NOT_EXECUTED")

    def test_even_all_green_core_returns_exit_two(self):
        fetch, _, _ = source_fixture()
        with patch.object(checker, "review", return_value=checker.review(fetcher=fetch)):
            with patch("sys.stdout", new_callable=io.StringIO) as output:
                self.assertEqual(checker.main(["--execute"]), 2)
        self.assertFalse(json.loads(output.getvalue())["resident_agent_allowed"])

    def test_untrusted_error_is_never_echoed(self):
        with patch.object(checker, "review",
                          side_effect=ReleaseCIDenied("bearer_secret_DO_NOT_PRINT")):
            with patch("sys.stdout", new_callable=io.StringIO) as output:
                self.assertEqual(checker.main(["--execute"]), 2)
        self.assertEqual(json.loads(output.getvalue())["status"], "UNKNOWN")
        self.assertNotIn("secret", output.getvalue().lower())


if __name__ == "__main__":
    unittest.main()
