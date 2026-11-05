"""H772 ReleaseGuard: offline contract, risk decisions and negative security tests."""
from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta
import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout

from qa_advisor.release_guard import (
    ReleaseEvidenceRefused, SCHEMA, evaluate, main,
)

SHA = "a" * 40
OLD = "b" * 40
NOW = datetime(2026, 11, 5, 9, 0, tzinfo=UTC)
REPO = "MikeMoore1337/hermes"


def evidence(*, stage="PR", repo=REPO):
    target = "dev" if repo.endswith("your-fitness-coach") and stage == "PR" else (
        "master" if repo.endswith("your-fitness-coach") else "main"
    )
    return {
        "schema": SCHEMA, "repo": repo, "stage": stage, "branch": target,
        "candidate_sha": SHA, "observed_head_sha": SHA,
        "observed_at": "2026-11-05T08:55:00Z",
        "required_workflows": [381262090],
        "checks": [{
            "workflow_id": 381262090, "run_id": 12345, "head_sha": SHA,
            "status": "completed", "conclusion": "success",
        }],
        "review": (
            {"state": "approved", "head_sha": SHA} if stage == "PR"
            else {"state": "not_applicable", "head_sha": None}
        ),
        "mergeability": "clean" if stage == "PR" else "not_applicable",
        "draft": False if stage == "PR" else None,
    }


def check(raw):
    return evaluate(raw, now=NOW)


class ReleaseGuardTests(unittest.TestCase):
    def test_green_is_precheck_only_never_production_go(self):
        result = check(evidence())
        self.assertEqual(result["status"], "READY_FOR_OWNER_REVIEW")
        self.assertEqual(result["reasons"], [])
        self.assertEqual(result["owner_approval"], "NOT_GRANTED")
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["deploy_authorized"])
        self.assertFalse(result["evidence_verified"])
        self.assertFalse(result["required_workflow_policy_verified"])
        self.assertEqual(result["production_evidence"], "NOT_VERIFIED")
        self.assertEqual(result["candidate_sha"], SHA)
        self.assertEqual(result["required_count"], 1)
        self.assertEqual(result["evidence_urls"], [
            "https://github.com/MikeMoore1337/hermes/actions/runs/12345",
        ])

    def test_release_and_yfc_branch_policy(self):
        self.assertEqual(check(evidence(stage="RELEASE"))["status"], "READY_FOR_OWNER_REVIEW")
        yfc = check(evidence(stage="RELEASE", repo="MikeMoore1337/your-fitness-coach"))
        self.assertEqual(yfc["status"], "INCONCLUSIVE")
        self.assertIn("yfc_dev_to_master_gate_not_verified", yfc["reasons"])
        self.assertEqual(check(evidence(repo="MikeMoore1337/your-fitness-coach"))["status"],
                         "READY_FOR_OWNER_REVIEW")

    def test_required_check_failure_is_blocked(self):
        for conclusion in ("failure", "startup_failure", "timed_out", "action_required"):
            with self.subTest(conclusion=conclusion):
                raw = evidence()
                raw["checks"][0]["conclusion"] = conclusion
                result = check(raw)
                self.assertEqual(result["status"], "BLOCKED")
                self.assertIn("required_check_failed", result["reasons"])

    def test_nonproving_or_pending_ci_is_inconclusive(self):
        for conclusion in ("cancelled", "neutral", "skipped"):
            with self.subTest(conclusion=conclusion):
                raw = evidence()
                raw["checks"][0]["conclusion"] = conclusion
                self.assertIn("required_check_not_proving", check(raw)["reasons"])
        for status in ("queued", "in_progress"):
            with self.subTest(status=status):
                raw = evidence()
                raw["checks"][0].update(status=status, conclusion=None)
                self.assertIn("required_check_pending", check(raw)["reasons"])

    def test_missing_workflow_never_becomes_green(self):
        raw = evidence()
        raw["checks"] = []
        self.assertEqual(check(raw)["status"], "INCONCLUSIVE")
        self.assertIn("required_check_missing", check(raw)["reasons"])

    def test_branch_sha_and_ci_sha_mismatches(self):
        for key, reason in (("observed_head_sha", "branch_sha_mismatch"),
                            ("check_head_sha", "check_sha_mismatch")):
            raw = evidence()
            if key == "observed_head_sha":
                raw[key] = OLD
            else:
                raw["checks"][0]["head_sha"] = OLD
            self.assertEqual(check(raw)["status"], "INCONCLUSIVE")
            self.assertIn(reason, check(raw)["reasons"])

    def test_unknown_head_and_stale_or_future_evidence(self):
        raw = evidence()
        raw["observed_head_sha"] = None
        self.assertIn("branch_head_unknown", check(raw)["reasons"])
        raw = evidence()
        raw["observed_at"] = "2026-11-05T06:00:00Z"
        self.assertIn("stale_evidence", check(raw)["reasons"])
        raw["observed_at"] = "2026-11-05T09:03:00Z"
        self.assertIn("future_evidence", check(raw)["reasons"])

    def test_pr_review_conflict_and_draft(self):
        for field, value, expected in (
            ("draft", True, "draft_pr"),
            ("mergeability", "dirty", "merge_conflict"),
            ("mergeability", "unknown", "mergeability_unknown"),
            ("review_state", "pending", "review_pending"),
            ("review_state", "changes_requested", "changes_requested"),
            ("review_state", "unknown", "review_unknown"),
        ):
            with self.subTest(field=field, value=value):
                raw = evidence()
                if field == "review_state":
                    raw["review"]["state"] = value
                else:
                    raw[field] = value
                self.assertIn(expected, check(raw)["reasons"])
        raw = evidence()
        raw["review"]["head_sha"] = OLD
        self.assertIn("review_sha_not_verified", check(raw)["reasons"])

    def test_priority_blocked_over_inconclusive(self):
        raw = evidence()
        raw["draft"] = True
        raw["checks"] = []
        result = check(raw)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["reasons"], ["draft_pr", "required_check_missing"])

    def test_forbid_new_fields_for_authorization_and_user_text(self):
        for field in ("owner_approval", "execution_authorized", "description", "token"):
            raw = evidence()
            raw[field] = "GRANTED"
            with self.subTest(field=field), self.assertRaisesRegex(
                ReleaseEvidenceRefused, "evidence_shape_invalid"
            ):
                check(raw)

    def test_invalid_identifiers_and_types_fail_closed(self):
        cases = [
            ("repo", "other/repo"),
            ("repo", "MikeMoore1337/HERMES"),
            ("candidate_sha", "not-a-sha"),
            ("candidate_sha", "A" * 40),
            ("candidate_sha", None),
            ("observed_head_sha", "x"),
            ("branch", "master"),
            ("stage", "AUTO_DEPLOY"),
            ("required_workflows", []),
            ("required_workflows", [True]),
            ("required_workflows", [381262090, 381262090]),
            ("required_workflows", list(range(1, 18))),
            ("checks", [1]),
            ("checks", [{}]),
            ("checks", [{"workflow_id": True}]),
            ("mergeability", "approved"),
            ("draft", "false"),
            ("observed_at", "not-a-date"),
            ("observed_at", "2026-11-05T08:55:00+03:00"),
        ]
        for key, value in cases:
            with self.subTest(key=key, value=str(value)[:35]):
                raw = evidence()
                raw[key] = value
                with self.assertRaises(ReleaseEvidenceRefused):
                    check(raw)

    def test_check_states_and_duplicate_runs_fail_closed(self):
        mutations = [
            {"status": "completed", "conclusion": None},
            {"status": "in_progress", "conclusion": "success"},
            {"status": "done", "conclusion": "success"},
            {"status": "completed", "conclusion": "hacked"},
            {"status": "completed", "conclusion": ["success"]},
            {"workflow_id": 0},
            {"workflow_id": True},
            {"run_id": -1},
            {"run_id": True},
            {"head_sha": OLD.upper()},
        ]
        for changed in mutations:
            with self.subTest(changed=changed):
                raw = evidence()
                raw["checks"][0].update(changed)
                with self.assertRaises(ReleaseEvidenceRefused):
                    check(raw)
        raw = evidence()
        raw["checks"].append(deepcopy(raw["checks"][0]))
        with self.assertRaisesRegex(ReleaseEvidenceRefused, "duplicate_workflow_invalid"):
            check(raw)

    def test_release_only_accepts_explicit_not_applicable(self):
        raw = evidence(stage="RELEASE")
        raw["draft"] = False
        with self.assertRaisesRegex(ReleaseEvidenceRefused, "release_evidence_invalid"):
            check(raw)
        raw = evidence(stage="RELEASE")
        raw["review"]["state"] = "approved"
        with self.assertRaisesRegex(ReleaseEvidenceRefused, "release_evidence_invalid"):
            check(raw)

    def test_clock_fail_closed(self):
        with self.assertRaisesRegex(ReleaseEvidenceRefused, "clock_invalid"):
            evaluate(evidence(), now=datetime(2026, 11, 5))
        with self.assertRaisesRegex(ReleaseEvidenceRefused, "clock_invalid"):
            evaluate(evidence(), now="2026-11-05")

    def test_safe_cli_is_inert_without_input_and_refuses_symlink(self):
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(main([]), 0)
        self.assertEqual(json.loads(output.getvalue()), {"status": "NOT_EXECUTED"})
        with tempfile.TemporaryDirectory() as directory:
            filename = Path(directory) / "evidence.json"
            filename.write_text(json.dumps(evidence()), encoding="utf-8")
            output = io.StringIO()
            with redirect_stdout(output):
                code = main(["--input", str(filename)])
            report = json.loads(output.getvalue())
            # The fixture time is historical at runtime; never call it live-ready.
            self.assertEqual(code, 2)
            self.assertEqual(report["status"], "INCONCLUSIVE")
            link = Path(directory) / "alias.json"
            link.symlink_to(filename)
            output = io.StringIO()
            with redirect_stdout(output):
                code = main(["--input", str(link)])
            self.assertEqual(code, 2)
            self.assertEqual(json.loads(output.getvalue())["status"], "REFUSED")


if __name__ == "__main__":
    unittest.main()
