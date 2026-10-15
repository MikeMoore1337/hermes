"""H-04 main-branch quality.yml CI window: negative tests and no false recovery."""
from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from qa_advisor.ci_snapshot import (
    ALLOWLISTED_WORKFLOWS, SnapshotRefused, decide, inspect_once, main,
)
from qa_advisor.github_public import GithubPublicError, public_runs

REPO = "MikeMoore1337/hermes"
QUALITY = "workflow-381262090"
SHA = "a" * 40


def run(rid: int, status="completed", conclusion="success", workflow=QUALITY, repo=REPO):
    return {"repo": repo, "workflow": workflow, "run_id": rid,
            "head_sha": SHA, "status": status,
            "conclusion": conclusion,
            "jobs": []}


class RequiredMainCIReportTests(unittest.TestCase):
    def test_known_exact_quality_workflow_is_pinned_and_real(self):
        self.assertEqual(ALLOWLISTED_WORKFLOWS, frozenset({QUALITY}))

    def test_success_and_failure_and_old_run_ordering(self):
        cases = [
            (["failure", "success"], "SUCCESS", True),
            (["success", "failure"], "FAILURE", False),
            (["success", "startup_failure"], "FAILURE", False),
            (["success", "timed_out"], "FAILURE", False),
            (["failure", "cancelled"], "UNKNOWN", False),
        ]
        for conclusions, expected_status, recovered in cases:
            with self.subTest(conclusions=conclusions):
                a, b = conclusions
                result = decide([run(21, conclusion=b),run(20, conclusion=a)],
                                trusted_workflow_ids=ALLOWLISTED_WORKFLOWS)
                self.assertEqual(result["status"], expected_status)
                self.assertEqual(result["latest_run_success"], recovered)
                self.assertIs(result["verified_recovery"], False)
                self.assertEqual(result["run_id"], 21)

    def test_latest_pending_does_not_resolve_old_failure(self):
        got = decide([run(11, conclusion="failure"),
                      run(12, status="in_progress", conclusion=None)],
                     trusted_workflow_ids=ALLOWLISTED_WORKFLOWS)
        self.assertEqual(got["status"], "RUNNING")
        self.assertFalse(got["verified_recovery"])

    def test_untrusted_workflow_and_empty_results_are_unknown(self):
        for rows in (
            [],
            [run(11, workflow="workflow-123456789")],
            [run(11, repo="MikeMoore1337/your-fitness-coach")],
        ):
            with self.subTest(rows=len(rows)):
                got = decide(rows, trusted_workflow_ids=ALLOWLISTED_WORKFLOWS)
                self.assertEqual(got["status"], "UNKNOWN")
                self.assertEqual(got["verified_recovery"], False)

    def test_invalid_unverified_config_or_evidence_refused(self):
        for config in (frozenset(), set([QUALITY]), frozenset({"not-an-id"})):
            with self.subTest(config=str(config)):
                with self.assertRaises(SnapshotRefused):
                    decide([run(1)], trusted_workflow_ids=config)
        for rows in (None, 123, [run(i) for i in range(5)],
                     [{**run(1), "secret": "Bearer SECRET"}]):
            with self.subTest(type=type(rows).__name__):
                with self.assertRaises(SnapshotRefused):
                    decide(rows, trusted_workflow_ids=ALLOWLISTED_WORKFLOWS)

    def test_one_scope_exact_main_branch_and_no_write(self):
        calls=[]
        def fake_reader(repo,*,branch,token_file):
            calls.append((repo,branch,token_file))
            return [run(15,conclusion="failure")]
        got=inspect_once(reader=fake_reader)
        self.assertEqual(got["status"], "FAILURE")
        self.assertEqual(got["run_id"], 15)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][:2], (REPO,"main"))
        self.assertNotIn("private_data", str(got))

    def test_zero_auth_io_without_execute(self):
        with patch("qa_advisor.ci_snapshot.inspect_once") as client:
            with patch("sys.stdout", new_callable=io.StringIO) as out:
                self.assertEqual(main([]),0)
            self.assertIn('"NOT_EXECUTED"',out.getvalue())
            client.assert_not_called()

    def test_refused_private_api_does_not_produce_healthy_status(self):
        with patch("qa_advisor.ci_snapshot.inspect_once",
                   side_effect=GithubPublicError("github_forbidden_or_rate_limited")):
            with patch("sys.stdout", new_callable=io.StringIO) as out:
                self.assertEqual(main(["--execute"]),2)
            self.assertIn('"UNKNOWN"',out.getvalue())
            self.assertNotIn("SUCCESS",out.getvalue())

    def test_branch_selection_rejects_unknown_repos_before_auth(self):
        client=Mock()
        with self.assertRaisesRegex(GithubPublicError,"branch_not_allowlisted"):
            public_runs("MikeMoore1337/your-fitness-coach", branch="main", opener=client)
        with self.assertRaisesRegex(GithubPublicError,"branch_not_allowlisted"):
            public_runs(REPO, branch="../actions", opener=client)
        client.open.assert_not_called()

    def test_branch_main_get_is_exact_and_one(self):
        import json
        class Response:
            status=200
            def __enter__(self):return self
            def __exit__(self,*_):return False
            def read(self,_):return json.dumps({"workflow_runs":[{
               "id": 900,"workflow_id": 381262090,"head_sha":SHA,
               "status":"completed","conclusion":"success",
            }]}).encode()
        client=Mock()
        client.open.return_value=Response()
        with tempfile.TemporaryDirectory() as d:
            token=Path(d)/"token"
            token.write_text("github_pat_"+"X"*45,encoding="ascii")
            token.chmod(0o600)
            rows=public_runs(REPO,branch="main",opener=client,token_file=token)
        self.assertEqual(len(rows),1)
        self.assertEqual(client.open.call_count,1)
        request=client.open.call_args.args[0]
        self.assertEqual(request.get_method(),"GET")
        self.assertEqual(request.full_url,
             "https://api.github.com/repos/MikeMoore1337/hermes/actions/runs?branch=main&per_page=3")

if __name__ == "__main__":
    unittest.main()
