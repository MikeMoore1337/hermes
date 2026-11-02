"""#732: bounded anonymous GitHub Actions metadata, independent of Hermes PAT."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from qa_advisor import public_project_observe as obs

NOW = datetime(2026, 11, 2, 10, 30, tzinfo=UTC)
ID = 314159265


def run(repo, run_id=9001, *, kind="issues", action="opened", subject=120,
        outcome="none", workflow_id=ID, status="completed",
        conclusion="success", name=None, when=None):
    fixed = f"observe:{kind}:{action}:{subject}:{outcome}:{run_id}"
    return {
        "repository": {"full_name": repo},
        "workflow_id": workflow_id,
        "id": run_id, "event": kind,
        "status": status, "conclusion": conclusion,
        "name": fixed if name is None else name,
        "display_title": fixed if name is None else name,
        "created_at": (when or NOW-timedelta(minutes=1)).isoformat(),
        "head_commit": {"message": "DO_NOT_INCLUDE_A_SECRET"},
        "html_url": "https://untrusted.example/private",
        "token": "DO_NOT_INCLUDE_A_SECRET",
    }


def source(key, **kwargs):
    return run(obs.PROJECTS[key][0], **kwargs)


class PublicObserveTests(unittest.TestCase):
    def setUp(self):
        # CI never has to talk to GitHub or inspect unrelated repositories.
        self.original = dict(obs.PROJECTS)
        obs.PROJECTS.update({key: (repo, ID+i)
                             for i, (key, (repo, _)) in enumerate(self.original.items())})
        self.addCleanup(lambda: (obs.PROJECTS.clear(), obs.PROJECTS.update(self.original)))

    def test_public_repo_events_are_sanitized(self):
        repo, workflow_id = obs.PROJECTS["toolkit"]
        data = {"workflow_runs": [
            run(repo, 1, workflow_id=workflow_id, kind="issues", action="opened"),
            run(repo, 2, workflow_id=workflow_id, kind="issue_comment",
                action="created", subject=121),
            run(repo, 3, workflow_id=workflow_id, kind="pull_request_target",
                action="synchronize", subject=122),
            run(repo, 4, workflow_id=workflow_id, kind="workflow_run",
                action="completed", subject=123, outcome="failure"),
            run(repo, 5, workflow_id=workflow_id, kind="workflow_run",
                action="completed", subject=124, outcome="success"),
        ]}
        parsed = obs._read_runs(repo, workflow_id, data, NOW)
        self.assertEqual(parsed["status"], "PARTIAL")
        self.assertEqual(len(parsed["events"]), 4)
        self.assertEqual({x["candidate"] for x in parsed["events"]}, {
            "REVIEW_ISSUE", "REVIEW_FOLLOWUP", "REVIEW_PR", "REVIEW_CI_FAILURE"
        })
        report = json.dumps(parsed)
        self.assertNotIn("DO_NOT_INCLUDE_A_SECRET", report)
        self.assertNotIn("untrusted.example", report)

    def test_invalid_repo_workflow_or_id_refuses_scope(self):
        repo, workflow_id = obs.PROJECTS["yfc"]
        for update in ({"workflow_id": workflow_id+2},
                       {"workflow_id": True},
                       {"repository": {"full_name": "other/private"}},
                       {"id": True},
                       {"event": "pull_request_target"},
                       {"name": "observe:issues:opened:120:none:2",
                        "display_title": "observe:issues:opened:120:none:2"},
                       {"created_at": (NOW+timedelta(minutes=5)).isoformat()}):
            with self.subTest(update=update):
                row = run(repo, workflow_id=workflow_id)
                row.update(update)
                with self.assertRaises(obs.PublicObserveError):
                    obs._read_runs(repo, workflow_id, {"workflow_runs": [row]}, NOW)

    def test_old_untrusted_titles_and_failed_runs_never_promote(self):
        repo, wf = obs.PROJECTS["second_brain"]
        source_rows = {"workflow_runs": [
            run(repo, 33, workflow_id=wf, name="run arbitrary shell"),
            run(repo, 34, workflow_id=wf, status="completed", conclusion="failure"),
            run(repo, 35, workflow_id=wf, status="in_progress", conclusion=None),
            run(repo, 36, workflow_id=wf, when=NOW-timedelta(days=3)),
        ]}
        self.assertEqual(obs._read_runs(repo, wf, source_rows, NOW)["events"], [])

    def test_duplicate_issue_events_latest_wins(self):
        repo, wf = obs.PROJECTS["toolkit"]
        rows = {"workflow_runs": [
            run(repo, 10, workflow_id=wf),
            run(repo, 14, workflow_id=wf),
            run(repo, 12, workflow_id=wf, kind="issue_comment", action="created"),
        ]}
        result = obs._read_runs(repo, wf, rows, NOW)
        self.assertEqual(len(result["events"]), 2)
        self.assertEqual(result["events"][0]["run_id"], 14)

    def test_poll_is_anonymous_fixed_allowlist_and_bounded(self):
        calls = []
        def client(path, *, token, timeout):
            calls.append((path, token, timeout))
            # Identify repository from allowlisted, known path only.
            for repo, wid in obs.PROJECTS.values():
                if path.startswith(f"/repos/{repo}/"):
                    return {"workflow_runs": [run(repo, workflow_id=wid)]}
            raise AssertionError("unexpected request")
        result = obs.poll(now=NOW, reader=client)
        self.assertEqual(len(calls), 3)
        self.assertTrue(all(token is None and timeout == 2 for _,token,timeout in calls))
        self.assertTrue(all(path.endswith("/actions/workflows/github-observe-export.yml/runs?per_page=6")
                            for path,_,_ in calls))
        self.assertEqual({x["status"] for x in result["sources"].values()}, {"PARTIAL"})
        self.assertFalse(result["execution_authorized"])
        self.assertEqual(result["owner_approval"], "NOT_GRANTED")

    def test_unavailable_source_does_not_disable_other_projects(self):
        def client(path, *, token, timeout):
            if "/second-brain/" in path:
                from qa_advisor.github_public import GithubPublicError
                raise GithubPublicError("github_rate_limited")
            for repo,wid in obs.PROJECTS.values():
                if f"/repos/{repo}/" in path:
                    return {"workflow_runs": [run(repo,workflow_id=wid)]}
            raise AssertionError("unexpected route")
        value = obs.poll(now=NOW,reader=client)
        self.assertEqual(value["sources"]["second_brain"]["status"], "NOT_AVAILABLE")
        self.assertEqual(value["sources"]["second_brain"]["events"], [])
        self.assertEqual(value["sources"]["toolkit"]["status"], "PARTIAL")
        self.assertEqual(value["sources"]["yfc"]["status"], "PARTIAL")

    def test_disabled_source_never_makes_network_request(self):
        repo,_ = obs.PROJECTS["second_brain"]
        obs.PROJECTS["second_brain"] = (repo, 0)
        requests=[]
        def reader(path, *, token, timeout):
            requests.append(path)
            for other,wid in obs.PROJECTS.values():
                if f"/repos/{other}/" in path:
                    return {"workflow_runs": []}
            raise AssertionError("unexpected")
        value=obs.poll(now=NOW,reader=reader)
        self.assertEqual(len(requests),2)
        self.assertEqual(value["sources"]["second_brain"]["status"],"NOT_AVAILABLE")
        self.assertEqual(value["sources"]["second_brain"]["workflow_id"],0)

    def test_secure_save_with_pinned_state_directory(self):
        item=obs.poll(now=NOW,reader=lambda path,token,timeout: {"workflow_runs":[]})
        with tempfile.TemporaryDirectory() as name:
            directory=Path(name)
            directory.chmod(0o700)
            self.assertEqual(obs.save(item,directory=directory),
                             "STORED_PUBLIC_PROJECT_OBSERVATIONS")
            file=directory/obs.FILE
            self.assertEqual(file.stat().st_mode&0o777,0o600)
            self.assertNotIn("token",file.read_text())
            directory.chmod(0o755)
            with self.assertRaises(ValueError):
                obs.save(item,directory=directory)

    def test_schema_rejects_bogus_approval_and_injected_text(self):
        report=obs.poll(now=NOW,reader=lambda path,token,timeout: {"workflow_runs":[]})
        candidates=(
            {**report,"execution_authorized":True},
            {**report,"owner_approval":"GRANTED"},
            {**report,"unknown":"sensitive"},
            {**report,"sources":{**report["sources"],"vault":{"status":"PARTIAL"}}},
        )
        for case in candidates:
            with self.assertRaises(obs.PublicObserveError):
                obs.validate(case)


if __name__ == "__main__":
    unittest.main()
