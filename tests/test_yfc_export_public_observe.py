"""YFC exporter is the only source used by the existing project watcher."""
from datetime import UTC, datetime, timedelta
import copy
import json
import unittest
from unittest.mock import MagicMock

from control_center import github_projects_view
from control_center.operator_inbox import assemble
from control_center.snapshot import UNITS
from qa_advisor import github_public, public_project_observe as obs


NOW = datetime(2026, 11, 26, 12, 45, tzinfo=UTC)
REPO = "MikeMoore1337/your-fitness-coach"
WORKFLOW_ID = 407410999
PATH = f"/repos/{REPO}/actions/workflows/github-observe-export.yml/runs?per_page=6"


def run(run_id, *, kind="issue_comment", action="created", subject=1366,
        outcome="none", conclusion="success", workflow_id=WORKFLOW_ID):
    name = f"observe:{kind}:{action}:{subject}:{outcome}:{run_id}"
    return {"id": run_id, "workflow_id": workflow_id, "event": kind,
            "repository": {"full_name": REPO}, "name": name, "display_title": name,
            "status": "completed", "conclusion": conclusion,
            "created_at": (NOW - timedelta(minutes=1)).isoformat(),
            "body": "PRIVATE_CONTENT_DO_NOT_EXPOSE"}


class YfcExportObserveTests(unittest.TestCase):
    def test_one_anonymous_exporter_call_and_matching_control_center_contract(self):
        calls = []
        def reader(path, *, token, timeout):
            calls.append((path, token, timeout))
            if path == PATH:
                return {"workflow_runs": [run(1), run(2)]}
            return {"workflow_runs": []}

        feed = obs.poll(now=NOW, reader=reader)
        yfc = feed["sources"]["yfc"]
        self.assertEqual(yfc["workflow_id"], WORKFLOW_ID)
        self.assertEqual(yfc["status"], "PARTIAL")
        self.assertEqual(len(yfc["events"]), 1)
        self.assertEqual(yfc["events"][0]["run_id"], 2)
        self.assertEqual([c for c in calls if REPO in c[0]], [(PATH, None, 2)])
        self.assertNotIn("PRIVATE_CONTENT", json.dumps(feed))
        self.assertIs(github_projects_view.validate(feed), feed)
        self.assertFalse(feed["execution_authorized"])
        self.assertEqual(feed["owner_approval"], "NOT_GRANTED")
        overview = {"schema": 1, "mode": "read_only", "generated_at": NOW.isoformat(),
                    "services": [{"id": ident, "name": label, "unit": unit, "kind": kind,
                                  "state": "active"} for ident, label, unit, kind in UNITS],
                    "github_project_feed": feed}
        inbox = assemble(overview, None, now=NOW)
        self.assertEqual(inbox["sources"]["gh_yfc"]["status"], "PARTIAL")
        self.assertEqual(inbox["sources"]["gh_yfc"]["details"],
                         "Последние 6 запусков GitHub Observe, до 5 событий; история неполная")
        self.assertEqual(len([x for x in inbox["events"] if x["source"] == "gh_yfc"]), 1)
        self.assertFalse(inbox["actions_enabled"])
        self.assertNotIn("PRIVATE_CONTENT", json.dumps(inbox))

    def test_fail_closed_on_wrong_identity_and_do_not_fall_back(self):
        calls = []
        def reader(path, *, token, timeout):
            calls.append(path)
            return {"workflow_runs": [run(4, workflow_id=WORKFLOW_ID + 1)]}
        result = obs._get_one("yfc", when=NOW, reader=reader)
        self.assertEqual(result["status"], "NOT_AVAILABLE")
        self.assertEqual(result["events"], [])
        self.assertEqual(calls, [PATH])

    def test_master_ci_failure_allowed_but_skipped_exporter_not_promoted(self):
        rows = [run(5, kind="workflow_run", action="completed", subject=101,
                    outcome="failure"),
                run(6, kind="workflow_run", action="completed", subject=102,
                    outcome="failure", conclusion="skipped")]
        result = obs._read_runs(REPO, WORKFLOW_ID, {"workflow_runs": rows}, NOW)
        self.assertEqual([(x["number"], x["candidate"]) for x in result["events"]],
                         [(101, "REVIEW_CI_FAILURE")])

    def test_conflicting_run_identity_is_rejected_but_consistent_repeats_collapse(self):
        first = run(7, subject=1366)
        conflict = run(7, subject=1427)
        with self.assertRaisesRegex(obs.PublicObserveError, "event_identity_conflict"):
            obs._read_runs(REPO, WORKFLOW_ID, {"workflow_runs": [first, conflict]}, NOW)
        repeated = obs._read_runs(REPO, WORKFLOW_ID, {"workflow_runs": [first, first]}, NOW)
        self.assertEqual(len(repeated["events"]), 1)
        distinct = obs._read_runs(REPO, WORKFLOW_ID,
                                  {"workflow_runs": [first, run(8, subject=1366)]}, NOW)
        self.assertEqual([(x["number"], x["run_id"]) for x in distinct["events"]], [(1366, 8)])

    def test_both_snapshot_validators_refuse_reused_run_id(self):
        def reader(path, *, token, timeout):
            return {"workflow_runs": [run(7)]} if path == PATH else {"workflow_runs": []}
        feed = obs.poll(now=NOW, reader=reader)
        bad = copy.deepcopy(feed)
        record = bad["sources"]["yfc"]
        record["inspected_count"] = 2
        record["events"].append({**record["events"][0], "number": 1427})
        for validator, error in ((obs.validate, obs.PublicObserveError),
                                 (github_projects_view.validate, github_projects_view.ProjectFeedRefused)):
            with self.subTest(validator=validator.__module__), self.assertRaises(error):
                validator(bad)

    def test_untrusted_metadata_refused_or_not_promoted(self):
        for changes in (
            {"repository": {"full_name": "other/private"}},
            {"workflow_id": True}, {"id": True},
            {"event": "issues"},
            {"created_at": (NOW + timedelta(minutes=5)).isoformat()},
        ):
            row = run(7)
            row.update(changes)
            with self.subTest(changes=changes), self.assertRaises(obs.PublicObserveError):
                obs._read_runs(REPO, WORKFLOW_ID, {"workflow_runs": [row]}, NOW)
        for title in ("arbitrary instructions", "observe:issues:opened:1:none:999"):
            row = run(7)
            row["name"] = row["display_title"] = title
            if title.startswith("observe:"):
                with self.assertRaises(obs.PublicObserveError):
                    obs._read_runs(REPO, WORKFLOW_ID, {"workflow_runs": [row]}, NOW)
            else:
                self.assertEqual(obs._read_runs(REPO, WORKFLOW_ID,
                                               {"workflow_runs": [row]}, NOW)["events"], [])

    def test_bounded_window_and_stale_snapshot(self):
        with self.assertRaises(obs.PublicObserveError):
            obs._read_runs(REPO, WORKFLOW_ID, {"workflow_runs": [run(i) for i in range(1, 8)]}, NOW)
        feed = obs.poll(now=NOW, reader=lambda path, token, timeout: {"workflow_runs": []})
        self.assertTrue(github_projects_view.fresh(feed, now=NOW))
        self.assertFalse(github_projects_view.fresh(feed, now=NOW + timedelta(minutes=46)))
        feed["sources"]["yfc"]["workflow_id"] = 259698256
        with self.assertRaises(github_projects_view.ProjectFeedRefused):
            github_projects_view.validate(feed)

    def test_exporter_http_is_anonymous_and_old_native_paths_denied(self):
        opener = MagicMock()
        response = MagicMock()
        response.status = 200
        response.read.return_value = b'{"workflow_runs": []}'
        response.__enter__.return_value = response
        opener.open.return_value = response
        self.assertEqual(github_public.get_json(PATH, opener=opener, timeout=2),
                         {"workflow_runs": []})
        self.assertEqual(opener.open.call_args.args[0].get_method(), "GET")
        for path in (f"/repos/{REPO}/events?per_page=20",
                     f"/repos/{REPO}/actions/workflows/ci.yml/runs?per_page=6"):
            with self.assertRaisesRegex(github_public.GithubPublicError,
                                        "endpoint_not_allowlisted"):
                github_public.get_json(path, opener=opener, timeout=2)
        with self.assertRaisesRegex(github_public.GithubPublicError, "github_token_scope_denied"):
            github_public.get_json(PATH, opener=opener, token="x" * 40, timeout=2)
        self.assertEqual(opener.open.call_count, 1)


if __name__ == "__main__":
    unittest.main()
