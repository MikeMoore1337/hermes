"""#732: original YFC public events and existing CI, no YFC master changes."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
import io
import json
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from qa_advisor import github_public
from qa_advisor import public_project_observe as obs
from control_center import github_projects_view as view
from control_center.operator_inbox import assemble
from control_center.snapshot import UNITS

NOW = datetime(2026, 11, 2, 20, 55, tzinfo=UTC)
REPO = "MikeMoore1337/your-fitness-coach"


def event(kind, action, number, *, ident="25970819414", when=None):
    key = "pull_request" if kind == "PullRequestEvent" else "issue"
    return {
        "id": ident, "repo": {"name": REPO}, "type": kind,
        "payload": {key: {"number": number,
                         "title": "PRIVATE_USER_TITLE_MUST_NOT_LEAK"},
                    "action": action,
                    "body": "PRIVATE_USER_BODY_MUST_NOT_LEAK"},
        "created_at": (when or NOW - timedelta(minutes=4)).isoformat(),
        "actor": {"login": "PRIVATE_ACTOR_MUST_NOT_LEAK"},
    }


def run(number=4160011, *, conclusion="failure", workflow_id=obs.YFC_NATIVE_CI_ID,
        branch="dev", trigger="push", when=None):
    return {
        "id": number, "workflow_id": workflow_id,
        "repository": {"full_name": REPO},
        "head_repository": {"full_name": REPO},
        "name": "CI", "status": "completed", "conclusion": conclusion,
        "event": trigger, "head_branch": branch,
        "created_at": (when or NOW-timedelta(minutes=3)).isoformat(),
        "display_title": "PRIVATE_PR_TITLE_MUST_NOT_LEAK",
        "html_url": "https://untrusted.invalid/secret",
    }


def fixtures():
    return (
        {"events": [
            event("IssueCommentEvent", "created", 1366, ident="25970819414"),
            event("IssuesEvent", "opened", 1377, ident="25970819416"),
            event("PullRequestEvent", "ready_for_review", 1374, ident="25970819418"),
            event("PullRequestEvent", "merged", 1371, ident="25970819419"),
            event("PushEvent", "", 999, ident="25970819420"),
        ]},
        {"workflow_runs": [
            run(4160011, conclusion="failure"),
            run(4160012, conclusion="success", branch="master"),
            run(4160013, conclusion="cancelled", trigger="pull_request",
                branch="feat/920"),
        ]},
    )


def overview():
    return {
        "schema": 1, "mode": "read_only", "generated_at": NOW.isoformat(),
        "services": [
            {"id": ident, "name": label, "unit": unit, "kind": kind,
             "state": "blocked" if ident == "agent" else "active"}
            for ident, label, unit, kind in UNITS
        ],
    }


class NativeYfcPublicEventsTests(unittest.TestCase):
    def test_realistic_public_events_are_sanitized_and_bounded(self):
        events, ci = fixtures()
        result = obs._yfc_native_events(events, ci, NOW)
        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(result["inspected_count"], 8)
        self.assertEqual(len(result["events"]), 5)
        kinds = {item["kind"] for item in result["events"]}
        self.assertEqual(kinds, {"issues", "issue_comment", "pull_request_target", "workflow_run"})
        self.assertTrue(any(x["number"] == 1377 and x["candidate"] == "REVIEW_ISSUE"
                            for x in result["events"]))
        self.assertTrue(any(x["number"] == 4160011 and x["candidate"] == "REVIEW_CI_FAILURE"
                            for x in result["events"]))
        report = json.dumps(result)
        for forbidden in ("PRIVATE_USER", "PRIVATE_ACTOR", "untrusted.invalid", "merged"):
            self.assertNotIn(forbidden, report)

    def test_unexpected_repo_subject_id_future_and_ci_source_fail_closed(self):
        cases = (
            ({"repo": {"name": "other/secret"}}, "yfc_event_repo_invalid"),
            ({"id": True}, "yfc_event_id_invalid"),
            ({"id": "0"}, "yfc_event_id_invalid"),
            ({"payload": {"action": "created"}}, "yfc_event_subject_invalid"),
            ({"created_at": (NOW+timedelta(minutes=5)).isoformat()}, "yfc_event_in_future"),
        )
        for changes, reason in cases:
            with self.subTest(changes=changes):
                item = event("IssueCommentEvent", "created", 6)
                item.update(changes)
                with self.assertRaisesRegex(obs.PublicObserveError, reason):
                    obs._yfc_native_events({"events": [item]}, {"workflow_runs": []}, NOW)
        for changes in (
            {"workflow_id": 123}, {"workflow_id": True},
            {"repository": {"full_name": "other/secret"}},
            {"head_repository": {"full_name": "someone/fork"}},
            {"name": "Untrusted title"},
            {"created_at": (NOW+timedelta(minutes=5)).isoformat()},
        ):
            with self.subTest(ci_changes=changes):
                data = run()
                data.update(changes)
                with self.assertRaises(obs.PublicObserveError):
                    obs._yfc_native_events({"events": []}, {"workflow_runs": [data]}, NOW)

    def test_older_events_are_hidden_and_a_full_window_is_accepted(self):
        records = [event("IssuesEvent", "opened", number=100+i, ident=str(25970819401+i))
                   for i in range(20)]
        ci = [run(number=4160000+i, conclusion="success") for i in range(6)]
        result = obs._yfc_native_events({"events": records}, {"workflow_runs": ci}, NOW)
        self.assertEqual(result["inspected_count"], 26)
        self.assertEqual(len(result["events"]), obs.MAX_EVENTS)
        self.assertNotIn("PRIVATE_USER", json.dumps(result))
        stale = event("IssuesEvent", "opened", 1999,
                      ident="25970819999", when=NOW-timedelta(hours=30))
        out = obs._yfc_native_events({"events": [stale]}, {"workflow_runs": []}, NOW)
        self.assertEqual(out["events"], [])
        with self.assertRaisesRegex(obs.PublicObserveError, "yfc_native_window_invalid"):
            obs._yfc_native_events({"events": records+[records[0]]},
                                   {"workflow_runs": []}, NOW)

    def test_native_yfc_uses_two_anonymous_fixed_paths_and_preserves_toolkit(self):
        calls = []
        pub, ci = fixtures()
        def reader(path, *, token, timeout):
            calls.append((path, token, timeout))
            if path == obs.YFC_EVENTS_PATH:
                return pub
            if path == obs.YFC_CI_PATH:
                return ci
            if path.endswith("ai-development-toolkit/actions/workflows/"
                             "github-observe-export.yml/runs?per_page=6"):
                return {"workflow_runs": []}
            raise AssertionError("unexpected network call")
        result = obs.poll(now=NOW, reader=reader)
        self.assertEqual(len(calls), 3)
        self.assertTrue(all(token is None and timeout == 2 for _,token,timeout in calls))
        self.assertEqual({path for path,_,_ in calls},
                         {obs.YFC_EVENTS_PATH, obs.YFC_CI_PATH,
                          "/repos/MikeMoore1337/ai-development-toolkit/actions/"
                          "workflows/github-observe-export.yml/runs?per_page=6"})
        self.assertEqual(result["sources"]["yfc"]["status"], "PARTIAL")
        self.assertEqual(result["sources"]["toolkit"]["status"], "PARTIAL")
        self.assertEqual(result["sources"]["second_brain"]["status"], "NOT_AVAILABLE")
        self.assertEqual(result["sources"]["yfc"]["workflow_id"], 259698256)
        self.assertEqual(view.validate(result), result)
        payload = overview()
        payload["github_project_feed"] = result
        inbox = assemble(payload, None, now=NOW)
        self.assertEqual(inbox["sources"]["gh_yfc"]["status"], "PARTIAL")
        self.assertEqual(inbox["sources"]["gh_toolkit"]["status"], "PARTIAL")
        self.assertEqual(inbox["sources"]["gh_second_brain"]["status"], "NOT_AVAILABLE")
        self.assertFalse(inbox["actions_enabled"])
        self.assertTrue(any(r["source"] == "gh_yfc" for r in inbox["events"]))
        for secret in ("PRIVATE_USER", "PRIVATE_ACTOR", "untrusted.invalid"):
            self.assertNotIn(secret, json.dumps(inbox))
        after = assemble(payload, None, now=NOW+timedelta(minutes=46))
        self.assertEqual(after["sources"]["gh_yfc"]["status"], "STALE")
        self.assertFalse(any(r["source"] == "gh_yfc" and
                             r["event_id"] != "gh_yfc:stale" for r in after["events"]))

    def test_partial_public_network_failure_returns_not_available(self):
        pub, ci = fixtures()
        def reader(path, *, token, timeout):
            if path == obs.YFC_EVENTS_PATH:
                raise github_public.GithubPublicError("public_api_network_error")
            return ci
        result = obs._get_yfc_native(when=NOW, reader=reader)
        self.assertEqual(result["status"], "NOT_AVAILABLE")
        self.assertEqual(result["events"], [])
        self.assertEqual(result["inspected_count"], 0)

    def test_exact_public_http_endpoints_accept_anonymous_get_only(self):
        opener = MagicMock()
        response = MagicMock()
        response.status = 200
        response.read.return_value = json.dumps([event("IssuesEvent", "opened", 1377)]).encode()
        response.__enter__.return_value = response
        opener.open.return_value = response
        parsed = github_public.get_json(obs.YFC_EVENTS_PATH, token=None,
                                        timeout=2, opener=opener)
        self.assertEqual(len(parsed["events"]), 1)
        self.assertEqual(opener.open.call_args.args[0].get_method(), "GET")
        for denied in (
            obs.YFC_EVENTS_PATH+"&page=2",
            obs.YFC_EVENTS_PATH.replace("your-fitness-coach","second-brain"),
            obs.YFC_CI_PATH+"&per_page=200",
        ):
            with self.subTest(path=denied):
                with self.assertRaisesRegex(github_public.GithubPublicError,
                                             "endpoint_not_allowlisted"):
                    github_public.get_json(denied, token=None, opener=opener)
        with self.assertRaisesRegex(github_public.GithubPublicError,
                                     "github_token_scope_denied"):
            github_public.get_json(obs.YFC_EVENTS_PATH,
                                   token="github_pat_"+"x"*40, opener=opener)
        self.assertEqual(opener.open.call_count, 1)

    def test_response_rejects_raw_strings_and_unbounded_lists(self):
        opener = MagicMock()
        response = MagicMock()
        response.status = 200
        response.__enter__.return_value = response
        opener.open.return_value = response
        for payload in ({}, ["x"]*21):
            with self.subTest(payload_type=type(payload)):
                response.read.return_value = json.dumps(payload).encode()
                with self.assertRaises(github_public.GithubPublicError):
                    github_public.get_json(obs.YFC_EVENTS_PATH, token=None,
                                           opener=opener, timeout=2)


if __name__ == "__main__":
    unittest.main()
