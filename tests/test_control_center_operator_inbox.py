"""#468 protected read-only inbox projection: scope, no false green, stale/dedup."""
from __future__ import annotations

import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path

from control_center.operator_inbox import (
    InboxUnavailable, MAX_EVENTS, assemble, load_overview,
)
from control_center.snapshot import UNITS
from qa_advisor.github_observe_feed import from_runs, OBSERVE_WORKFLOW_ID, OBSERVE_WORKFLOW

NOW = dt.datetime(2026, 10, 22, 12, 0, tzinfo=dt.timezone.utc)


def fixture(states=None, *, age_seconds=20):
    choices = states or {}
    return {"schema": 1, "mode": "read_only",
            "generated_at": (NOW-dt.timedelta(seconds=age_seconds)).isoformat(),
            "services": [
                {"id": ident, "name": name, "unit": unit, "kind": kind,
                 "state": choices.get(ident, "blocked" if ident == "agent" else "active")}
                for ident, name, unit, kind in UNITS],
            "agent_policy": "do not copy this unverified text into the inbox"}


def scheduler(counts=None, *, queue_state="available"):
    return {"schema": 1, "mode": "read_only", "queue_state": queue_state,
            "counts": {"queued": 0, "deferred": 0, "running": 0,
                       "blocked": 0, "completed": 0, **(counts or {})},
            "jobs": [{"job_id": "secret-id-do-not-echo",
                      "wait_reason": "token=never-echo"}]}


class InboxTests(unittest.TestCase):
    def test_source_coverage_not_fabricated(self):
        result = assemble(fixture(), scheduler(), now=NOW)
        self.assertEqual(result["mode"], "read_only")
        self.assertFalse(result["actions_enabled"])
        self.assertEqual(result["completeness"], "PARTIAL")
        self.assertEqual(result["events"], [])
        self.assertEqual(result["summary"]["total"], 0)
        self.assertEqual(result["sources"]["systemd"]["status"], "SUPPORTED")
        self.assertEqual(result["sources"]["scheduler"]["status"], "PARTIAL")
        self.assertEqual(result["sources"]["brc"]["status"], "NOT_AVAILABLE")
        self.assertEqual(result["sources"]["delivery"]["status"], "NOT_AVAILABLE")
        self.assertEqual(result["sources"]["ops_incidents"]["status"], "NOT_AVAILABLE")
        self.assertEqual(result["sources"]["github_observe"]["status"], "NOT_AVAILABLE")
        self.assertIn("не доказывает", result["note"])

    def test_incidents_and_stable_ids(self):
        data = fixture({"ops": "failed", "alerts": "unknown", "agent": "unexpected_active"})
        a = assemble(data, scheduler({"blocked": 2, "deferred": 1}), now=NOW)
        b = assemble(data, scheduler({"blocked": 2, "deferred": 1}), now=NOW)
        self.assertEqual(a, b)
        self.assertEqual(a["summary"]["total"], 5)
        self.assertEqual(a["summary"]["critical"], 2)
        self.assertEqual(a["summary"]["blocked"], 1)
        self.assertEqual(len({e["event_id"] for e in a["events"]}), 5)
        self.assertEqual(a["events"][0]["category"], "failure")
        self.assertTrue(all(e["scope"] == "owner_read_only" for e in a["events"]))
        self.assertEqual(a["summary"]["source_count"], 6)
        self.assertNotIn("secret-id-do-not-echo", json.dumps(a))
        self.assertNotIn("token=never-echo", json.dumps(a))

    def test_no_automatic_green_from_inactive_or_timer(self):
        a = assemble(fixture({"agent_bounded": "inactive", "qa": "unknown"}), None, now=NOW)
        self.assertEqual(a["sources"]["scheduler"]["status"], "NOT_AVAILABLE")
        self.assertTrue(any(e["event_id"] == "systemd:agent_bounded" for e in a["events"]))
        self.assertTrue(any(e["event_id"] == "systemd:qa" for e in a["events"]))
        self.assertFalse(any(e["event_id"] == "systemd:agent" for e in a["events"]))
        self.assertEqual(a["summary"]["available_sources"], 1)

    def test_stale_and_future_fail_closed(self):
        for age in (181, -121, 86400):
            with self.subTest(age=age):
                response = assemble(fixture(age_seconds=age), scheduler(), now=NOW)
                self.assertEqual(response["sources"]["systemd"]["status"], "STALE")
                self.assertEqual(response["summary"]["total"], 1)
                self.assertEqual(response["events"][0]["event_id"], "systemd:unverified")
                self.assertFalse(any(e["status"] == "healthy" for e in response["events"]))

    def test_duplicate_unknown_and_forged_unit_fail_closed(self):
        for changed in ({"id": "ops", "state": "impossible"},
                        {"id": "brc", "state": "active"},
                        {"id": "ops", "unit": "sudo.service"}):
            with self.subTest(changed=changed):
                obj = fixture()
                obj["services"][0].update(changed)
                result = assemble(obj, None, now=NOW)
                self.assertEqual(result["sources"]["systemd"]["status"], "PARTIAL")
                self.assertEqual(len(result["events"]), 1)
        bad = fixture()
        bad["services"].append(bad["services"][0].copy())
        with self.assertRaisesRegex(InboxUnavailable, "overview_invalid"):
            assemble(bad, None, now=NOW)

    def test_unknown_scheduler_source_stays_unavailable(self):
        for obj in (None, {}, scheduler(queue_state="not_configured"),
                    scheduler({"blocked": "1"})):
            with self.subTest(obj=obj):
                r = assemble(fixture(), obj, now=NOW)
                self.assertEqual(r["sources"]["scheduler"]["status"], "NOT_AVAILABLE")
                self.assertEqual(r["summary"]["total"], 0)

    def test_bounded_loader_no_raw_leak_or_symlink(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            file = directory / "overview.json"
            file.write_text(json.dumps(fixture()), encoding="utf-8")
            self.assertEqual(load_overview(file)["schema"], 1)
            link = directory / "fake.json"
            link.symlink_to(file)
            with self.assertRaises(InboxUnavailable):
                load_overview(link)
            file.write_bytes(b"{" + b"x"*131072)
            with self.assertRaises(InboxUnavailable):
                load_overview(file)
            file.write_text(json.dumps({"schema": 1, "mode": "write"}))
            with self.assertRaises(InboxUnavailable):
                load_overview(file)

    def github_feed(self, *, now=NOW):
        def entry(number, run_id, kind, action, outcome="none"):
            return {
                "id": run_id, "workflow_id": OBSERVE_WORKFLOW_ID,
                "name": OBSERVE_WORKFLOW, "repository": {"full_name": "MikeMoore1337/hermes"},
                "event": kind, "status": "completed", "conclusion": "success",
                "display_title": f"observe:{kind}:{action}:{number}:{outcome}",
                "created_at": (now-dt.timedelta(minutes=2)).isoformat(),
                "body": "SAMPLE_SECRET_PROMPT_INJECTION",
                "html_url": "https://evil.example/SAMPLE_SECRET_PROMPT_INJECTION",
            }
        return from_runs({"workflow_runs": [
            entry(42, 1000, "issues", "opened"),
            entry(42, 1001, "issue_comment", "created"),
            entry(777, 1002, "workflow_run", "completed", "failure"),
        ]}, now=now)

    def test_github_feed_uses_approved_dynamic_inbox_without_new_ui(self):
        overview = fixture()
        overview["github_observe_feed"] = self.github_feed()
        result = assemble(overview, scheduler(), now=NOW)
        self.assertEqual(result["sources"]["github_observe"]["status"], "PARTIAL")
        self.assertEqual(result["summary"]["available_sources"], 3)
        self.assertEqual(result["summary"]["critical"], 1)
        self.assertEqual(result["summary"]["review"], 2)
        self.assertEqual(result["summary"]["total"], 3)
        self.assertFalse(result["actions_enabled"])
        events = [e for e in result["events"] if e["source"] == "github_observe"]
        self.assertEqual(len(events), 3)
        self.assertTrue(all(e["evidence_link"] is None for e in events))
        self.assertTrue(all(e["scope"] == "owner_read_only" for e in events))
        self.assertTrue(any("№42" in e["title"] for e in events))
        self.assertTrue(any(e["event_id"] == "github_observe:workflow_run:777"
                            and e["category"] == "failure" for e in events))
        raw = json.dumps(result, ensure_ascii=False)
        self.assertNotIn("SAMPLE_SECRET_PROMPT_INJECTION", raw)
        self.assertNotIn("evil.example", raw)
        self.assertNotIn("GRANTED", raw)

    def test_missing_or_stale_github_feed_never_proves_health(self):
        baseline = assemble(fixture(), scheduler(), now=NOW)
        self.assertEqual(baseline["sources"]["github_observe"]["status"], "NOT_AVAILABLE")
        overview = fixture()
        overview["github_observe_feed"] = self.github_feed(now=NOW-dt.timedelta(minutes=46))
        stale = assemble(overview, scheduler(), now=NOW)
        self.assertEqual(stale["sources"]["github_observe"]["status"], "STALE")
        self.assertEqual(stale["summary"]["review"], 1)
        self.assertEqual(stale["events"][0]["event_id"], "github_observe:stale")
        self.assertNotIn("№777", json.dumps(stale, ensure_ascii=False))

    def test_forged_permission_in_snapshot_is_hidden_from_operator(self):
        overview = fixture()
        source = self.github_feed()
        source["execution_authorized"] = True
        overview["github_observe_feed"] = source
        result = assemble(overview, scheduler(), now=NOW)
        self.assertEqual(result["sources"]["github_observe"]["status"], "PARTIAL")
        self.assertEqual(result["summary"]["total"], 0)
        self.assertFalse(result["actions_enabled"])
        self.assertNotIn("GRANTED", json.dumps(result))

    def test_no_unauthorized_details_or_brc_fetch(self):
        data = fixture({"ops": "failed"})
        data["services"][1]["name"] = "secret token=top-secret"
        data["agent_policy"] = "sk-proj-not-for-frontend"
        reply = assemble(data, scheduler(), now=NOW)
        encoded = json.dumps(reply, ensure_ascii=False)
        self.assertNotIn("top-secret", encoded)
        self.assertNotIn("sk-proj", encoded)
        self.assertTrue(all(e["evidence_link"] in ("/api/overview", "/api/codex/tasks")
                            for e in reply["events"]))
        self.assertLessEqual(len(reply["events"]), MAX_EVENTS)


if __name__ == "__main__":
    unittest.main()
