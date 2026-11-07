"""Engineering Control data-only integration into the existing owner Inbox.

Offline synthetic acceptance: validation, authority, permissions, stale
evidence, bounded handoff, and no raw PR/package/secret text in web response.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from qa_advisor import engineering_feed as writer
from control_center import engineering_view as reader
from control_center.operator_inbox import assemble
from control_center.snapshot import collect, UNITS

NOW = datetime(2026, 11, 5, 15, 0, tzinfo=UTC)
STAMP = NOW.isoformat().replace("+00:00", "Z")


def report(module, *, status=None, stamp=STAMP):
    statuses = {
        "release_guard": "BLOCKED",
        "merge_control": "REVIEW_REQUIRED",
        "deppilot": "INCONCLUSIVE",
        "opensource_radar": "HOLD_FOR_REVIEW",
    }
    schema = writer.KINDS[module][0]
    value = {
        "schema": schema, "status": status or statuses[module],
        "checked_at": stamp, "reasons": ["fixed_hypothesis"],
        "recommendation_only": True,
        "arbitrary": "secret=NEVER_ECHO_IN_INBOX",
    }
    if module == "deppilot":
        value.update(changes_written=False, production_authorized=False)
    elif module == "opensource_radar":
        value.update(owner_approval="NOT_GRANTED", install_authorized=False)
    else:
        value.update(owner_approval="NOT_GRANTED", execution_authorized=False)
        value["deploy_authorized" if module == "release_guard" else "merge_authorized"] = False
    return value


def examples():
    return {key: report(key) for key in writer.KINDS}


def overview(feed, *, when=NOW):
    return {
        "schema": 1, "mode": "read_only",
        "generated_at": when.isoformat().replace("+00:00", "Z"),
        "services": [
            {"id": key, "name": label, "unit": unit, "kind": kind,
             "state": "blocked" if key == "agent" else "active"}
            for key, label, unit, kind in UNITS
        ],
        "engineering_feed": feed,
    }


class EngineeringFeedTests(unittest.TestCase):
    def test_status_report_produces_no_raw_payload(self):
        result = writer.build(examples(), now=NOW)
        self.assertEqual(result["schema"], writer.SCHEMA)
        self.assertEqual(set(result["sources"]), set(writer.KINDS))
        self.assertFalse(result["execution_authorized"])
        self.assertEqual(result["owner_approval"], "NOT_GRANTED")
        self.assertEqual(result["sources"]["release_guard"]["status"], "BLOCKED")
        self.assertEqual(result["sources"]["release_guard"]["reason_count"], 1)
        serialized = json.dumps(result)
        self.assertNotIn("NEVER_ECHO_IN_INBOX", serialized)
        self.assertNotIn("fixed_hypothesis", serialized)
        self.assertEqual(writer.validate(result), result)
        self.assertEqual(reader.validate(result), result)

    def test_unavailable_modules_do_not_invent_coverage(self):
        envelope = writer.build({"merge_control": report("merge_control")}, now=NOW)
        self.assertEqual(envelope["sources"]["deppilot"], {
            "status": "NOT_AVAILABLE", "checked_at": None, "reason_count": 0,
        })
        self.assertEqual(reader.validate(envelope), envelope)
        ui = assemble(overview(envelope), None, now=NOW)
        self.assertEqual(ui["sources"]["engineering_control"]["status"], "PARTIAL")
        self.assertEqual(len([e for e in ui["events"] if e["source"] == "engineering_control"]), 1)

    def test_existing_inbox_shows_only_fixed_statuses(self):
        fed = writer.build(examples(), now=NOW)
        ui = assemble(overview(fed), None, now=NOW)
        self.assertEqual(ui["mode"], "read_only")
        self.assertFalse(ui["actions_enabled"])
        self.assertEqual(ui["sources"]["engineering_control"]["status"], "PARTIAL")
        events = [e for e in ui["events"] if e["source"] == "engineering_control"]
        self.assertEqual(len(events), 4)
        self.assertTrue(all(e["evidence_link"] is None for e in events))
        self.assertTrue(all(e["scope"] == "owner_read_only" for e in events))
        self.assertTrue(all(e["category"] in ("blocked", "needs_review") for e in events))
        self.assertEqual({e["event_id"] for e in events}, {
            "engineering_control:release_guard", "engineering_control:merge_control",
            "engineering_control:deppilot", "engineering_control:opensource_radar",
        })
        text = json.dumps(ui, ensure_ascii=False)
        self.assertNotIn("NEVER_ECHO_IN_INBOX", text)
        self.assertNotIn("fixed_hypothesis", text)
        self.assertNotIn("source_sha", text)

    def test_provisional_positive_never_becomes_owner_go(self):
        fed = writer.build({
            "release_guard": report("release_guard", status="READY_FOR_OWNER_REVIEW"),
            "merge_control": report("merge_control", status="NO_OVERLAP_IN_SUPPLIED_WINDOW"),
            "deppilot": report("deppilot", status="NO_CHANGES_IN_SUPPLIED_CANDIDATES"),
            "opensource_radar": report("opensource_radar", status="PILOT_REVIEW"),
        }, now=NOW)
        ui = assemble(overview(fed), None, now=NOW)
        self.assertEqual(ui["sources"]["engineering_control"]["status"], "PARTIAL")
        events = [e for e in ui["events"] if e["source"] == "engineering_control"]
        self.assertEqual(len(events), 2)
        self.assertTrue(all(e["category"] == "needs_review" for e in events))
        self.assertIn("решение владельца", json.dumps(ui, ensure_ascii=False))
        self.assertFalse(ui["actions_enabled"])

    def test_stale_reports_are_hidden_from_inbox(self):
        fed = writer.build(examples(), now=NOW)
        future = NOW + timedelta(hours=2)
        ui = assemble(overview(fed, when=future), None, now=future)
        self.assertEqual(ui["sources"]["engineering_control"]["status"], "STALE")
        events = [e for e in ui["events"] if e["source"] == "engineering_control"]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_id"], "engineering_control:stale")
        self.assertNotIn("ReleaseGuard: Обнаружены блокировки",
                         json.dumps(ui, ensure_ascii=False))

    def test_refuse_authorization_forgery_and_unknown_status(self):
        for key, mutation in (
            ("release_guard", {"owner_approval": "GRANTED"}),
            ("release_guard", {"deploy_authorized": True}),
            ("merge_control", {"merge_authorized": True}),
            ("deppilot", {"changes_written": True}),
            ("opensource_radar", {"install_authorized": True}),
            ("release_guard", {"status": "AUTO_DEPLOY"}),
        ):
            with self.subTest(key=key, changed=mutation):
                raw = report(key)
                raw.update(mutation)
                with self.assertRaises(writer.EngineeringFeedRefused):
                    writer.build({key: raw}, now=NOW)

    def test_bad_timestamps_types_and_extra_fields(self):
        raw = examples()
        raw["release_guard"]["checked_at"] = "2000-01-01T00:00:00Z"
        with self.assertRaisesRegex(writer.EngineeringFeedRefused, "report_stale_or_future"):
            writer.build(raw, now=NOW)
        fed = writer.build(examples(), now=NOW)
        for changed in (
            {**fed, "token": "SENSITIVE"},
            {**fed, "execution_authorized": True},
            {**fed, "sources": {**fed["sources"], "secrets": {}}},
            {**fed, "sources": {**fed["sources"],
                                "release_guard": {**fed["sources"]["release_guard"],
                                                  "reason_count": True}}},
        ):
            with self.subTest(changed=list(changed)), self.assertRaises(reader.EngineeringViewRefused):
                reader.validate(changed)

    def test_atomic_file_roundtrip_permissions_and_symlink_denial(self):
        feed = writer.build(examples(), now=NOW)
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            directory.chmod(0o700)
            self.assertEqual(writer.save(feed, directory=directory),
                             "STORED_SANITIZED_ENGINEERING")
            stored = directory / writer.FILE
            self.assertEqual(stored.stat().st_mode & 0o777, 0o600)
            self.assertEqual(reader.load(stored), feed)
            self.assertTrue(reader.fresh(feed, now=NOW))
            self.assertFalse(reader.fresh(feed, now=NOW+timedelta(hours=2)))
            link = directory / "untrusted.json"
            link.symlink_to(stored)
            with self.assertRaises(reader.EngineeringViewRefused):
                reader.load(link)
            directory.chmod(0o755)
            with self.assertRaises(writer.SignalError if hasattr(writer, "SignalError") else ValueError):
                writer.save(feed, directory=directory)

    def test_existing_collector_projects_without_new_service(self):
        fed = writer.build({"release_guard": report("release_guard")}, now=NOW)
        def fake_systemctl(*args, **kw):
            return type("Reply", (), {
                "returncode": 0, "stdout": "ActiveState=active\nLoadState=loaded\n",
            })()
        with patch("control_center.snapshot.read_engineering_feed", return_value=fed):
            with patch("control_center.snapshot.read_owner_view", return_value={}):
                snapshot = collect(runner=fake_systemctl, now=NOW)
        self.assertEqual(snapshot["engineering_feed"], fed)
        rendered = assemble(snapshot, None, now=NOW)
        self.assertEqual(rendered["sources"]["engineering_control"]["status"], "PARTIAL")
        self.assertTrue(any(e["event_id"] == "engineering_control:release_guard"
                            for e in rendered["events"]))

    def test_cli_is_inert_without_input(self):
        from qa_advisor.engineering_feed import main
        with patch("sys.stdout", new_callable=io.StringIO) as stdout:
            self.assertEqual(main([]), 0)
        self.assertEqual(json.loads(stdout.getvalue()), {"status": "NOT_EXECUTED"})


if __name__ == "__main__":
    unittest.main()
