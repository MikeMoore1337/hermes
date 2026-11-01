"""#717: independent Control Center release boundary for sanitized GitHub feeds."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
import os
from pathlib import Path
import tempfile
import unittest

from control_center import github_observe_view as ui
from qa_advisor import github_observe_feed as qa

NOW = datetime(2026, 11, 1, 21, 0, tzinfo=UTC)


def sample():
    run = {
        "id": 1998,
        "workflow_id": qa.OBSERVE_WORKFLOW_ID,
        "name": qa.OBSERVE_WORKFLOW,
        "repository": {"full_name": qa.REPO},
        "event": "pull_request_target", "status": "completed",
        "conclusion": "success",
        "display_title": "observe:pull_request_target:opened:512:none",
        "created_at": (NOW-timedelta(minutes=3)).isoformat(),
        "html_url": "https://untrusted.example/SAMPLE_SECRET",
    }
    return qa.from_runs({"workflow_runs": [run]}, now=NOW)


class GitHubControlCenterBoundaryTests(unittest.TestCase):
    def test_ui_accepts_qa_safe_schema_without_any_raw_git_data(self):
        report = sample()
        self.assertEqual(ui.validate(report), report)
        self.assertTrue(ui.fresh(report, now=NOW))
        self.assertFalse(ui.fresh(report, now=NOW+timedelta(minutes=46)))
        self.assertFalse(ui.fresh(report, now=NOW-timedelta(minutes=3)))
        self.assertEqual(ui.WORKFLOW_ID, qa.OBSERVE_WORKFLOW_ID)
        self.assertEqual(ui.SCHEMA, qa.SCHEMA)
        self.assertEqual(ui.REPO, qa.REPO)
        self.assertNotIn("SAMPLE_SECRET", json.dumps(report))
        self.assertNotIn("untrusted.example", json.dumps(report))

    def test_ui_rejects_extra_fields_and_forged_actions(self):
        base = sample()
        variants = [
            {**base, "execution_authorized": True},
            {**base, "owner_approval": "GRANTED"},
            {**base, "workflow_id": True},
            {**base, "repo": "untrusted/foreign"},
            {**base, "unexpected": "SAMPLE_SECRET"},
            {**base, "events": [{**base["events"][0], "candidate": "RUN_MODEL"}]},
            {**base, "events": [{**base["events"][0], "subject_number": "512"}]},
            {**base, "events": [{**base["events"][0], "event": "wrong"}]},
            {**base, "events": [base["events"][0], base["events"][0]]},
            {**base, "inspected_count": 0},
        ]
        for v in variants:
            with self.subTest(variant=list(v)), self.assertRaises(ui.FeedRefused):
                ui.validate(v)

    def test_root_only_reader_rejects_symlink_mode_and_corruption(self):
        with tempfile.TemporaryDirectory() as root:
            folder = Path(root)
            folder.chmod(0o700)
            path = folder/"feed.json"
            self.assertIsNone(ui.load(path))
            report = sample()
            path.write_text(json.dumps(report), encoding="utf-8")
            path.chmod(0o600)
            self.assertEqual(ui.load(path), report)
            path.chmod(0o644)
            with self.assertRaisesRegex(ui.FeedRefused, "feed_file_unsafe"):
                ui.load(path)
            path.unlink()
            outside = folder/"outside"
            outside.write_text(json.dumps(report))
            path.symlink_to(outside)
            with self.assertRaises(ui.FeedRefused):
                ui.load(path)
            path.unlink()
            path.write_bytes(b"{" + b"x" * ui.MAX_BYTES)
            path.chmod(0o600)
            with self.assertRaises(ui.FeedRefused):
                ui.load(path)
            folder.chmod(0o755)
            with self.assertRaisesRegex(ui.FeedRefused, "feed_directory_unsafe"):
                ui.load(path)

    def test_controller_does_not_import_qa_advisor(self):
        # The installed Control Center release only contains control_center/
        # and research_scout/. A hidden import here breaks production start.
        import inspect
        from control_center import operator_inbox, snapshot
        for source in (inspect.getsource(ui), inspect.getsource(operator_inbox),
                       inspect.getsource(snapshot)):
            self.assertNotIn("from qa_advisor", source)
            self.assertNotIn("import qa_advisor", source)


if __name__ == "__main__":
    unittest.main()
