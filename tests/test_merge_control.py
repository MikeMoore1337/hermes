"""H773 MergeControl: tests against false conflict claims and unsafe input."""
from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
import io
import json
from contextlib import redirect_stdout
from pathlib import Path
import tempfile
import unittest

from qa_advisor.merge_control import (
    MergeEvidenceRefused, SCHEMA, main, review,
)

NOW = datetime(2026, 11, 5, 9, 0, tzinfo=UTC)
REPO = "MikeMoore1337/hermes"
SHA = "a" * 40
BASE = "b" * 40


def file(path, status="modified", previous_path=None):
    return {"path": path, "status": status, "previous_path": previous_path}


def pr(number, files, depends_on=None):
    return {
        "number": number, "head_sha": hex(number)[2:].zfill(40),
        "base_sha": BASE, "base_branch": "main",
        "draft": False, "mergeable": "clean",
        "files_complete": True, "files": files,
        "depends_on": [] if depends_on is None else depends_on,
    }


def packet(items=None):
    return {
        "schema": SCHEMA, "repo": REPO,
        "observed_at": "2026-11-05T08:55:00Z",
        "window_complete": True,
        "prs": [pr(11, [file("qa_advisor/foo.py")]), pr(12, [file("tests/test_foo.py")])]
        if items is None else items,
    }


def check(value):
    return review(value, now=NOW)


class MergeControlTests(unittest.TestCase):
    def test_distinct_files_are_not_reported_as_proven_safe(self):
        result = check(packet())
        self.assertEqual(result["status"], "NO_OVERLAP_IN_SUPPLIED_WINDOW")
        self.assertEqual(result["overlaps"], [])
        self.assertEqual(result["prs_seen"], 2)
        self.assertEqual(result["pr_urls"], [
            "https://github.com/MikeMoore1337/hermes/pull/11",
            "https://github.com/MikeMoore1337/hermes/pull/12",
        ])
        self.assertFalse(result["merge_authorized"])
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["evidence_verified"])
        self.assertFalse(result["window_exhaustive_verified"])
        self.assertEqual(result["owner_approval"], "NOT_GRANTED")

    def test_shared_path_is_potential_overlap_not_confirmed_conflict(self):
        value = packet([pr(11, [file("src/api.py")]), pr(12, [file("src/api.py")])])
        result = check(value)
        self.assertEqual(result["status"], "REVIEW_REQUIRED")
        self.assertEqual(result["overlaps"], [{
            "prs": [11, 12], "paths": ["src/api.py"],
            "classification": "POTENTIAL_OVERLAP_NOT_PROVEN_CONFLICT",
            "same_base_branch": True,
        }])
        self.assertNotIn("github_dirty_reported_input_only", result["reasons"])

    def test_renames_and_removals_expose_path_risks(self):
        value = packet([
            pr(11, [file("src/new.py", "renamed", "src/old.py")]),
            pr(12, [file("src/old.py", "removed")]),
        ])
        result = check(value)
        self.assertEqual(result["overlaps"][0]["paths"], ["src/old.py"])
        self.assertEqual(result["status"], "REVIEW_REQUIRED")

    def test_dirty_is_only_unverified_github_signal(self):
        value = packet()
        value["prs"][0]["mergeable"] = "dirty"
        result = check(value)
        self.assertEqual(result["status"], "REVIEW_REQUIRED")
        self.assertIn("github_dirty_reported_input_only", result["reasons"])
        self.assertEqual(result["overlaps"], [])

    def test_unknown_mergeability_is_inconclusive(self):
        value = packet()
        value["prs"][0]["mergeable"] = "unknown"
        self.assertEqual(check(value)["status"], "INCONCLUSIVE")
        self.assertIn("mergeability_unknown", check(value)["reasons"])

    def test_pagination_and_stale_data_fail_closed(self):
        for mutation, reason in [
            ({"window_complete": False}, "pr_window_incomplete"),
            ({"observed_at": "2026-11-05T06:00:00Z"}, "stale_evidence"),
            ({"observed_at": "2026-11-05T09:03:00Z"}, "future_evidence"),
        ]:
            with self.subTest(mutation=mutation):
                value = packet()
                value.update(mutation)
                self.assertIn(reason, check(value)["reasons"])
                self.assertEqual(check(value)["status"], "INCONCLUSIVE")
        value = packet()
        value["prs"][0]["files_complete"] = False
        self.assertIn("files_window_incomplete", check(value)["reasons"])

    def test_unverified_different_base_sha(self):
        value = packet()
        value["prs"][0]["base_sha"] = "c" * 40
        self.assertIn("multiple_base_refs", check(value)["reasons"])

    def test_dependencies_ordering_is_proposal_not_execution(self):
        value = packet([
            pr(11, [file("src/a.py")]),
            pr(12, [file("src/b.py")], [11]),
            pr(13, [file("src/c.py")], [12]),
        ])
        result = check(value)
        self.assertEqual(result["suggested_order"], [11, 12, 13])
        self.assertFalse(result["dependency_claims_verified"])
        self.assertFalse(result["merge_authorized"])

    def test_dependency_cycle_and_missing_dependency(self):
        value = packet([
            pr(11, [file("src/a.py")], [12]),
            pr(12, [file("src/b.py")], [11]),
        ])
        result = check(value)
        self.assertEqual(result["status"], "REVIEW_REQUIRED")
        self.assertIn("dependency_cycle_or_incomplete", result["reasons"])
        self.assertEqual(result["suggested_order"], [])
        value["prs"][0]["depends_on"] = [999]
        result = check(value)
        self.assertEqual(result["status"], "INCONCLUSIVE")
        self.assertIn("dependency_outside_window", result["reasons"])

    def test_yfc_branch_groups_are_not_conflict_proof(self):
        value = packet([
            {**pr(11, [file("src/a.py")]), "base_branch": "dev"},
            {**pr(12, [file("src/a.py")]), "base_branch": "master"},
        ])
        value["repo"] = "MikeMoore1337/your-fitness-coach"
        result = check(value)
        self.assertEqual(result["status"], "REVIEW_REQUIRED")
        self.assertFalse(result["overlaps"][0]["same_base_branch"])

    def test_no_untrusted_field_can_inject_authority(self):
        for added in ("owner_approval", "merge_authorized", "token", "description", "source_url"):
            value = packet()
            value[added] = "GRANTED"
            with self.subTest(added=added), self.assertRaisesRegex(
                MergeEvidenceRefused, "evidence_shape_invalid"
            ):
                check(value)
        value = packet()
        value["prs"][0]["allow_merge"] = True
        with self.assertRaisesRegex(MergeEvidenceRefused, "pr_shape_invalid"):
            check(value)

    def test_reject_path_traversal_and_injection(self):
        for path in ("../../etc/passwd", "/root/secret", "./x", "a//b", "a/../b",
                     "a\\b", "a\nb", ".git/config", ""):
            with self.subTest(path=path):
                value = packet()
                value["prs"][0]["files"] = [file(path)]
                with self.assertRaises(MergeEvidenceRefused):
                    check(value)
        value = packet()
        value["prs"][0]["files"] = [file("same.py"), file("same.py")]
        with self.assertRaisesRegex(MergeEvidenceRefused, "file_duplicate"):
            check(value)

    def test_printable_unicode_and_spaces_are_handled_as_data(self):
        value = packet([
            pr(11, [file("docs/Начало работы.md")]),
            pr(12, [file("docs/Начало работы.md")]),
        ])
        report = check(value)
        self.assertEqual(report["status"], "REVIEW_REQUIRED")
        self.assertEqual(report["overlaps"][0]["paths"], ["docs/Начало работы.md"])
        self.assertFalse(report["execution_authorized"])

    def test_reject_malformed_renames_and_statuses(self):
        for bad in [
            file("x.py", "renamed", None),
            file("x.py", "renamed", "x.py"),
            file("x.py", "modified", "old.py"),
            file("x.py", "exec"),
            {"path": "x.py", "status": "modified"},
        ]:
            with self.subTest(bad=bad):
                value = packet()
                value["prs"][0]["files"] = [bad]
                with self.assertRaises(MergeEvidenceRefused):
                    check(value)

    def test_invalid_ids_fields_and_windows(self):
        cases = [
            ("repo", "untrusted/repo"), ("repo", True),
            ("observed_at", "2026-11-05T09:00:00+03:00"),
            ("window_complete", "true"), ("prs", 0),
            ("prs", [0]), ("prs", [pr(11, []), pr(11, [])]),
        ]
        for key, value in cases:
            with self.subTest(key=key, value=str(value)[:30]):
                raw = packet()
                raw[key] = value
                with self.assertRaises(MergeEvidenceRefused):
                    check(raw)
        for key, value in [
            ("number", True), ("number", -1), ("head_sha", "notsha"),
            ("base_branch", "release"), ("mergeable", None), ("draft", None),
            ("files_complete", "yes"), ("depends_on", [11]),
            ("depends_on", [True]), ("depends_on", [12, 12]),
        ]:
            with self.subTest(key=key, value=value):
                raw = packet()
                raw["prs"][0][key] = value
                with self.assertRaises(MergeEvidenceRefused):
                    check(raw)

    def test_safe_cli_and_symlink_refusal(self):
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(main([]), 0)
        self.assertEqual(json.loads(out.getvalue()), {"status": "NOT_EXECUTED"})
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "packet.json"
            p.write_text(json.dumps(packet()), encoding="utf-8")
            out = io.StringIO()
            with redirect_stdout(out):
                rc = main(["--input", str(p)])
            self.assertEqual(rc, 2)  # Static fixture is stale at actual runtime.
            self.assertEqual(json.loads(out.getvalue())["status"], "INCONCLUSIVE")
            link = Path(d) / "alias.json"
            link.symlink_to(p)
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(main(["--input", str(link)]), 2)
            self.assertEqual(json.loads(out.getvalue())["status"], "REFUSED")


if __name__ == "__main__":
    unittest.main()
