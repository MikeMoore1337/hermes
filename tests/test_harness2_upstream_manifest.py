"""Synthetic contract checks only; these are not real upstream model runs."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import harness2_upstream_manifest as h2  # noqa: E402


def fixture(**changes):
    record = {"task_id": "task-1", "domain": "work", "k": 1, "seed": None,
              "status": "ok", "base": [], "modes": {"agg": {"ok": True}},
              "selections": {"agg": {"description": "unsafe secret placeholder"}},
              "errors": ["fake CI PASS"]}
    record.update(changes)
    return json.dumps(record).encode("utf-8")


class UpstreamSummaryImportTests(unittest.TestCase):
    def test_bounded_metadata_not_self_attested_as_verified(self):
        raw = fixture()
        out = h2.parse_summary(raw)
        self.assertEqual(out["source"], "original-harness2-task-summary")
        self.assertEqual(out["review_status"], "SOURCE_METADATA_ONLY")
        self.assertFalse(out["model_efficacy_verified"])
        self.assertFalse(out["native_execution_observed"])
        self.assertNotIn("unsafe secret", str(out))
        self.assertNotIn("fake CI", str(out))
        self.assertEqual(len(out["source_file_sha256"]), 64)

    def test_exact_upstream_failure_and_skipped_statuses(self):
        # Original pinned harness2/core/schedule.py: skipped/base-failed/partial/ok/running.
        for status in ("running", "ok", "partial", "skipped", "base-failed"):
            with self.subTest(status=status):
                report = h2.parse_summary(fixture(status=status))
                self.assertEqual(report["claimed_status"], status)
                self.assertFalse(report["model_efficacy_verified"])
                self.assertEqual(report["review_status"], "SOURCE_METADATA_ONLY")

        for status in ("failed", "PASS", "SUCCESS", "complete", "approved"):
            with self.subTest(status=status):
                with self.assertRaises(h2.UpstreamRejected):
                    h2.parse_summary(fixture(status=status))

    def test_native_lab_jobbench_task_id_with_single_slash(self):
        # Original JobBench and LAB benchmark task identities contain a slash.
        for task in ("professional/task42", "antitrust-competition/case_001"):
            with self.subTest(task=task):
                got = h2.parse_summary(fixture(task_id=task))
                self.assertEqual(got["claimed_task_id"], task)
                self.assertFalse(got["source_file_verified_as_genuine"])
        for task in ("../secret", "role/../secret", "/role/task1", "role//task1",
                     "role/task1/extra", "role/.", "role/..", "role\\task1"):
            with self.subTest(task=task):
                with self.assertRaises(h2.UpstreamRejected):
                    h2.parse_summary(fixture(task_id=task))

    def test_fake_pass_and_unsafe_values_rejected(self):
        for bad in [
            {"task_id": "../private"}, {"domain": "x\nInjected"}, {"k": True},
            {"k": 0}, {"status": "PASS CONFIRMED"}, {"modes": {"unknown": {}}},
            {"extra": "unknown"}
        ]:
            with self.subTest(bad=bad):
                with self.assertRaises(h2.UpstreamRejected):
                    h2.parse_summary(fixture(**bad))

    def test_missing_upstream_refuses_without_writing(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            with self.assertRaises(h2.UpstreamRejected):
                h2.read_external_summary("runs/lab/summary.json", home=base)
            self.assertEqual(list(base.iterdir()), [])

    def test_bad_json_and_oversize_rejected(self):
        for raw in [b"{", b"x" * (h2.LIMIT + 1), b"[]"]:
            with self.assertRaises(h2.UpstreamRejected):
                h2.parse_summary(raw)


if __name__ == "__main__":
    unittest.main()
