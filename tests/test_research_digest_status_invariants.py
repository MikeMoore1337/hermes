"""H-03: persisted digest cannot promote HOLD, NO_DATA or unsafe citations."""
from __future__ import annotations

import copy
import json
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from research_scout.daily_digest import DigestError, FILENAME, TOPIC_IDS, prepare, save

NOW = datetime(2026, 10, 15, 9, tzinfo=UTC)


def article(*, doi: str | None = "10.1234/exercise2026",
            status: str = "MANUAL_REVIEW", reason: str = "metadata_only") -> dict:
    return {
        "source": "EUROPE_PMC",
        "id": "42840492",
        "source_url": "https://europepmc.org/article/MED/42840492",
        "title": "Test-only candidate: no scientific recommendations",
        "doi": doi,
        "first_publication_date": "2026-10-14",
        "status": status, "reason": reason,
    }


def report(item: dict | None = None) -> dict:
    def searcher(topic, *, now):
        return {
            "topic": topic, "status": "MANUAL_REVIEW" if item and topic == TOPIC_IDS[0]
                     else "NO_DATA",
            "candidates": [item] if item and topic == TOPIC_IDS[0] else [],
        }
    return prepare(now=NOW, searcher=searcher,
                   doi_verifier=lambda entry: {
                       "status": "MANUAL_REVIEW", "doi": entry["doi"]})


class DigestStatusInvariantsTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="hermes-science-status-")
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.directory.chmod(0o700)

    def _assert_rejected_without_writing(self, record):
        with self.assertRaises(DigestError):
            save(record, self.directory)
        self.assertFalse((self.directory / FILENAME).exists())

    def test_all_three_actual_valid_states_still_persist(self):
        cases = [
            (report(article()), "MANUAL_REVIEW"),
            (report(article(doi=None)), "HOLD"),
            (report(), "NO_DATA"),
        ]
        for record, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(record["status"], expected)
                save(record, self.directory)
                saved = json.loads((self.directory / FILENAME).read_text(encoding="utf-8"))
                self.assertEqual(saved["status"], expected)
                self.assertFalse(saved["scientific_claims_verified"])

    def test_hold_packet_cannot_be_promoted_to_manual_review_or_no_data(self):
        actual = report(article(doi=None))
        self.assertEqual(actual["items"][0]["reason"], "doi_missing")
        for forged in ("MANUAL_REVIEW", "NO_DATA"):
            with self.subTest(forged=forged):
                changed = copy.deepcopy(actual)
                changed["status"] = forged
                self._assert_rejected_without_writing(changed)

    def test_no_data_cannot_be_relabelled_as_manual_review(self):
        changed = report()
        changed["status"] = "MANUAL_REVIEW"
        self._assert_rejected_without_writing(changed)

    def test_reviewable_paper_cannot_be_relabelled_as_no_data(self):
        changed = report(article())
        changed["status"] = "NO_DATA"
        self._assert_rejected_without_writing(changed)

    def test_error_cannot_be_hidden_behind_no_data_or_manual_review(self):
        for forged in ("NO_DATA", "MANUAL_REVIEW"):
            changed = report()
            changed["errors"].append({
                "topic": "exercise-recovery", "reason": "source_unknown"})
            changed["status"] = forged
            with self.subTest(forged=forged):
                self._assert_rejected_without_writing(changed)

    def test_missing_doi_cannot_be_promoted_by_changing_item_status(self):
        changed = report(article(doi=None))
        changed["items"][0]["status"] = "MANUAL_REVIEW"
        self._assert_rejected_without_writing(changed)

    def test_stale_or_suspicious_source_reason_cannot_pass_as_manual_review(self):
        for reason in ("stale_publication_date", "suspicious_title",
                       "future_publication_date", "duplicate_doi"):
            changed = report(article())
            changed["items"][0]["reason"] = reason
            with self.subTest(reason=reason):
                self._assert_rejected_without_writing(changed)

    def test_normalized_hold_reason_cannot_pass_as_safe_metadata(self):
        changed = report(article())
        changed["items"][0]["status"] = "HOLD"
        self._assert_rejected_without_writing(changed)

    def test_rejection_preserves_previous_protected_report(self):
        safe = report(article())
        save(safe, self.directory)
        existing = (self.directory / FILENAME).read_bytes()
        forged = copy.deepcopy(safe)
        forged["status"] = "NO_DATA"
        with self.assertRaises(DigestError):
            save(forged, self.directory)
        self.assertEqual((self.directory / FILENAME).read_bytes(), existing)

    def test_invalid_status_does_not_echo_untrusted_study_title(self):
        forged = report(article())
        forged["items"][0]["title"] = "PRIVATE_LURE_FOR_LOG"
        forged["status"] = "NO_DATA"
        with self.assertRaises(DigestError) as caught:
            save(forged, self.directory)
        self.assertNotIn("PRIVATE_LURE_FOR_LOG", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
