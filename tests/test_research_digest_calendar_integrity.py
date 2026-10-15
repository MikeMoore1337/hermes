"""A persisted MANUAL_REVIEW must have a real, timely publication date."""
from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from research_scout.daily_digest import DigestError, FILENAME, save
from tests.test_research_digest_status_invariants import article, report


class ResearchCalendarIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hermes-research-date-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.directory.chmod(0o700)

    def rejects(self, record):
        with self.assertRaises(DigestError):
            save(record, self.directory)
        self.assertFalse((self.directory / FILENAME).exists())

    def test_invalid_calendar_date_cannot_be_reviewed(self):
        for invalid in ("2026-02-30", "2026-13-01", "0000-01-01"):
            record = report(article())
            record["items"][0]["publication_date"] = invalid
            with self.subTest(invalid=invalid):
                self.rejects(record)

    def test_future_publication_date_cannot_remain_reviewable(self):
        record = report(article())
        record["items"][0]["publication_date"] = "2027-01-01"
        self.rejects(record)

    def test_stale_publication_date_cannot_remain_reviewable(self):
        record = report(article())
        record["items"][0]["publication_date"] = "2026-08-01"
        self.rejects(record)

    def test_manual_review_without_published_date_is_refused(self):
        record = report(article())
        record["items"][0]["publication_date"] = None
        self.rejects(record)

    def test_valid_current_date_and_stale_hold_are_permitted(self):
        recent = report(article())
        save(recent, self.directory)
        self.assertTrue((self.directory / FILENAME).exists())
        stale = copy.deepcopy(recent)
        stale["items"][0]["publication_date"] = "2024-01-01"
        stale["items"][0]["status"] = "HOLD"
        stale["items"][0]["reason"] = "stale_publication_date"
        stale["status"] = "HOLD"
        save(stale, self.directory)
        self.assertEqual((self.directory / FILENAME).stat().st_mode & 0o777, 0o600)

    def test_hold_with_nonsensical_calendar_date_is_rejected(self):
        record = report(article())
        record["items"][0]["publication_date"] = "2026-99-15"
        record["items"][0]["status"] = "HOLD"
        record["items"][0]["reason"] = "invalid_publication_date"
        record["status"] = "HOLD"
        self.rejects(record)


if __name__ == "__main__":
    unittest.main()
