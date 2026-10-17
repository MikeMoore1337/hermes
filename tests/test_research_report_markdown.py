"""H-03 metadata report remains offline, bounded and non-authoritative."""
from __future__ import annotations

import unittest

from research_scout.report_markdown import ReportError, render


def packet(*, status="MANUAL_REVIEW", items=None):
    return {
        "schema": "hermes-research-metadata-v1",
        "observed_at": "2026-10-17T12:00:00+00:00",
        "status": status,
        "requests_attempted": 3,
        "topics": ["resistance-training", "muscle-hypertrophy", "exercise-recovery"],
        "items": [] if items is None else items,
        "errors": [],
        "scientific_claims_verified": False,
        "automatic_publication": False,
        "report_requires_manual_review": True,
    }


def candidate(**changes):
    item = {
        "topic": "exercise-recovery",
        "title": "Example research",
        "identifier": "42733310",
        "source_url": "https://europepmc.org/article/MED/42733310",
        "doi": "10.1002/ejsc.70246",
        "status": "MANUAL_REVIEW",
        "reason": "metadata_only",
        "publication_date": "2026-10-10",
        "crossref_doi_status": "NOT_CHECKED",
        "article_notice_state": "NOT_CHECKED",
        "article_notice_codes": [],
        "scientific_claims_verified": False,
    }
    item.update(changes)
    return item


class ReportMarkdownTests(unittest.TestCase):
    def test_empty_packet_has_no_verified_research(self):
        text = render(packet(status="NO_DATA"))
        self.assertIn("Проверенные научные материалы (0)", text)
        self.assertIn("независимую проверку", text.lower())

    def test_reviewable_metadata_is_not_promoted_to_science(self):
        text = render(packet(items=[candidate()]))
        self.assertIn("Ожидают научной проверки (1)", text)
        self.assertIn("Не установлено", text)
        self.assertIn("не подтверждено", text.lower())
        self.assertNotIn("научно доказано", text.lower())

    def test_hold_and_integrity_warning_are_visible(self):
        item = candidate(status="HOLD", reason="integrity_hold",
                         article_notice_state="REVIEW_REQUIRED",
                         article_notice_codes=["CORRECTION_NOTICE"])
        text = render(packet(status="HOLD", items=[item]))
        self.assertIn("Исправления / отзыв", text)
        self.assertIn("HOLD", text)
        self.assertIn("Проверенные научные материалы (0)", text)

    def test_inconsistent_aggregate_status_rejected(self):
        with self.assertRaises(ReportError):
            render(packet(items=[candidate(status="HOLD", reason="doi_missing", doi=None)]))

    def test_forged_scientific_clearance_rejected(self):
        data = packet(items=[candidate()])
        data["scientific_claims_verified"] = True
        with self.assertRaises(ReportError):
            render(data)

    def test_markup_is_escaped(self):
        text = render(packet(items=[candidate(title="<script>**bold**")]))
        self.assertIn("&lt;script&gt;", text)
        self.assertNotIn("<script>", text)

    def test_duplicate_item_not_double_counted(self):
        item = candidate()
        text = render(packet(items=[item, dict(item)]))
        self.assertIn("Ожидают научной проверки (1)", text)


if __name__ == "__main__":
    unittest.main()
