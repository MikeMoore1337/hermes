"""#599 first genuine-source article candidate: structural, nonpublication gates.

The candidate is deliberately NOT a source-reviewed transfer envelope.
It contains no source SHA receipts, rights approval or HMAC credentials.
"""
from __future__ import annotations

import json
from pathlib import Path
import unittest

from research_scout import yfc_draft_handoff as handoff

ROOT = Path(__file__).resolve().parents[1]
CANDIDATE = (
    ROOT / "research_scout" / "reviews" /
    "i4-lifting-load-candidate-2026-10-27.json"
)


class FirstArticleCandidateTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads(CANDIDATE.read_text(encoding="utf-8"))

    def test_full_ru_article_and_evidence_matrix_are_bounded_and_traceable(self):
        document = self.document
        self.assertEqual(
            set(document),
            {"schema", "research_version", "article", "source_receipts"},
        )
        self.assertEqual(document["schema"], handoff.SCHEMA)
        article = document["article"]
        self.assertEqual(article["article_kind"], "evidence_review")
        self.assertEqual(article["search_intent"], "evidence")
        self.assertEqual(article["evidence_level"], "limited")
        self.assertIsNone(article["domain_reviewer"])
        self.assertEqual(len(article["sources"]), 2)
        self.assertGreaterEqual(len(article["body_sections"]), 5)
        self.assertGreaterEqual(
            sum(len(section["paragraphs"]) for section in article["body_sections"]),
            12,
        )
        self.assertGreaterEqual(len(article["claims"]), 4)
        self.assertTrue(any("1ПМ" in para for section in article["body_sections"]
                            for para in section["paragraphs"]))
        self.assertTrue(all(
            item["review_status"] == "pending" and item["support_level"] == "unclear"
            for item in article["claim_source_matrix"]
        ))
        self.assertEqual(
            {row["claim_id"] for row in article["claim_source_matrix"]},
            {row["claim_id"] for row in article["claims"]},
        )
        self.assertEqual({source["source_id"] for source in article["sources"]},
                         {"fink2016", "vann2022"})
        self.assertTrue(all(source["url"].startswith(
            "https://pmc.ncbi.nlm.nih.gov/articles/PMC"
        ) for source in article["sources"]))
        slug, sources = handoff._validate_article(article)
        self.assertEqual(slug, article["slug"])
        self.assertEqual(len(sources), 2)

    def test_no_fake_primary_receipts_and_no_submission_or_publication(self):
        document = self.document
        self.assertEqual(document["source_receipts"], [])
        self.assertNotIn("publication_allowed", document["article"])
        self.assertNotIn("published", document["article"])
        self.assertNotIn("scientific_claims_verified", document["article"])
        self.assertNotIn("secret", json.dumps(document, ensure_ascii=False).lower())
        with self.assertRaisesRegex(
            handoff.HandoffHold, "PRIMARY_TEXT_RECEIPTS_MISSING"
        ):
            handoff.build_payload(document)
        # Fail-closed before HMAC handling, credential access or any network I/O.

    def test_owner_cannot_accidentally_relabel_candidate_as_ready(self):
        self.assertNotIn("licence_reviews", self.document)
        self.assertNotIn("rights_independently_verified", self.document)
        self.assertNotIn("verified", {
            row["review_status"]
            for row in self.document["article"]["claim_source_matrix"]
        })


if __name__ == "__main__":
    unittest.main()
