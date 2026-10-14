"""No-network end-to-end Research Scout search/review tests."""
from __future__ import annotations

import io
import unittest
from datetime import UTC, datetime
from unittest.mock import patch

from research_scout.ncbi_end_to_end import review_topic, main
from research_scout.ncbi_esummary import NCBIError
from research_scout.citation_review import CitationInputError

NOW = datetime(2026, 10, 14, 15, 0, tzinfo=UTC)
EMAIL = "maintainer@example.org"


def search(topic, *, contact):
    return {"status": "UNVERIFIED_PMID_CANDIDATES",
            "topic": topic, "pmids": ["36334240", "37120382"]}


def item(pmid, *, contact):
    return {
        "status": "UNVERIFIED_METADATA", "pmid": pmid,
        "source_url": f"https://pubmed.ncbi.nlm.nih.gov/{pmid}/",
        "citation_title": "Strength training and outcomes",
        "citation_doi": f"10.1234/study.{pmid}",
        "publication_date_candidate": "2026 Oct 14",
        "source_api": "NCBI_ESUMMARY",
    }


class ManualResearchTests(unittest.TestCase):
    def test_two_citations_manual_review_without_scientific_claims(self):
        seen = []
        gaps = []
        result = review_topic("resistance-training", contact=EMAIL,
                              search=search, citation=lambda pmid, *, contact: (
                                  seen.append((pmid, contact)) or item(pmid, contact=contact)
                              ), pause=gaps.append, now=NOW)
        self.assertEqual(result["status"], "MANUAL_REVIEW")
        self.assertEqual(len(result["review"]["items"]), 2)
        self.assertEqual(gaps, [1.0, 1.0])
        self.assertEqual(len(seen), 2)
        self.assertFalse(result["scientific_claims_verified"])
        self.assertFalse(result["review"]["scientific_claims_verified"])

    def test_unknown_topic_and_missing_email_refused_before_any_fetch(self):
        for topic, contact in (("private-query", EMAIL), ("resistance-training", "")):
            with self.subTest(topic=topic), self.assertRaises(NCBIError):
                review_topic(topic, contact=contact,
                             search=lambda *_a, **_k: self.fail("must not fetch"),
                             now=NOW)

    def test_no_data_stops_without_citation_lookup(self):
        result = review_topic("exercise-recovery", contact=EMAIL,
                              search=lambda *_a, **_k: {
                                  "status": "NO_DATA", "pmids": []
                              },
                              citation=lambda *_a, **_k: self.fail("must not lookup"),
                              pause=lambda _: self.fail("must not pause"), now=NOW)
        self.assertEqual(result["status"], "NO_DATA")

    def test_malformed_or_duplicate_esearch_ids_never_reach_esummary(self):
        for ids in (["36334240", "36334240"], ["http://127.0.0.1/"], [12345678]):
            with self.subTest(ids=ids), self.assertRaises(NCBIError):
                review_topic("exercise-recovery", contact=EMAIL,
                             search=lambda *_a, **_k: {
                                 "status": "UNVERIFIED_PMID_CANDIDATES", "pmids": ids
                             },
                             citation=lambda *_a, **_k: self.fail("must not lookup"),
                             now=NOW)

    def test_quarantined_article_stops_before_second_lookup(self):
        calls = []
        def citation(pmid, *, contact):
            calls.append(pmid)
            return {"status": "QUARANTINE", "pmid": pmid,
                    "reason": "suspicious_citation_title"}
        result = review_topic("resistance-training", contact=EMAIL,
                              search=search, citation=citation,
                              pause=lambda _: None, now=NOW)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(calls, ["36334240"])
        self.assertNotIn("review", result)

    def test_network_failure_cannot_become_partial_success(self):
        with self.assertRaisesRegex(NCBIError, "provider_unavailable"):
            review_topic("resistance-training", contact=EMAIL,
                         search=search, citation=lambda *_a, **_k: (
                             (_ for _ in ()).throw(NCBIError("provider_unavailable"))
                         ), pause=lambda _: None, now=NOW)

    def test_cross_source_pmid_mismatch_fails_closed(self):
        with self.assertRaisesRegex(NCBIError, "ncbi_citation_inconsistent"):
            review_topic("resistance-training", contact=EMAIL,
                         search=search, citation=lambda *_a, **_k: {
                             "status": "UNVERIFIED_METADATA", "pmid": "99999999"
                         }, pause=lambda _: None, now=NOW)

    def test_ambiguous_article_publication_date_is_hold(self):
        result = review_topic("resistance-training", contact=EMAIL,
                              search=search, citation=lambda pmid, *, contact: {
                                  **item(pmid, contact=contact),
                                  "publication_date_candidate": "2026 Oct",
                              }, pause=lambda _: None, now=NOW)
        self.assertEqual(result["status"], "HOLD")

    def test_no_explicit_execute_never_runs_network(self):
        import json
        import sys
        out = io.StringIO()
        with patch("sys.argv", ["research-scout", "--topic", "resistance-training"]), \
             patch("sys.stdout", out), patch("research_scout.ncbi_end_to_end.review_topic") as call:
            self.assertEqual(main(), 2)
        call.assert_not_called()
        self.assertEqual(json.loads(out.getvalue())["reason"], "explicit_execute_required")

    def test_missing_environment_contact_never_opens_network(self):
        import json
        out = io.StringIO()
        with patch("sys.argv", ["research-scout", "--execute", "--topic", "resistance-training"]), \
             patch("sys.stdout", out), patch.dict("os.environ", {}, clear=True), \
             patch("research_scout.ncbi_end_to_end.find_candidates") as call:
            self.assertEqual(main(), 2)
        call.assert_not_called()
        self.assertEqual(json.loads(out.getvalue())["status"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
