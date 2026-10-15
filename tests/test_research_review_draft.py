"""Source-bound Research Scout drafts remain manual-review artifacts."""
from __future__ import annotations

import json
import subprocess
import sys
import unittest

from research_scout.review_draft import (
    MANUAL_REVIEW,
    ReviewDraftError,
    build_draft,
    build_daily_item_draft,
    compare_drafts,
)


def candidate(**extra):
    value = {
        "source": "EUROPE_PMC",
        "id": "12345678",
        "source_url": "https://pubmed.ncbi.nlm.nih.gov/12345678/",
        "title": "Resistance training study",
        "doi": "10.1000/example.2026",
        "status": "MANUAL_REVIEW",
        "reason": "metadata_only",
        "first_publication_date": "2026-10-14",
        "scientific_claims_verified": False,
    }
    value.update(extra)
    return value


class ReviewDraftTests(unittest.TestCase):
    def test_manually_supplied_excerpt_is_not_automatic_scientific_verification(self) -> None:
        full_text = "https://bjsm.bmj.com/content/58/1/1"
        draft = build_draft(candidate(confirmed={
            "sample_size": {
                "value": 120, "source_url": full_text,
                "review_basis": "operator_reviewed_full_text",
                "supporting_excerpt": "The trial enrolled 120 participants.",
            },
            "methods": {
                "value": "parallel groups", "source_url": full_text,
                "review_basis": "operator_reviewed_full_text",
                "supporting_excerpt": "Participants were allocated to parallel groups.",
            },
        }))
        self.assertEqual(draft["status"], MANUAL_REVIEW)
        self.assertEqual(draft["sample_size"], 120)
        self.assertEqual(draft["source_kind"], "bibliographic_index")
        self.assertEqual(draft["primary_source_link"], full_text)
        self.assertEqual(draft["primary_source_access"],
                         "OPERATOR_REVIEW_ATTESTED_NOT_INDEPENDENTLY_VERIFIED")
        self.assertFalse(draft["provenance"]["full_text_independently_verified"])
        self.assertEqual(draft["expert_review_status"], "MANUAL_REVIEW_REQUIRED")
        self.assertFalse(draft["scientific_claims_verified"])

    def test_incomplete_metadata_is_explicitly_unknown(self) -> None:
        draft = build_draft(candidate(doi=None, first_publication_date=None))
        self.assertEqual(draft["publication_date"], "UNKNOWN")
        self.assertEqual(draft["identifiers"]["doi"], "UNKNOWN")
        self.assertEqual(draft["methods"], "UNKNOWN")
        self.assertEqual(draft["sample_size"], "UNKNOWN")
        self.assertEqual(draft["uncertainty"], "high")

    def test_secondary_source_does_not_become_primary(self) -> None:
        draft = build_draft(candidate(
            source_url="https://www.sciencedaily.com/releases/2026/10/1.htm",
            doi=None,
        ))
        self.assertEqual(draft["source_kind"], "secondary")
        self.assertEqual(draft["primary_source_link"], "UNKNOWN")
        self.assertEqual(draft["primary_source_access"], "NOT_VERIFIED")

    def test_indexed_correction_record_is_not_a_verified_full_text(self) -> None:
        with self.assertRaisesRegex(ReviewDraftError, "confirmed_field_provenance_invalid"):
            build_draft(candidate(confirmed={
                "correction_status": {
                    "value": "correction confirmed by publisher",
                    "source_url": "https://pubmed.ncbi.nlm.nih.gov/12345678/",
                },
            }))
        draft = build_draft(candidate())
        self.assertEqual(draft["correction_status"], "UNKNOWN")
        self.assertEqual(draft["primary_source_link"], "UNKNOWN")

    def test_comparison_does_not_infer_conflict_or_consensus(self) -> None:
        first = build_draft(candidate())
        second = build_draft(candidate(id="PMC12345678", title="Another study"))
        result = compare_drafts([first, second])
        self.assertEqual(result["status"], MANUAL_REVIEW)
        self.assertEqual(result["contradictory_results"], "NOT_ASSESSED_WITHOUT_EXPERT_REVIEW")
        self.assertEqual(result["meta_analysis"], "NOT_PERFORMED")

    def test_unsafe_claims_and_untrusted_confirmations_are_rejected(self) -> None:
        with self.assertRaisesRegex(ReviewDraftError, "confirmed_field_requires_full_text_evidence"):
            build_draft(candidate(confirmed={
                "main_results": {
                    "value": "guaranteed cure",
                    "source_url": "https://www.sciencedaily.com/releases/2026/10/1.htm",
                    "review_basis": "operator_reviewed_full_text",
                    "supporting_excerpt": "Claimed effect.",
                },
            }))
        with self.assertRaisesRegex(ReviewDraftError, "scientific_verification_not_allowed"):
            build_draft(candidate(scientific_claims_verified=True))

    def test_bibliographic_and_doi_are_not_primary_full_text(self) -> None:
        for url, kind in (
            ("https://pubmed.ncbi.nlm.nih.gov/12345678/", "bibliographic_index"),
            ("https://europepmc.org/articles/PMC123456", "bibliographic_index"),
            ("https://doi.org/10.1000/example", "doi_resolver"),
            ("https://bjsm.bmj.com/content/58/1/1", "publisher_page"),
        ):
            with self.subTest(url=url):
                draft = build_draft(candidate(source_url=url))
                self.assertEqual(draft["source_kind"], kind)
                self.assertEqual(draft["primary_source_link"], "UNKNOWN")
                self.assertEqual(draft["primary_source_access"], "NOT_VERIFIED")

    def test_pubmed_excerpt_claim_cannot_impersonate_full_text(self) -> None:
        with self.assertRaisesRegex(ReviewDraftError, "confirmed_field_requires_full_text_evidence"):
            build_draft(candidate(confirmed={
                "methods": {
                    "value": "parallel groups",
                    "source_url": "https://pubmed.ncbi.nlm.nih.gov/12345678/",
                    "review_basis": "operator_reviewed_full_text",
                    "supporting_excerpt": "Parallel groups.",
                },
            }))

    def test_actual_daily_item_stays_metadata_only(self) -> None:
        from research_scout.daily_digest import TOPIC_IDS
        item = {
            "topic": next(iter(TOPIC_IDS)),
            "title": "Plant-Derived Whole Foods and Food-Based Supplements",
            "identifier": "42797032",
            "source_url": "https://europepmc.org/article/MED/42797032",
            "doi": "10.3390/nu18183049",
            "status": "MANUAL_REVIEW",
            "reason": "metadata_only",
            "publication_date": "2026-09-18",
            "crossref_doi_status": "NOT_CHECKED",
            "article_notice_state": "NOT_CHECKED",
            "article_notice_codes": [],
            "scientific_claims_verified": False,
        }
        draft = build_daily_item_draft(item)
        self.assertEqual(draft["identifiers"]["pmid"], "42797032")
        self.assertEqual(draft["source_kind"], "bibliographic_index")
        self.assertEqual(draft["study_type"], "UNKNOWN")
        self.assertEqual(draft["main_results"], "UNKNOWN")
        self.assertEqual(draft["correction_status"], "UNKNOWN")
        self.assertEqual(draft["source_daily_report"]["article_notice_state"], "NOT_CHECKED")
        self.assertFalse(draft["scientific_claims_verified"])
        self.assertFalse(draft["automatic_publication"])
        cli = subprocess.run(
            [sys.executable, "-m", "research_scout.review_draft", "--daily-item-stdin"],
            input=json.dumps(item).encode("utf-8"), capture_output=True, check=False,
        )
        self.assertEqual(cli.returncode, 0, cli.stderr)
        self.assertEqual(json.loads(cli.stdout)["status"], "MANUAL_REVIEW")

        item["article_notice_state"] = "REVIEW_REQUIRED"
        item["article_notice_codes"] = ["CORRECTION_NOTICE"]
        with self.assertRaisesRegex(ReviewDraftError, "daily_item_notice_not_held"):
            build_daily_item_draft(item)
        item["status"] = "HOLD"
        self.assertEqual(build_daily_item_draft(item)["status"], "HOLD")
        item["scientific_claims_verified"] = True
        with self.assertRaisesRegex(ReviewDraftError, "daily_item_contract_invalid"):
            build_daily_item_draft(item)
        item["scientific_claims_verified"] = False
        item["unexpected"] = "injection"
        with self.assertRaisesRegex(ReviewDraftError, "daily_item_schema_invalid"):
            build_daily_item_draft(item)


    def test_cli_is_explicit_and_offline(self) -> None:
        payload = json.dumps(candidate()).encode()
        completed = subprocess.run(
            [sys.executable, "-m", "research_scout.review_draft", "--review-stdin"],
            input=payload,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(json.loads(completed.stdout)["status"], MANUAL_REVIEW)


if __name__ == "__main__":
    unittest.main()
