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
    def test_well_documented_fixture_requires_primary_provenance(self) -> None:
        draft = build_draft(candidate(confirmed={
            "study_type": {"value": "randomized trial", "source_url": "https://pubmed.ncbi.nlm.nih.gov/12345678/"},
            "population": {"value": "adults", "source_url": "https://pubmed.ncbi.nlm.nih.gov/12345678/"},
            "sample_size": {"value": 120, "source_url": "https://pubmed.ncbi.nlm.nih.gov/12345678/"},
            "methods": {"value": "parallel groups", "source_url": "https://pubmed.ncbi.nlm.nih.gov/12345678/"},
            "main_results": {"value": "effect not extracted by this fixture", "source_url": "https://pubmed.ncbi.nlm.nih.gov/12345678/"},
            "limitations": {"value": "short follow-up", "source_url": "https://pubmed.ncbi.nlm.nih.gov/12345678/"},
        }))
        self.assertEqual(draft["status"], MANUAL_REVIEW)
        self.assertEqual(draft["sample_size"], 120)
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

    def test_correction_is_only_a_confirmed_field(self) -> None:
        draft = build_draft(candidate(confirmed={
            "correction_status": {
                "value": "correction confirmed by publisher",
                "source_url": "https://pubmed.ncbi.nlm.nih.gov/12345678/",
            },
        }))
        self.assertEqual(draft["correction_status"], "correction confirmed by publisher")
        self.assertEqual(draft["provenance"]["confirmed_fields"]["correction_status"],
                         "https://pubmed.ncbi.nlm.nih.gov/12345678/")

    def test_comparison_does_not_infer_conflict_or_consensus(self) -> None:
        first = build_draft(candidate())
        second = build_draft(candidate(id="PMC12345678", title="Another study"))
        result = compare_drafts([first, second])
        self.assertEqual(result["status"], MANUAL_REVIEW)
        self.assertEqual(result["contradictory_results"], "NOT_ASSESSED_WITHOUT_EXPERT_REVIEW")
        self.assertEqual(result["meta_analysis"], "NOT_PERFORMED")

    def test_unsafe_claims_and_untrusted_confirmations_are_rejected(self) -> None:
        with self.assertRaisesRegex(ReviewDraftError, "confirmed_field_requires_primary_source"):
            build_draft(candidate(confirmed={
                "main_results": {
                    "value": "guaranteed cure",
                    "source_url": "https://www.sciencedaily.com/releases/2026/10/1.htm",
                },
            }))
        with self.assertRaisesRegex(ReviewDraftError, "scientific_verification_not_allowed"):
            build_draft(candidate(scientific_claims_verified=True))

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
