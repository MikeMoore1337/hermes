"""H-03 daily missing-DOI recovery: bounded official core + Crossref."""
from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from research_scout.daily_digest import DigestError, TOPIC_IDS, prepare, save
from research_scout.article_integrity import ArticleIntegrityError

NOW = datetime(2026, 10, 18, 7, tzinfo=UTC)
DOI = "10.3389/fcimb.2026.1918695"
PMID = "42840492"
PMCID = "PMC13639859"


def sample(identifier=PMID):
    url = ("https://europepmc.org/articles/" if identifier.startswith("PMC")
           else "https://europepmc.org/article/MED/") + identifier
    return {
        "source": "EUROPE_PMC", "id": identifier, "source_url": url,
        "title": "Whey protein review", "doi": None,
        "first_publication_date": "2026-09-22",
        "status": "HOLD", "reason": "doi_missing",
        "scientific_claims_verified": False,
    }


def core(identifier=PMID, doi=DOI, codes=()):
    codes = list(codes)
    return {
        "article_source": "PMC" if identifier.startswith("PMC") else "MED",
        "article_identifier": identifier,
        "pmid": PMID if not identifier.startswith("PMC") else None,
        "pmcid": identifier if identifier.startswith("PMC") else PMCID,
        "doi": doi, "status": "HOLD" if (doi is None or codes) else "MANUAL_REVIEW",
        "notice_state": "REVIEW_REQUIRED" if codes else "NOT_REPORTED_IN_THIS_METADATA",
        "notice_codes": codes, "authoritative_notice_clearance": False,
        "scientific_claims_verified": False, "automatic_publication": False,
    }


def searcher(topic, *, now):
    assert now == NOW
    return {"topic": topic, "status": "MANUAL_REVIEW",
            "candidates": [sample()] if topic == TOPIC_IDS[0] else []}


class DailyDOIRecoveryTests(unittest.TestCase):
    def test_core_recovers_doi_within_existing_five_get_and_holds_science(self):
        registry = Mock(return_value={"status": "MANUAL_REVIEW", "doi": DOI})
        integrity = Mock(return_value=core())
        result = prepare(now=NOW, searcher=searcher, doi_verifier=registry,
                         integrity_verifier=integrity)
        integrity.assert_called_once_with("MED", PMID)
        registry.assert_called_once()
        self.assertEqual(result["requests_attempted"], 5)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["errors"], [])
        record = result["items"][0]
        self.assertEqual(record["doi"], DOI)
        self.assertEqual(record["reason"], "doi_enriched_review_required")
        self.assertEqual(record["status"], "HOLD")
        self.assertEqual(record["crossref_doi_status"], "MATCHED_METADATA_ONLY")
        self.assertFalse(result["scientific_claims_verified"])
        self.assertFalse(result["automatic_publication"])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            root.chmod(0o700)
            save(result, root)

    def test_pmc_without_doi_does_not_infer_pmid_link_or_retry(self):
        def find(topic, *, now):
            return {"topic": topic, "status": "MANUAL_REVIEW",
                    "candidates": [sample(PMCID)] if topic == TOPIC_IDS[0] else []}
        integrity = Mock(return_value=core(PMCID, doi=None))
        registry = Mock()
        result = prepare(now=NOW, searcher=find, doi_verifier=registry,
                         integrity_verifier=integrity)
        integrity.assert_called_once_with("PMC", PMCID)
        registry.assert_not_called()
        self.assertEqual(result["requests_attempted"], 4)
        self.assertEqual(result["items"][0]["status"], "HOLD")
        self.assertEqual(result["items"][0]["reason"], "doi_missing")

    def test_core_correction_retains_hold(self):
        result = prepare(now=NOW, searcher=searcher,
            doi_verifier=lambda candidate: {"status": "MANUAL_REVIEW",
                                            "doi": candidate["doi"]},
            integrity_verifier=lambda *_: core(codes=["CORRECTION_NOTICE"]))
        self.assertEqual(result["requests_attempted"], 5)
        self.assertEqual(result["items"][0]["reason"], "integrity_hold")
        self.assertEqual(result["items"][0]["article_notice_codes"],
                         ["CORRECTION_NOTICE"])
        self.assertEqual(result["status"], "HOLD")

    def test_unknown_identity_or_external_data_denied_before_registry(self):
        for override in (
            {"article_source": "PMC"}, {"article_identifier": "00000"},
            {"pmid": "999"}, {"scientific_claims_verified": True},
            {"automatic_publication": True},
            {"authoritative_notice_clearance": True},
            {"doi": "https://evil.test"},
            {"notice_state": "REVIEW_REQUIRED", "notice_codes": []},
            {"notice_state": "NOT_REPORTED_IN_THIS_METADATA",
             "notice_codes": ["CORRECTION_NOTICE"]},
        ):
            with self.subTest(override=override):
                fake = {**core(), **override}
                registry = Mock()
                result = prepare(now=NOW, searcher=searcher,
                                 doi_verifier=registry,
                                 integrity_verifier=Mock(return_value=fake))
                registry.assert_not_called()
                self.assertEqual(result["requests_attempted"], 4)
                self.assertEqual(result["items"][0]["reason"], "integrity_unknown")
                self.assertEqual(result["items"][0]["status"], "HOLD")
                self.assertEqual(result["status"], "HOLD")

    def test_failed_source_does_not_retry_or_spend_doi_get(self):
        registry = Mock()
        integrity = Mock(side_effect=ArticleIntegrityError("article_http_unavailable"))
        result = prepare(now=NOW, searcher=searcher,
                         doi_verifier=registry, integrity_verifier=integrity)
        integrity.assert_called_once()
        registry.assert_not_called()
        self.assertEqual(result["requests_attempted"], 4)
        self.assertEqual(result["items"][0]["article_notice_state"], "UNAVAILABLE")
        self.assertEqual(result["status"], "HOLD")

    def test_at_most_one_missing_doi_get_when_six_candidates(self):
        def many(topic, *, now):
            index = list(TOPIC_IDS).index(topic)
            return {"topic": topic, "status": "MANUAL_REVIEW",
                    "candidates": [sample(str(42840000+index*2+suffix))
                                   for suffix in range(2)]}
        integrity = Mock(return_value=core("42840000"))
        registry = Mock(return_value={"status": "MANUAL_REVIEW", "doi": DOI})
        result = prepare(now=NOW, searcher=many,
                         doi_verifier=registry, integrity_verifier=integrity)
        integrity.assert_called_once()
        registry.assert_called_once()
        self.assertEqual(result["requests_attempted"], 5)
        self.assertEqual(len(result["items"]), 6)
        self.assertTrue(all(x["status"] == "HOLD" for x in result["items"]))

    def test_forged_promotion_rejected_by_save(self):
        original = prepare(now=NOW, searcher=searcher,
            doi_verifier=lambda candidate: {"status": "MANUAL_REVIEW",
                                            "doi": candidate["doi"]},
            integrity_verifier=lambda *_: core())
        for mutation in (
            {"status": "MANUAL_REVIEW"},
            {"article_notice_state": "REVIEW_REQUIRED",
             "article_notice_codes": ["CORRECTION_NOTICE"]},
        ):
            forged = deepcopy(original)
            forged["items"][0].update(mutation)
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                directory.chmod(0o700)
                with self.assertRaises(DigestError):
                    save(forged, directory)


if __name__ == "__main__":
    unittest.main()
