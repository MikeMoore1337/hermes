"""Offline #599 claim packet composition tests: synthetic content only."""
from copy import deepcopy
from datetime import date
import hashlib
from pathlib import Path
import tempfile
import unittest

from research_scout import yfc_article_composer as composer


def sample():
    sources = [
        {"source_id": "paperone", "title": "Synthetic paper one",
         "publisher": "Journal", "source_type": "randomized_trial",
         "url": "https://pmc.ncbi.nlm.nih.gov/articles/PMC13610232/",
         "published_at": "2026-10-18", "limitations": "Synthetic fixture"},
        {"source_id": "papertwo", "title": "Synthetic paper two",
         "publisher": "Journal", "source_type": "systematic_review",
         "url": "https://pmc.ncbi.nlm.nih.gov/articles/PMC13104005/",
         "published_at": "2026-10-18", "limitations": "Synthetic fixture"},
    ]
    return {
        "schema": composer.SCHEMA,
        "research_version": "i4-test-reviewed-v1",
        "metadata": {
            "slug": "how-to-read-training-studies",
            "title": "Как изучать исследования о тренировках",
            "description": "Учебный материал о научных источниках",
            "lead": "Научные результаты необходимо оценивать с учётом условий исследования.",
            "topics": ["sports_nutrition"],
            "primary_query": "как интерпретировать исследования о тренировках",
            "risk_level": "low", "evidence_level": "unknown",
        },
        "sources": sources,
        "source_receipts": [],
        "licence_reviews": [{
            "source_id": source["source_id"],
            "licence_id": "CC-BY-4.0",
            "licence_url": "https://creativecommons.org/licenses/by/4.0/",
            "notice_status": "NO_UNRESOLVED_NOTICE_REPORTED",
            "checked_on": date.today().isoformat(),
            "basis": "OPERATOR_READ_PUBLISHER_FULL_TEXT",
        } for source in sources],
        "claims": [{
            "claim_id": "claimone",
            "claim_text": "Нужно учитывать особенности исследовательского дизайна",
            "normalized_claim": "Дизайн исследования влияет на интерпретацию",
            "interpretation": "Учебная интерпретация вводится оператором и не выводится из библиографической карточки автоматически.",
            "limitations": "Не следует переносить результаты на всех людей без оценки выборки и ограничений методологии.",
            "source_ids": ["paperone", "papertwo"],
        }],
    }


class ComposerTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name) / "texts"
        self.root.mkdir(mode=0o700)
        self.doc = sample()
        for item in self.doc["sources"]:
            data = ("synthetic cached primary text " + item["source_id"]).encode()
            f = self.root / (item["source_id"] + ".txt")
            f.write_bytes(data)
            f.chmod(0o600)
            self.doc["source_receipts"].append({
                "source_id": item["source_id"], "url": item["url"],
                "full_text_sha256": hashlib.sha256(data).hexdigest(),
            })

    def make(self, doc=None):
        return composer.compose(self.doc if doc is None else doc,
                                source_dir=self.root)

    def test_deterministic_and_never_published_or_science_verified(self):
        result = self.make()
        self.assertEqual(result, self.make())
        self.assertEqual(result["status"], "READY_NOT_SUBMITTED")
        self.assertFalse(result["hmac_submission_allowed"])
        self.assertFalse(result["automatic_publication"])
        article = result["document"]["article"]
        self.assertEqual(len(article["body_sections"]), 2)
        self.assertEqual(article["claim_source_matrix"][0]["review_status"], "pending")
        self.assertEqual(article["claim_source_matrix"][0]["support_level"], "unclear")
        self.assertIsNone(article["domain_reviewer"])

    def test_source_rights_notice_and_stale_fail_closed(self):
        for key, bad in [
            ("licence_id", "ALL_RIGHTS_RESERVED"),
            ("licence_url", "https://invalid.example/"),
            ("notice_status", "CORRECTION"),
            ("checked_on", "2020-01-01"),
            ("basis", "AI_ASSUMED"),
        ]:
            with self.subTest(key=key):
                doc = deepcopy(self.doc)
                doc["licence_reviews"][0][key] = bad
                with self.assertRaises(composer.ComposerHold):
                    self.make(doc)

    def test_claims_must_be_curated_and_supported(self):
        for key, bad in [
            ("source_ids", ["paperone"]),
            ("source_ids", ["paperone", "untrusted"]),
            ("interpretation", "short"),
            ("interpretation", "<script>bad()</script>"),
        ]:
            with self.subTest(key=key):
                doc = deepcopy(self.doc)
                doc["claims"][0][key] = bad
                with self.assertRaises(composer.ComposerHold):
                    self.make(doc)

    def test_tampered_protected_primary_text_rejected(self):
        (self.root / "paperone.txt").write_text("tampered")
        with self.assertRaisesRegex(composer.ComposerHold, "PROVENANCE_OR_HANDOFF_GATE_HOLD"):
            self.make()

    def test_metadata_only_not_an_article(self):
        doc = deepcopy(self.doc)
        doc["claims"] = []
        with self.assertRaises(composer.ComposerHold):
            self.make(doc)


if __name__ == "__main__":
    unittest.main()
