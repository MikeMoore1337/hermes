"""I4 signed draft-only transfer: exhaustive offline boundary tests, zero live calls."""
from __future__ import annotations

from contextlib import redirect_stdout
from copy import deepcopy
import hashlib
import hmac
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from research_scout import yfc_draft_handoff as handoff


def article():
    return {
        "slug": "research-on-recovery",
        "title": "Ограничения научных исследований восстановления после нагрузки",
        "description": "Учебная статья о критической оценке источников",
        "lead": "Обсуждаем границы применимости исследований, не давая назначений.",
        "body_sections": [
            {"heading": "Почему результаты не универсальны",
             "paragraphs": ["У исследования есть выборка и методика, и поэтому "
                            "переносить выводы на каждого человека нельзя."]},
            {"heading": "Что требует дополнительной проверки",
             "paragraphs": ["Перед практическими рекомендациями следует проверить "
                            "полные тексты первичных работ и риски смещения."]},
        ],
        "topics": ["sports_nutrition"],
        "article_kind": "evidence_review",
        "search_intent": "evidence",
        "primary_query": "исследования восстановления",
        "secondary_queries": [],
        "risk_level": "moderate",
        "evidence_level": "limited",
        "claims": [
            {"claim_id": "claimone", "claim_text": "Обобщение требует осторожности",
             "normalized_claim": "Без независимого обзора не делать выводов"},
        ],
        "sources": [
            {"source_id": "paperone", "title": "Primary study one", "publisher": "PMC",
             "url": "https://pmc.ncbi.nlm.nih.gov/articles/PMC13610232/",
             "source_type": "systematic_review",
             "published_at": "2026-10-18", "limitations": "No independent claim signoff"},
            {"source_id": "papertwo", "title": "Primary study two", "publisher": "PMC",
             "url": "https://pmc.ncbi.nlm.nih.gov/articles/PMC13104005/",
             "source_type": "randomized_trial",
             "published_at": "2026-10-18", "limitations": "No independent claim signoff"},
        ],
        "claim_source_matrix": [
            {"claim_id": "claimone", "source_ids": ["paperone", "papertwo"],
             "support_level": "unclear", "limitations": "Cannot infer a clinical claim",
             "review_status": "pending"},
        ],
        "author": {"name": "Research Scout", "type": "Organization"},
        "editor": {"name": "YFC Editorial", "type": "Organization"},
        "domain_reviewer": None,
        "related_slugs": [], "cta": {},
        "evergreen_score": 50, "product_relevance": 30, "editorial_value": 50,
        "web_article_potential_reasons": [],
    }


class SourceBoundHandoffTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "primary"
        self.root.mkdir(mode=0o700)
        self.texts = {"paperone": b"Actual cached primary source text 1",
                      "papertwo": b"Actual cached primary source text 2"}
        sources = article()["sources"]
        receipts = []
        for source in sources:
            sid = source["source_id"]
            path = self.root / (sid + ".txt")
            path.write_bytes(self.texts[sid])
            path.chmod(0o600)
            receipts.append({"source_id": sid, "url": source["url"],
                             "full_text_sha256":
                                 hashlib.sha256(self.texts[sid]).hexdigest()})
        self.document = {
            "schema": handoff.SCHEMA, "article": article(),
            "research_version": "i4-20261026-source-gated",
            "source_receipts": receipts,
        }

    def build(self, data=None):
        return handoff.build_payload(self.document if data is None else data,
                                     source_dir=self.root)

    def test_deterministic_signed_payload_never_has_publish_operation(self):
        a, b = self.build(), self.build()
        self.assertEqual(a, b)
        self.assertEqual(a["schema_version"], "hermes-web-article-intake-v1")
        self.assertEqual(a["candidate_id"], b["candidate_id"])
        self.assertEqual(len(a["candidate_id"]), 32)
        self.assertEqual(a["provenance"]["provider"], "local")
        self.assertEqual(a["provenance"]["skill_version"], "yfc-hermes-editorial-v1")
        self.assertNotIn('"publish"', json.dumps(a))
        self.assertNotIn("root_token", repr(a))
        hdr = handoff.headers(a, "synthetic-hmac-secret-1234", "test-key", timestamp=123)
        body = handoff._encode(a)
        digest = hmac.new(b"synthetic-hmac-secret-1234",
                          b"123\n" + a["request_nonce"].encode() + b"\n" + body,
                          hashlib.sha256).hexdigest()
        self.assertEqual(hdr["X-Hermes-Signature"], "sha256=" + digest)
        self.assertEqual(hdr["X-Hermes-Nonce"], a["request_nonce"])
        self.assertEqual(hdr["Content-Type"], "application/json")
        self.assertEqual(handoff.INTAKE_URL,
                         "https://app.your-fitness-coach.ru/api/v1/hermes/articles/intake")

    def test_tampered_source_hash_mode_and_symlink_fail_closed(self):
        data = deepcopy(self.document)
        data["source_receipts"][0]["full_text_sha256"] = "0" * 64
        with self.assertRaisesRegex(handoff.HandoffHold, "PRIMARY_TEXT_DIGEST_MISMATCH"):
            self.build(data)
        path = self.root / "paperone.txt"
        path.chmod(0o644)
        with self.assertRaises(handoff.HandoffHold):
            self.build()
        path.unlink()
        path.symlink_to(self.root / "papertwo.txt")
        with self.assertRaises(handoff.HandoffHold):
            self.build()

    def test_missing_body_matrix_or_source_fails_before_credential_access(self):
        for change in ("no_body", "bad_review", "no_sources"):
            data = deepcopy(self.document)
            if change == "no_body":
                data["article"]["body_sections"] = []
            elif change == "bad_review":
                data["article"]["claim_source_matrix"][0]["review_status"] = "verified"
            else:
                data["article"]["sources"] = data["article"]["sources"][:1]
            with self.subTest(change=change):
                with self.assertRaises(handoff.HandoffHold):
                    self.build(data)

    def test_reject_arbitrary_unsafe_source_url_or_reviewer(self):
        for url in ("http://pmc.ncbi.nlm.nih.gov/a",
                    "https://pmc.ncbi.nlm.nih.gov.evil.test/a",
                    "https://pmc.ncbi.nlm.nih.gov/a?secret=1",
                    "https://user@pmc.ncbi.nlm.nih.gov/a"):
            data = deepcopy(self.document)
            data["article"]["sources"][0]["url"] = url
            with self.subTest(url=url):
                with self.assertRaisesRegex(handoff.HandoffHold, "SOURCE_URL_NOT_ALLOWLISTED"):
                    self.build(data)
        data = deepcopy(self.document)
        data["article"]["domain_reviewer"] = {"name": "Fake scientist", "type": "Person"}
        with self.assertRaises(handoff.HandoffHold):
            self.build(data)

    def test_payload_stable_and_content_changes_new_idempotency(self):
        first = self.build()
        updated = deepcopy(self.document)
        updated["article"]["body_sections"][1]["paragraphs"][0] += " Источник обновлён."
        second = self.build(updated)
        self.assertEqual(first["candidate_id"], second["candidate_id"])
        self.assertNotEqual(first["idempotency_key"], second["idempotency_key"])
        self.assertNotEqual(first["request_nonce"], second["request_nonce"])
        updated["article"]["sources"][0]["url"] = (
            "https://pmc.ncbi.nlm.nih.gov/articles/PMC00000001/")
        updated["source_receipts"][0]["url"] = updated["article"]["sources"][0]["url"]
        third = self.build(updated)
        self.assertNotEqual(first["candidate_id"], third["candidate_id"])

    def test_approval_required_and_never_blind_retry(self):
        payload = self.build()
        opener = MagicMock()
        with self.assertRaisesRegex(handoff.HandoffHold, "OWNER_SUBMIT_GATE_CLOSED"):
            handoff.transmit(payload, secret="synthetic-hmac-secret-1234",
                             key_id="test-key", approved=False, opener=opener)
        opener.open.assert_not_called()
        response = MagicMock()
        response.status = 200
        response.url = handoff.INTAKE_URL
        response.read.return_value = json.dumps({
            "status": "accepted", "article_status": "draft",
            "article_id": "a" * 32, "content_version": 1,
        }).encode()
        opener.open.return_value.__enter__.return_value = response
        result = handoff.transmit(payload, secret="synthetic-hmac-secret-1234",
                                  key_id="test-key", approved=True, opener=opener)
        self.assertEqual(result, "accepted")
        opener.open.assert_called_once()
        response.url = "https://malicious.invalid/redirect"
        with self.assertRaisesRegex(handoff.HandoffHold, "INTAKE_RESPONSE_UNTRUSTED"):
            handoff.transmit(payload, secret="synthetic-hmac-secret-1234",
                             key_id="test-key", approved=True, opener=opener)

    def test_response_never_treats_published_as_draft(self):
        opener = MagicMock()
        res = MagicMock()
        res.status = 200
        res.url = handoff.INTAKE_URL
        res.read.return_value = json.dumps({
            "status": "accepted", "article_status": "published",
            "article_id": "a" * 32, "content_version": 1,
        }).encode()
        opener.open.return_value.__enter__.return_value = res
        with self.assertRaisesRegex(handoff.HandoffHold, "INTAKE_RESPONSE_UNTRUSTED"):
            handoff.transmit(self.build(), secret="synthetic-hmac-secret-1234",
                             key_id="test-key", approved=True, opener=opener)

    def test_missing_source_and_secret_never_print_private_material(self):
        with patch.object(handoff, "REVIEWED_FILE", Path("/missing/file")):
            stream = io.StringIO()
            with redirect_stdout(stream):
                self.assertEqual(handoff.main([]), 2)
            data = json.loads(stream.getvalue())
            self.assertEqual(data["status"], "HOLD")
            self.assertFalse(data["publisher_invoked"])
            self.assertNotIn("missing/file", stream.getvalue())
        with self.assertRaisesRegex(handoff.HandoffHold, "HMAC_NOT_CONFIGURED"):
            handoff.headers(self.build(), "", "", timestamp=1)


if __name__ == "__main__":
    unittest.main()
