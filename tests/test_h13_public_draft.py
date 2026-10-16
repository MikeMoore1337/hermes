"""H-13 offline public draft candidate checks and deliberate false-positive sampling."""
import json
import subprocess
import sys
import unittest
from editorial_review.public_draft import EditorialReviewError, review, SCHEMA

def sample(text, source_ids=None):
    return {
        "schema": SCHEMA, "visibility": "PUBLIC_SYNTHETIC",
        "kind": "scientific_draft", "text": text,
        "source_ids": ["S1"] if source_ids is None else source_ids,
    }

def codes(text, sources=None):
    return [x["code"] for x in review(sample(text, sources))["findings"]]

class H13Tests(unittest.TestCase):
    def test_uncited_percentage_requires_editor(self):
        out = review(sample("Частота реакции составила 25%."))
        self.assertEqual(out["status"], "MANUAL_REVIEW_REQUIRED")
        self.assertIn("QUANTITY_WITHOUT_CITATION", [x["code"] for x in out["findings"]])
        self.assertFalse(out["publication_allowed"])
        self.assertFalse(out["source_content_verified"])

    def test_known_citation_is_not_proof_of_truth(self):
        out = review(sample("Частота реакции составила 25% [ref:S1]."))
        self.assertEqual(out["status"], "NO_FLAGS_NOT_APPROVAL")
        self.assertFalse(out["medical_accuracy_verified"])
        self.assertFalse(out["publication_allowed"])

    def test_invalid_reference_detected(self):
        self.assertIn("UNKNOWN_CITATION", codes("Результат 25% [ref:S2]."))

    def test_medical_absolute_claim_flagged(self):
        for text in ("Продукт гарантированно лечит.",
                     "Добавка полностью безопасен.",
                     "Продукт не имеет побочных эффектов."):
            with self.subTest(text=text):
                self.assertIn("MEDICAL_ABSOLUTE_CLAIM", codes(text))

    def test_legal_assertion_requires_lawyer(self):
        out = review(sample("Штраф составит определённую сумму."))
        self.assertIn("LEGAL_ASSERTION", [x["code"] for x in out["findings"]])
        self.assertEqual(out["findings"][0]["requires"], "LAWYER_REVIEW")
        self.assertFalse(out["legal_compliance_verified"])

    def test_clean_russian_corpus_has_no_flags(self):
        # Small synthetic negative corpus, not a statistically representative estimate.
        clean = ("Цель обзора — определить вопросы для дальнейшей проверки.",
                 "Результаты этого обзора не заменяют оценку первоисточников.",
                 "Методология и ограничения описаны отдельно.",
                 "Авторы рассматривают разные подходы к оценке восстановления.")
        for text in clean:
            with self.subTest(text=text):
                self.assertEqual(codes(text), [])

    def test_code_blocks_not_assessed_as_editorial_claims(self):
        tick = chr(96)*3
        self.assertEqual(codes("Пример конфигурации:\n"+tick+"\n60%\n"+tick+
                               "\nЭто пример, а не научное утверждение."), [])

    def test_bounded_rejects_private_or_unapproved_inputs(self):
        for override in (
            {"visibility": "PRIVATE_VAULT"},
            {"kind": "legal_advice"},
            {"text": "x"*8193},
            {"source_ids": ["S1", "S1"]},
            {"source_ids": ["https://example.com"]},
            {"extra": "external_provider"},
        ):
            data = sample("Нейтральный текст.")
            data.update(override)
            with self.subTest(override=override), self.assertRaises(EditorialReviewError):
                review(data)

    def test_no_input_text_echoed(self):
        result = review(sample("Частота реакции 75%."))
        self.assertNotIn("75%", json.dumps(result, ensure_ascii=False))
        self.assertFalse(result["original_text_modified"])
        self.assertEqual(result["network_calls"], 0)

    def test_cli_and_limit(self):
        cmd = [sys.executable, "-m", "editorial_review.public_draft", "--stdin"]
        x = subprocess.run(cmd, input=json.dumps(sample("Есть эффект 15%.")).encode("utf-8"),
                           capture_output=True)
        self.assertEqual(x.returncode, 0, x.stderr)
        self.assertIn("QUANTITY_WITHOUT_CITATION", x.stdout.decode("utf-8"))
        for blob in (b"bad-json", b"x"*16385):
            y = subprocess.run(cmd, input=blob, capture_output=True)
            self.assertEqual(y.returncode, 2)
            self.assertEqual(json.loads(y.stdout)["status"], "REJECTED")

if __name__ == "__main__":
    unittest.main()
