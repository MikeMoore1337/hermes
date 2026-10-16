"""H-13 deterministic Russian preflight, synthetic positives and false positives."""
from __future__ import annotations
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from editorial_preflight import ru_check as ru


class RussianPreflightTests(unittest.TestCase):
    def test_neutral_samples_do_not_get_spurious_flags(self):
        cases = [
            "После тренировки записал число повторений и самочувствие.",
            "Я использую метод из статьи, но пока не проверял результат.",
            "Эту форму стоит заполнить после встречи с редактором.",
            "Тире — часть русской пунктуации и не является признаком бота.",
            "До конца недели сделаем ревью и сохраним ссылки.",
            "Сегодня на улице холодно. Возьму куртку.",
        ]
        for text in cases:
            with self.subTest(text=text):
                r = ru.review(text)
                self.assertEqual(r["finding_total"], 0)
                self.assertEqual(r["status"], "NO_FINDINGS_NOT_APPROVAL")
                self.assertFalse(r["publication_allowed"])
                self.assertFalse(r["legal_compliance_verified"])

    def test_explicit_legal_and_style_phrases_are_review_hints(self):
        cases = [
            ("По Федеральному закону нужно ознакомиться с правилами.",
             "LEGAL_NORM_REFERENCE_REVIEW"),
            ("В документе указан 152-ФЗ, требуется проверить норму.",
             "LEGAL_NORM_REFERENCE_REVIEW"),
            ("Согласно КоАП РФ стоит уточнить применимость нормы.",
             "LEGAL_NORM_REFERENCE_REVIEW"),
            ("Штраф до 500 рублей возможен — требует проверки юриста.",
             "LEGAL_FINE_REVIEW"),
            ("Важно отметить, что результат пока неизвестен.",
             "STYLE_FORMULAIC_INTRO"),
            ("На сегодняшний день сведения неполные.",
             "STYLE_FORMULAIC_INTRO"),
            ("Упражнение гарантированно поможет каждому.",
             "STYLE_UNVERIFIED_ABSOLUTE"),
        ]
        for draft, expected in cases:
            with self.subTest(expected=expected):
                r = ru.review(draft)
                self.assertIn(expected, [x["code"] for x in r["findings"]])
                self.assertFalse(r["current_legislation_verified"])
                self.assertFalse(r["scientific_claims_verified"])

    def test_code_fence_inline_code_and_quote_are_not_author_claims(self):
        tick = chr(96)
        draft = (
            "Это пример, а не заявление.\n"
            "~~~python\nprint('На сегодняшний день')\n~~~\n"
            "В строке " + tick + "гарантированно" + tick +
            " пример слова.\n> Важно отметить, что цитата чужая.\n"
        )
        self.assertEqual(ru.review(draft)["finding_total"], 0)

    def test_official_portal_link_is_hint_not_law_verification(self):
        examples = [
            ("https://pravo.gov.ru/notes", True),
            ("https://publication.pravo.gov.ru/Document/View", True),
            ("http://pravo.gov.ru/notes", False),
            ("https://pravo.gov.ru.evil.org/", False),
            ("https://pravo.gov.ru@evil.org/", False),
            ("https://pravo.gov.ru:444/", False),
        ]
        for url, expected in examples:
            with self.subTest(url=url):
                r = ru.review("Официальный источник: " + url, profile="legal")
                self.assertEqual(r["official_portal_link_seen_not_verified"], expected)
                self.assertTrue(r["legal_source_review_required"])
                self.assertFalse(r["legal_compliance_verified"])

    def test_no_excerpt_content_path_or_urls_in_output(self):
        secret = "PRIVATE_EXAMPLE_9A72"
        packet = ru.review("В отчёте 152-ФЗ. " + secret)
        raw = json.dumps(packet, ensure_ascii=False)
        self.assertNotIn(secret, raw)
        self.assertNotIn("В отчёте", raw)
        self.assertFalse(packet["findings"][0]["text_excerpt_included"])

    def test_default_cli_does_not_read_or_connect(self):
        with patch.object(ru, "_read_file") as reading:
            with patch("sys.stdout", new_callable=io.StringIO) as output:
                self.assertEqual(ru.main([]), 0)
            reading.assert_not_called()
        self.assertEqual(json.loads(output.getvalue())["status"], "NOT_EXECUTED")

    def test_explicit_file_reads_once_without_rewrite(self):
        with tempfile.TemporaryDirectory() as folder:
            f = Path(folder) / "text.md"
            f.write_text("На сегодняшний день результат неизвестен.", encoding="utf-8")
            original = f.read_bytes()
            with patch("sys.stdout", new_callable=io.StringIO) as output:
                self.assertEqual(ru.main(["--execute", "--file", str(f)]), 0)
            packet = json.loads(output.getvalue())
            self.assertEqual(packet["status"], "REVIEW_HINTS")
            self.assertEqual(f.read_bytes(), original)
            self.assertNotIn(str(f), output.getvalue())

    def test_missing_file_invalid_extension_or_relative_path_denied(self):
        cases = ["", "./draft.md", "secrets.env", "relative.txt", "/does/not/exist.md"]
        for name in cases:
            with self.subTest(path=name), patch("sys.stdout", new_callable=io.StringIO):
                self.assertEqual(ru.main(["--execute", "--file", name]), 2)

    def test_oversize_invalid_utf8_symlink_hardlink_denied(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "draft.md"
            path.write_bytes(b"a" * (ru.MAX_BYTES + 1))
            with self.assertRaises(ru.PreflightDenied):
                ru._read_file(str(path))
            path.write_bytes(b"\xff")
            with self.assertRaises(ru.PreflightDenied):
                ru._read_file(str(path))
            path.write_text("No claims", encoding="utf-8")
            hardlink = Path(folder) / "alias.md"
            try:
                hardlink.hardlink_to(path)
            except (OSError, NotImplementedError):
                pass
            else:
                with self.assertRaises(ru.PreflightDenied):
                    ru._read_file(str(path))
                hardlink.unlink()
            alias = Path(folder) / "sym.md"
            try:
                alias.symlink_to(path)
            except (OSError, NotImplementedError):
                pass
            else:
                with self.assertRaises(ru.PreflightDenied):
                    ru._read_file(str(alias))

    def test_input_rejects_binary_surrogates_and_unknown_profiles(self):
        for text, profile in (
            ("", "general"), ("\x00", "general"), ("abc\x01", "general"),
            ("abc", "none"), ("\ud800", "general"),
            ("X" * (ru.MAX_BYTES + 1), "general"),
        ):
            with self.subTest(profile=profile):
                with self.assertRaises(ru.PreflightDenied):
                    ru.review(text, profile=profile)

    def test_count_truncation_never_approves_even_clean_profile(self):
        packet = ru.review("На сегодняшний день. " * 40, profile="legal")
        self.assertEqual(packet["finding_total"], 40)
        self.assertEqual(len(packet["findings"]), ru.MAX_FINDINGS)
        self.assertTrue(packet["truncated"])
        self.assertFalse(packet["publication_allowed"])
        self.assertFalse(packet["legal_compliance_verified"])

    def test_no_network_import_and_no_write_or_adaptive_llm(self):
        import inspect
        source = inspect.getsource(ru)
        for word in ("urllib.request", "requests.", "http.client", "openai.",
                     "subprocess.", "os.system", "write_text(", "write_bytes("):
            self.assertNotIn(word, source)
        self.assertFalse(ru.review("Текст без опасных шаблонов.")["network_used"])


if __name__ == "__main__":
    unittest.main()
