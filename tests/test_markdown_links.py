"""H-16 Markdown link checking cannot call out or read outside the clone."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import check_markdown_links as audit


class OfflineMarkdownLinksTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="hermes-md-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        (self.root / "docs").mkdir()
        (self.root / "README.md").write_text("# First Heading\n\n## Duplicate\n## Duplicate\n",
                                               encoding="utf-8")

    def write(self, text):
        target = self.root / "docs" / "guide.md"
        target.write_text(text, encoding="utf-8")
        return target

    def test_valid_local_file_and_duplicate_anchors(self):
        self.write("[top](../README.md#first-heading)\n"
                   "[two](../README.md#duplicate-1)\n"
                   "[folder](../docs/)\n")
        self.assertEqual(audit.check(self.root), [])

    def test_missing_file_and_anchor_are_explicit_failures(self):
        self.write("[missing](../missing.md)\n"
                   "[heading](../README.md#does-not-exist)")
        r = audit.check(self.root)
        self.assertEqual(len(r), 2)
        self.assertIn("missing_local_target", r[0])
        self.assertIn("missing_local_anchor", r[1])

    def test_fenced_and_inline_code_do_not_create_false_positives(self):
        self.write("~~~markdown\n[bad](no-such.md)\n~~~\n"
                   "`[ignored](no-such.md)`\n"
                   "```python\n[bad](wrong.md)\n```\n"
                   "[good](../README.md)")
        self.assertEqual(audit.check(self.root), [])

    def test_external_links_are_never_fetched(self):
        self.write("[status](https://example.invalid/broken#unknown)\n"
                   "[email](mailto:example@example.invalid)")
        with patch("urllib.request.urlopen", side_effect=AssertionError("egress")):
            self.assertEqual(audit.check(self.root), [])

    def test_parent_escape_symlink_and_absolute_paths_denied(self):
        self.write("[escape](../../outside.md)\n"
                   "[absolute](/etc/passwd)\n"
                   "[windows](C:/Windows/system.ini)")
        r = audit.check(self.root)
        self.assertEqual(len(r), 3)
        self.assertIn("link_outside_repository", r[0])
        self.assertIn("unsafe_local_link", r[1])
        self.assertIn("unsafe_local_link", r[2])

    def test_symlink_source_document_denied(self):
        (self.root / "docs" / "guide.md").symlink_to(self.root / "README.md")
        r = audit.check(self.root)
        self.assertEqual(r, ["docs/guide.md:0:unsafe_document"])

    def test_symlink_target_outside_denied(self):
        with tempfile.TemporaryDirectory() as exterior:
            ext = Path(exterior) / "outside.md"
            ext.write_text("# External", encoding="utf-8")
            (self.root / "docs" / "alias.md").symlink_to(ext)
            self.write("[escape](alias.md)")
            self.assertTrue(any("link_outside_repository" in x for x in audit.check(self.root)))

    def test_cyrillic_heading_uses_unicode_slug(self):
        (self.root / "README.md").write_text("# Пример раздела\n", encoding="utf-8")
        self.write("[target](../README.md#пример-раздела)")
        self.assertEqual(audit.check(self.root), [])

    def test_exact_vendored_prose_placeholder_does_not_hide_real_missing_links(self):
        folder = (self.root / "third_party" / "statejnik" / "skills" /
                  "statejnik" / "references" / "checklists")
        folder.mkdir(parents=True)
        doc = folder / "seo-geo.md"
        doc.write_text("\n" * 76 + "[X](url)\n", encoding="utf-8")
        self.assertEqual(audit.check(self.root), [])
        doc.write_text("\n" * 77 + "[X](url)\n", encoding="utf-8")
        self.assertEqual(len(audit.check(self.root)), 1)
        self.assertIn("missing_local_target", audit.check(self.root)[0])
        doc.write_text("\\n" * 76 + "[X](missing.md)\\n", encoding="utf-8")
        self.assertEqual(len(audit.check(self.root)), 1)

    def test_large_document_capped(self):
        self.write("a" * (audit.MAX_MARKDOWN_BYTES + 1))
        self.assertIn("markdown_oversize", audit.check(self.root)[0])

    def test_diagnostics_never_echo_external_url_contents(self):
        self.write("[missing](../none.md?secret=private-token)")
        r = audit.check(self.root)
        self.assertEqual(len(r), 1)
        self.assertNotIn("private-token", str(r))


if __name__ == "__main__":
    unittest.main()
