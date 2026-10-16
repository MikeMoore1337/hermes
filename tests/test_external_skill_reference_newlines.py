"""Cross-platform pinned external reference checks, fail closed on modified text."""
from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import check_external_skill_references as ext


class ReferenceNewlineTests(unittest.TestCase):
    def test_lf_and_explicit_crlf_match_same_git_blob(self):
        lf = b"First line\nAnother line\n"
        expected = ext.blob_sha(lf)
        self.assertTrue(ext.matches_pinned_blob(lf, expected, "exact"))
        self.assertFalse(ext.matches_pinned_blob(lf.replace(b"\n", b"\r\n"),
                                                expected, "exact"))
        self.assertTrue(ext.matches_pinned_blob(lf.replace(b"\n", b"\r\n"),
                                               expected, "consistent_crlf_text"))

    def test_tampering_and_mixed_endings_are_denied(self):
        lf = b"First line\nAnother line\n"
        expected = ext.blob_sha(lf)
        cases = (
            lf.replace(b"First", b"Altered"),
            b"First line\r\nAnother line\n",
            b"First line\nAnother line\r\n",
            b"First line\rAnother line\n",
            b"First line\r\nAnother line\r\nX",
            b"First line\r\n\x00Another line\r\n",
            b"",
        )
        for data in cases:
            with self.subTest(case=repr(data)[:40]):
                self.assertFalse(ext.matches_pinned_blob(
                    data, expected, "consistent_crlf_text"))

    def test_unknown_policy_and_non_bytes_rejected(self):
        expected = ext.blob_sha(b"x\n")
        self.assertFalse(ext.matches_pinned_blob(b"x\n", expected,
                                                 "guess_line_endings"))
        self.assertFalse(ext.matches_pinned_blob("x\n", expected,
                                                 "consistent_crlf_text"))

    def test_real_checked_out_reference_matches_pinned_manifest(self):
        manifest = json.loads(ext.LOCK.read_text(encoding="utf-8"))
        self.assertEqual(len(manifest["files"]), 1)
        entry = manifest["files"][0]
        data = (ext.ROOT / entry["local"]).read_bytes()
        self.assertTrue(ext.matches_pinned_blob(
            data, entry["git_blob_sha"], entry["newline_policy"]))

    def test_no_automatic_rewrite_or_relaxation_of_other_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            r = Path(directory)
            target = r / "sample.md"
            target.write_bytes(b"original\n")
            pin = ext.blob_sha(b"original\n")
            self.assertFalse(ext.matches_pinned_blob(
                b"modified\r\n", pin, "consistent_crlf_text"))
            self.assertEqual(target.read_bytes(), b"original\n")


if __name__ == "__main__":
    unittest.main()
