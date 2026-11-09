"""H454 Stage 2A native search: kernel openat2 against temp originals only.

No owner VPS/Windows host, no BRC commands, no credentials, no network calls.
"""
from __future__ import annotations

import os
from pathlib import Path
import platform
import sys
import tempfile
import unittest
from unittest.mock import patch

from device_fabric.linux_native_files import LinuxNativeFiles, NativeLinuxDenied, MAX_READ_BYTES
from device_fabric.linux_native_search import (
    LinuxNativeSearch, MAX_ENTRIES, MAX_DEPTH, MAX_MATCHES,
    MAX_CONTENT_BYTES,
)


@unittest.skipUnless(sys.platform == "linux" and
                     platform.machine().lower() in ("x86_64", "aarch64"),
                     "real Linux openat2 required")
class LinuxNativeSearchContracts(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="h454-search-ci-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name) / "approved-original"
        self.root.mkdir()
        (self.root / "src").mkdir()
        (self.root / "docs").mkdir()
        (self.root / "src" / "app.py").write_text(
            "print('Alpha')\n# TODO fix\n# todo second\n",
            encoding="utf-8")
        (self.root / "docs" / "Notes.md").write_text(
            "ПрИвЕт, мир\n# TODO documented\n", encoding="utf-8")
        (self.root / ".env").write_text("DONT_DISCLOSE=SECRET", encoding="utf-8")
        (self.root / ".git").mkdir()
        (self.root / ".git" / "config").write_text("SECRET", encoding="utf-8")
        (self.root / ".hg").mkdir()
        (self.root / ".hg" / "hgrc").write_text("SECRET", encoding="utf-8")
        (self.root / "node_modules").mkdir()
        (self.root / "node_modules" / "leaky.js").write_text("SECRET", encoding="utf-8")
        self.outside = Path(temp.name) / "outside"
        self.outside.mkdir()
        (self.outside / "private.md").write_text("SECRET CONTENT", encoding="utf-8")
        (self.root / "leak.md").symlink_to(self.outside / "private.md")
        os.link(self.outside / "private.md", self.root / "hardlink.md")
        self.files = LinuxNativeFiles(root=self.root, project="hermes")
        self.addCleanup(self.files.close)
        self.search = LinuxNativeSearch(self.files)

    def test_name_search_casefold_and_bounded_relative_paths(self):
        out = self.search.search("APP", mode="names")
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["project"], "hermes")
        self.assertEqual(out["matches"], [{"path":"src/app.py", "kind":"file"}])
        self.assertEqual(out["relative_root"], "")
        self.assertFalse(out["truncated"])
        self.assertGreater(out["entries_scanned"], 1)
        self.assertEqual(out["bytes_scanned"], 0)

    def test_directory_name_search_without_entering_private_git(self):
        out = self.search.search("docs")
        self.assertEqual(out["matches"], [{"path":"docs", "kind":"directory"}])
        self.assertNotIn(".git", str(out))
        self.assertNotIn(".hg", str(out))
        self.assertNotIn("node_modules", str(out))
        self.assertNotIn("SECRET", str(out))

    def test_content_search_returns_lines_only_not_source_snippets(self):
        out = self.search.search("todo", mode="content")
        self.assertEqual(out["matches"], [
            {"path": "docs/Notes.md", "line": 2},
            {"path": "src/app.py", "line": 2},
            {"path": "src/app.py", "line": 3},
        ])
        self.assertGreater(out["bytes_scanned"], 0)
        self.assertNotIn("TODO fix", str(out))
        self.assertNotIn("documented", str(out))
        self.assertNotIn("DONT_DISCLOSE", str(out))
        self.assertNotIn("SECRET", str(out))

    def test_unicode_casefold_content_search(self):
        out = self.search.search("привет", mode="content")
        self.assertEqual(out["matches"], [{"path":"docs/Notes.md", "line": 1}])

    def test_subdirectory_scope_never_widens(self):
        self.assertEqual(self.search.search("todo",mode="content",relative_root="docs")["matches"],
                         [{"path":"docs/Notes.md", "line":2}])
        with self.assertRaises(NativeLinuxDenied):
            self.search.search("SECRET",mode="content",relative_root="../outside")
        with self.assertRaises(NativeLinuxDenied):
            self.search.search("SECRET",mode="content",relative_root=".git")
        with self.assertRaises(NativeLinuxDenied):
            self.search.search("secret", mode="names", relative_root="leak.md")

    def test_symlinks_and_hardlinks_never_return_or_followed(self):
        out = self.search.search("leak", mode="names")
        self.assertEqual(out["matches"], [])
        out = self.search.search("hardlink", mode="names")
        self.assertEqual(out["matches"], [])
        out = self.search.search("SECRET CONTENT", mode="content")
        self.assertEqual(out["matches"], [])
        self.assertEqual((self.outside / "private.md").read_text(), "SECRET CONTENT")
        self.assertEqual(self.search.search("leaky", mode="names")["matches"], [])
        self.assertEqual(self.search.search("SECRET", mode="content")["matches"], [])

    def test_binary_source_extension_never_searches_raw_binary(self):
        (self.root / "binary.txt").write_bytes(b"TODO\x00private")
        out = self.search.search("TODO", mode="content")
        self.assertNotIn({"path":"binary.txt", "line":1}, out["matches"])

    def test_max_matches_enforced_with_truncated_marker(self):
        for i in range(MAX_MATCHES + 7):
            (self.root / "docs" / ("hit%03d.md" % i)).write_text("x", encoding="utf-8")
        out = self.search.search("hit", mode="names", relative_root="docs")
        self.assertEqual(len(out["matches"]), MAX_MATCHES)
        self.assertTrue(out["truncated"])
        self.assertTrue(all("hit" in item["path"] for item in out["matches"]))

    def test_scan_budget_enforced_before_unbounded_enumeration(self):
        for i in range(MAX_ENTRIES + 4):
            (self.root / ("item%04d.md" % i)).write_text("x", encoding="utf-8")
        out = self.search.search("does-not-match")
        self.assertEqual(out["entries_scanned"], MAX_ENTRIES)
        self.assertTrue(out["truncated"])
        self.assertEqual(out["matches"], [])

    def test_depth_limit_excludes_deeper_files(self):
        current = self.root / "src"
        for i in range(MAX_DEPTH + 2):
            current = current / ("nested%d" % i)
            current.mkdir()
        (current / "find-me.md").write_text("target-line", encoding="utf-8")
        out = self.search.search("target-line",mode="content")
        self.assertEqual(out["matches"], [])
        self.assertTrue(out["truncated"])

    def test_oversize_source_file_skipped_with_budget(self):
        (self.root / "huge.txt").write_bytes(b"T" * (MAX_READ_BYTES + 1))
        out = self.search.search("T",mode="content")
        self.assertNotIn("huge.txt", str(out["matches"]))
        self.assertTrue(out["truncated"])

    def test_binary_source_reads_are_charged_to_aggregate_budget(self):
        for index in range(10):
            (self.root / ("binary%03d.txt" % index)).write_bytes(
                b"\x00" + b"B" * (MAX_READ_BYTES - 1))
        out = self.search.search("B", mode="content")
        self.assertTrue(out["truncated"])
        self.assertEqual(out["bytes_scanned"], MAX_CONTENT_BYTES)
        self.assertEqual(out["matches"], [])

    def test_invalid_utf8_source_reads_are_also_charged(self):
        for index in range(10):
            (self.root / ("invalid%03d.txt" % index)).write_bytes(
                b"\xff" * MAX_READ_BYTES)
        out = self.search.search("needle", mode="content")
        self.assertTrue(out["truncated"])
        self.assertEqual(out["bytes_scanned"], MAX_CONTENT_BYTES)
        self.assertEqual(out["matches"], [])

    def test_growth_between_stat_and_opened_file_read_cannot_exceed_budget(self):
        for index in range(7):
            (self.root / ("a%03d.txt" % index)).write_bytes(
                b"x" * MAX_READ_BYTES)
        (self.root / "b-partial.txt").write_bytes(
            b"x" * (MAX_READ_BYTES // 2))
        last = self.root / "z-last.txt"
        last.write_bytes(b"")
        original_read = self.files.read_file
        grow_calls = []

        def grow(relative, *, max_bytes=None):
            if relative == "z-last.txt":
                grow_calls.append(max_bytes)
                last.write_bytes(b"Z" * MAX_READ_BYTES)
            return original_read(relative, max_bytes=max_bytes)

        with patch.object(self.files, "read_file", side_effect=grow):
            out = self.search.search("needle", mode="content")
        self.assertEqual(grow_calls, [MAX_READ_BYTES // 2])
        self.assertTrue(out["truncated"])
        self.assertLessEqual(out["bytes_scanned"], MAX_CONTENT_BYTES)
        self.assertEqual(out["matches"], [])

    def test_reader_validates_caller_budget_on_opened_fd(self):
        with self.assertRaises(NativeLinuxDenied):
            self.files.read_file("src/app.py", max_bytes=1)
        for invalid in (True, -1, MAX_READ_BYTES + 1, "10"):
            with self.subTest(max_bytes=invalid), self.assertRaises(NativeLinuxDenied):
                self.files.read_file("src/app.py", max_bytes=invalid)
        self.assertEqual(self.files.read_file("src/app.py", max_bytes=100)["status"],
                         "ok")

    def test_invalid_patterns_modes_and_root_types_fail_closed(self):
        cases = [
            ("", "names", ""), ("   ", "content", ""),
            ("x\n", "names", ""), ("x\x00", "names", ""),
            ("x" * 100, "names", ""), ("abc", "regex", ""),
            (None, "content", ""), ("abc", "names", None),
            ("abc", "names", "src/../docs"), ("abc", "names", "/etc"),
            ("abc", "names", "src\\other"),
        ]
        for query,mode,root in cases:
            with self.subTest(query=query,mode=mode,root=root):
                with self.assertRaisesRegex(NativeLinuxDenied, "^native_linux_denied$"):
                    self.search.search(query,mode=mode,relative_root=root)

    def test_source_permission_error_is_sanitized(self):
        with patch("device_fabric.linux_native_search.os.scandir",
                   side_effect=OSError("sensitive private path")):
            with self.assertRaisesRegex(NativeLinuxDenied, "^native_linux_denied$"):
                self.search.search("a",mode="names")

    def test_closed_original_root_refuses_search(self):
        self.files.close()
        with self.assertRaises(NativeLinuxDenied):
            self.search.search("a",mode="names")

    def test_no_shell_or_process_execution(self):
        with patch("subprocess.run", side_effect=AssertionError("not allowed")):
            out = self.search.search("app.py", mode="names")
        self.assertEqual(out["matches"], [{"path":"src/app.py", "kind":"file"}])


if __name__ == "__main__":
    unittest.main()
