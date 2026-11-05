"""Portable no-follow file descriptors: regular files, links and directories."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from qa_advisor.no_follow import open_nofollow


class PortableNoFollowTests(unittest.TestCase):
    def test_regular_file_opens_without_edit(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "safe.json"
            target.write_bytes(b'{"safe":true}')
            before = target.read_bytes()
            fd = open_nofollow(target)
            try:
                self.assertEqual(os.read(fd, 100), before)
            finally:
                os.close(fd)
            self.assertEqual(target.read_bytes(), before)

    def test_final_component_symlink_is_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "real.json"
            target.write_bytes(b"DO_NOT_READ_TARGET")
            shortcut = root / "alias.json"
            try:
                shortcut.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("OS denies developer-mode symlink creation")
            with self.assertRaises(OSError):
                fd = open_nofollow(shortcut)
                os.close(fd)
            self.assertEqual(target.read_bytes(), b"DO_NOT_READ_TARGET")

    def test_missing_file_is_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(OSError):
                open_nofollow(Path(temp) / "missing.txt")

    def test_open_never_creates_a_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            empty = root / "absent.json"
            with self.assertRaises(OSError):
                open_nofollow(empty)
            self.assertFalse(empty.exists())


if __name__ == "__main__":
    unittest.main()
