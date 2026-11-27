from contextlib import contextmanager
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from device_fabric.windows_personal_project_scan import ProjectScanDenied, scan


class ProjectScanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="h454-scan-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        (self.root / "src").mkdir()
        (self.root / "src" / "one.txt").write_text("synthetic", encoding="ascii")

    def test_plain_tree_is_counted_without_reading_contents(self):
        with patch("builtins.open", side_effect=AssertionError("file content opened")):
            snapshot = scan(self.root)
        self.assertEqual((snapshot.directories, snapshot.files), (2, 1))

    def test_entry_stat_link_count_zero_still_queries_the_file_path(self):
        real_scandir = os.scandir
        class Entry:
            def __init__(self, actual):
                self.actual, self.path = actual, actual.path
            def stat(self, *, follow_symlinks):
                item = self.actual.stat(follow_symlinks=follow_symlinks)
                return SimpleNamespace(st_mode=item.st_mode, st_nlink=0,
                    st_file_attributes=getattr(item, "st_file_attributes", 0))
        @contextmanager
        def windows_like_scandir(path):
            with real_scandir(path) as items:
                yield (Entry(item) for item in items)
        with patch("os.scandir", side_effect=windows_like_scandir):
            self.assertEqual(scan(self.root).files, 1)

    def test_hardlink_is_denied_and_error_contains_no_path(self):
        os.link(self.root / "src" / "one.txt", self.root / "src" / "alias.txt")
        with self.assertRaises(ProjectScanDenied) as error:
            scan(self.root)
        self.assertEqual(str(error.exception), "personal_project_scan_denied")

    def test_entry_budget_is_fail_closed(self):
        with self.assertRaises(ProjectScanDenied):
            scan(self.root, limit=1)

    def test_only_the_exact_denied_artifacts_directory_may_be_skipped(self):
        artifacts = self.root / '.artifacts'
        artifacts.mkdir()
        os.link(self.root / 'src' / 'one.txt', artifacts / 'alias.txt')
        # An allowed file with an external alias must still be rejected.
        with self.assertRaises(ProjectScanDenied):
            scan(self.root, excluded=(artifacts,))
        (artifacts / 'alias.txt').unlink()
        external = self.root.parent / (self.root.name + '-outside-fixture.txt')
        external.write_text('fixture', encoding='ascii')
        self.addCleanup(external.unlink)
        os.link(external, artifacts / 'alias.txt')
        with self.assertRaises(ProjectScanDenied):
            scan(self.root)
        self.assertEqual(scan(self.root, excluded=(artifacts,)).files, 1)
        with self.assertRaises(ProjectScanDenied):
            scan(self.root, excluded=(self.root / 'src',))

    if os.name != "nt":
        def test_symlink_is_not_followed(self):
            (self.root / "src" / "link").symlink_to(self.root / "src" / "one.txt")
            with self.assertRaises(ProjectScanDenied):
                scan(self.root)
    else:
        def test_windows_junction_is_not_followed(self):
            junction = self.root / "src" / "junction"
            with tempfile.TemporaryDirectory(prefix="h454-junction-outside-") as outside:
                command = [os.path.join(os.environ["WINDIR"], "System32", "cmd.exe"),
                           "/d", "/c", "mklink", "/J", str(junction), outside]
                created = subprocess.run(command, capture_output=True, timeout=5,
                                         creationflags=subprocess.CREATE_NO_WINDOW)
                try:
                    if created.returncode != 0:
                        self.fail("synthetic junction creation failed")
                    self.assertTrue(junction.lstat().st_file_attributes & 0x400)
                    with self.assertRaises(ProjectScanDenied):
                        scan(self.root)
                finally:
                    # Remove the verified link itself, never its target tree.
                    if os.path.lexists(junction):
                        if not junction.lstat().st_file_attributes & 0x400:
                            raise AssertionError("synthetic junction identity changed")
                        os.rmdir(junction)


if __name__ == "__main__":
    unittest.main()
