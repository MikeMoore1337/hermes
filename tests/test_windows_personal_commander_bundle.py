"""Hash verification for synthetic files and links; no project access."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from device_fabric import windows_personal_commander_bundle as bundle


class PersonalBundleTests(unittest.TestCase):
    def test_file_content_addition_and_removal_change_the_pinned_bundle(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / "bundle"
            root.mkdir()
            (root / "code.js").write_text("synthetic", encoding="ascii")
            try:
                manifest = bundle.manifest(root)
            except bundle.PersonalBundleDenied:
                item = root / "code.js"
                entry = item.lstat()
                with item.open("rb") as stream:
                    handle = os.fstat(stream.fileno())
                fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns")
                mismatch = [key for key in fields if getattr(entry, key) != getattr(handle, key)]
                self.fail("synthetic bundle verification denied; stat mismatch=" + repr(mismatch))
            digest = hashlib.sha256(manifest).hexdigest()
            self.assertEqual(bundle.verify(root, manifest, digest), digest)
            (root / "code.js").write_text("changed", encoding="ascii")
            with self.assertRaises(bundle.PersonalBundleDenied):
                bundle.verify(root, manifest, digest)
            (root / "code.js").write_text("synthetic", encoding="ascii")
            (root / "added.js").write_text("extra", encoding="ascii")
            with self.assertRaises(bundle.PersonalBundleDenied):
                bundle.verify(root, manifest, digest)
            (root / "added.js").unlink()
            (root / "code.js").unlink()
            with self.assertRaises(bundle.PersonalBundleDenied):
                bundle.verify(root, manifest, digest)

    def test_links_cannot_leave_the_bundle(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            root = base / "bundle"
            root.mkdir()
            target = base / "outside"
            target.mkdir()
            (target / "foreign.js").write_text("synthetic", encoding="ascii")
            try:
                os.symlink(target, root / "redirect", target_is_directory=True)
            except OSError:
                if os.name != "nt":
                    self.skipTest("directory symlink creation unavailable")
                created = subprocess.run([os.environ["COMSPEC"], "/d", "/c", "mklink", "/J",
                                          str(root / "redirect"), str(target)], capture_output=True,
                                         timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
                if created.returncode != 0:
                    self.fail("directory link creation unavailable")
            original_lstat = Path.lstat
            def confined_lstat(path):
                if path == target or target in path.parents:
                    self.fail("manifest probed the external link target")
                return original_lstat(path)
            with patch.object(Path, "lstat", confined_lstat), self.assertRaises(bundle.PersonalBundleDenied):
                bundle.manifest(root)


if __name__ == "__main__":
    unittest.main()
