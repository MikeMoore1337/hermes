"""Offline onboarding creates only the requested new sandbox project."""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from scripts import h15_offline_project_import as importer
from scripts.h15_offline_project_install import install


def git(*args):
    p = subprocess.run(["git", *map(str, args)], check=True, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    return p.stdout.decode().strip()


class OfflineProjectInstallTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="h454-import-test-")
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name).resolve()
        parent = root / "projects"
        parent.mkdir()
        stage = root / ".h454-import-fixture"
        stage.mkdir()
        nonce = "a" * 32
        (stage / "marker").write_text(nonce)
        src = root / "source"
        src.mkdir()
        git("init", "-b", "main", src)
        git("-C", src, "config", "user.email", "fixture@example.invalid")
        git("-C", src, "config", "user.name", "Fixture")
        (src / "README").write_text("synthetic project")
        git("-C", src, "add", "README")
        git("-C", src, "commit", "-m", "fixture")
        head = git("-C", src, "rev-parse", "HEAD")
        bundle = stage / "repo.bundle"
        git("-C", src, "bundle", "create", bundle, "refs/heads/main")
        self.package = dict(stage=stage, parent=parent, name="fixture", branch="main", head=head,
                            checksum=hashlib.sha256(bundle.read_bytes()).hexdigest(), size=bundle.stat().st_size,
                            origin="https://github.com/MikeMoore1337/fixture.git", nonce=nonce)

    def test_verified_bundle_installs_clean_project(self):
        result = install(**self.package)
        target = self.package["parent"] / "fixture"
        self.assertEqual(result["status"], "INSTALLED")
        self.assertEqual(git("-C", target, "rev-parse", "HEAD"), self.package["head"])
        self.assertEqual(git("-C", target, "status", "--porcelain"), "")
        self.assertEqual(git("-C", target, "remote", "get-url", "origin"), self.package["origin"])
        self.assertFalse((self.package["stage"] / "repo.bundle").exists())

    def test_existing_project_is_never_overwritten(self):
        target = self.package["parent"] / "fixture"
        target.mkdir()
        (target / "existing").write_text("keep")
        with self.assertRaises(FileExistsError):
            install(**self.package)
        self.assertEqual((target / "existing").read_text(), "keep")

    def test_corrupt_bundle_rejected_before_target_created(self):
        self.package["checksum"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "bundle_checksum_invalid"):
            install(**self.package)
        self.assertFalse((self.package["parent"] / "fixture").exists())


class OfflineProjectImportTest(unittest.TestCase):
    def test_invalid_repository_names_rejected_without_network(self):
        for name in ("../vault", "repo.git", "-bad", "has space"):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "invalid_repository_name"):
                importer.public_repository(name)

    def test_private_repository_rejected(self):
        payload = {"full_name": "MikeMoore1337/fixture", "private": True, "default_branch": "main"}
        with mock.patch.object(importer, "urlopen", return_value=io.BytesIO(json.dumps(payload).encode())):
            with self.assertRaisesRegex(ValueError, "repository_not_public_owner"):
                importer.public_repository("fixture")

    def test_multiple_windows_sandboxes_are_rejected(self):
        with mock.patch.object(importer, "run", return_value="container1\ncontainer2"):
            with self.assertRaisesRegex(ValueError, "sandbox_not_unique"):
                importer.sandbox()


if __name__ == "__main__":
    unittest.main()
