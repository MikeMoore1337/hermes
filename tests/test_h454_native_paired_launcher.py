"""Archive admission tests use synthetic bytes and never contact a host."""
import hashlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile
from contextlib import redirect_stdout

from scripts import h454_native_paired_launcher as launcher


@unittest.skipUnless(os.name == "posix", "Linux archive permissions")
class PairedLauncherTests(unittest.TestCase):
    def test_accepts_only_exact_private_single_link_archive(self):
        release = "a" * 40
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as package:
            package.comment = release.encode("ascii")
            package.writestr("scripts/h454_native_paired_apply.py", b"synthetic")
            package.writestr("device_fabric/__init__.py", b"synthetic")
        raw = buffer.getvalue()
        digest = hashlib.sha256(raw).hexdigest()
        with tempfile.TemporaryDirectory() as temp, patch.object(launcher, "ARCHIVE_ROOT", Path(temp)):
            path = Path(temp) / ("h454-paired-operator-" + release + ".zip")
            path.write_bytes(raw)
            path.chmod(0o400)
            self.assertEqual(launcher.verified_archive(release, digest, owner=os.geteuid()), path)
            for bad_release, bad_digest in (("../bad", digest), (release, "f" * 64)):
                with self.assertRaisesRegex(ValueError, "^native_paired_archive_denied$"):
                    launcher.verified_archive(bad_release, bad_digest, owner=os.geteuid())
            wrong_commit = "b" * 40
            wrong_path = Path(temp) / ("h454-paired-operator-" + wrong_commit + ".zip")
            wrong_path.write_bytes(raw)
            wrong_path.chmod(0o400)
            with self.assertRaises(ValueError):
                launcher.verified_archive(wrong_commit, digest, owner=os.geteuid())
            path.chmod(0o600)
            with self.assertRaises(ValueError):
                launcher.verified_archive(release, digest, owner=os.geteuid())
            path.chmod(0o400)
            link = Path(temp) / "second-link"
            os.link(path, link)
            with self.assertRaises(ValueError):
                launcher.verified_archive(release, digest, owner=os.geteuid())
            link.unlink()
            path.unlink()
            path.symlink_to(Path(temp) / "other")
            with self.assertRaises(ValueError):
                launcher.verified_archive(release, digest, owner=os.geteuid())

    def test_bad_runtime_refuses_before_archive_or_import(self):
        with patch.object(launcher.os, "geteuid", return_value=1234), \
             patch.object(launcher, "verified_archive") as verify, \
             patch.object(launcher.importlib, "import_module") as imported, \
             redirect_stdout(io.StringIO()):
            self.assertEqual(launcher.main(["install-off", "a" * 40, "b" * 64]), 2)
        verify.assert_not_called()
        imported.assert_not_called()

    def test_isolated_launcher_dispatches_from_verified_synthetic_archive(self):
        code = """\
from contextlib import contextmanager
class host:
    @staticmethod
    def inspect(): pass
@contextmanager
def host_lock(): yield
def operate(mode): return 'SYNTHETIC_' + mode.upper()
"""
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "source.zip"
            with zipfile.ZipFile(archive, "w") as package:
                package.writestr("scripts/__init__.py", "")
                package.writestr("scripts/h454_native_paired_apply.py", code)
            harness = """\
import importlib.util, sys
spec = importlib.util.spec_from_file_location('launcher_under_test', sys.argv[1])
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)
launcher.os.geteuid = lambda: 0
launcher.socket.gethostname = lambda: 'vps1777112993'
launcher.verified_archive = lambda release, digest, owner: sys.argv[2]
raise SystemExit(launcher.main([sys.argv[3], 'a' * 40, 'b' * 64]))
"""
            for mode, expected in (("plan", "PLAN_PASS_NO_MUTATION"),
                                   ("install-off", "SYNTHETIC_INSTALL-OFF")):
                with self.subTest(mode=mode):
                    result = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", harness,
                                             str(Path(launcher.__file__)), str(archive), mode],
                                            capture_output=True, text=True, timeout=10, check=False)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.strip(), "H454_PAIRED_UPGRADE=" + expected)


if __name__ == "__main__":
    unittest.main()
