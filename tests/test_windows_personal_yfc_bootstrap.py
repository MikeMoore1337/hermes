import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from device_fabric import windows_personal_commander_bundle as bundle
from scripts import h454_windows_personal_yfc_bootstrap as bootstrap


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="h454-bootstrap-")
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name).resolve()
        self.base = root / bootstrap.APP_NAME
        self.release = self.base / "release"
        private = self.base / "worker-private"
        verifier = self.release / "code" / "device_fabric" / "windows_personal_commander_bundle.py"
        verifier.parent.mkdir(parents=True)
        shutil.copyfile(bundle.__file__, verifier)
        entry = self.release / "code" / "scripts" / "h454_windows_personal_yfc_entry.py"
        entry.parent.mkdir(parents=True)
        entry.write_text("raise SystemExit(17)\n", encoding="ascii")
        private.mkdir(parents=True)
        manifest = bundle.manifest(self.release)
        (private / "release-manifest.json").write_bytes(manifest)
        self.digests = [hashlib.sha256(manifest).hexdigest(), hashlib.sha256(verifier.read_bytes()).hexdigest()]
        self.env = patch.dict(os.environ, {"LOCALAPPDATA": str(root)})
        self.env.start()
        self.addCleanup(self.env.stop)

    def call(self, digests):
        with patch.object(sys, "path", list(sys.path)), patch.object(sys, "argv", list(sys.argv)):
            return bootstrap.main(digests)

    def test_pinned_release_runs_only_after_verification(self):
        self.assertEqual(self.call(self.digests), 17)

    def test_isolated_interpreter_runs_pinned_release(self):
        kwargs = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}
        result = subprocess.run([sys.executable, "-I", "-B", bootstrap.__file__, *self.digests],
                                capture_output=True, timeout=30, **kwargs)
        self.assertEqual(result.returncode, 17, result.stderr.decode(errors="replace"))

    def test_changed_entry_cannot_run(self):
        entry = self.release / "code" / "scripts" / "h454_windows_personal_yfc_entry.py"
        entry.write_text("raise SystemExit(99)\n", encoding="ascii")
        self.assertEqual(self.call(self.digests), 2)

    def test_wrong_manifest_or_verifier_pin_is_denied(self):
        for index in (0, 1):
            digests = self.digests.copy()
            digests[index] = "0" * 64
            self.assertEqual(self.call(digests), 2)

    def test_hardlinked_manifest_is_denied(self):
        manifest = self.base / "worker-private" / "release-manifest.json"
        os.link(manifest, manifest.with_name("alias"))
        self.assertEqual(self.call(self.digests), 2)
