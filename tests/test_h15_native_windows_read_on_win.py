"""Real Win32 handle tests with disposable CI-runner files only (#454).

Never runs on the owner's Windows; all fixtures are under TemporaryDirectory.
"""
from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import h15_native_windows_read as broker


@unittest.skipUnless(os.name == "nt", "real Win32 API required")
class NativeWindowsReadOnRunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="h454-ci-windows-")
        # Hosted runner TEMP can be reached through a junction/drive alias;
        # use the physically resolved synthetic root for strict handle checks.
        base = Path(self.tmp.name).resolve(strict=True)
        self.root = base / "hermes-code"
        self.root.mkdir()
        self.outside = base / "private-canary"
        self.outside.mkdir()
        self.code = self.root / "src"
        self.code.mkdir()
        self.file = self.code / "safe.py"
        self.data = b"print('synthetic-canary')\r\n"
        self.file.write_bytes(self.data)
        (self.outside / "private.py").write_bytes(b"CI_PRIVATE_CANNOT_READ")
        self.patcher = patch.dict(broker.READ_ROOTS, {"hermes": str(self.root)}, clear=True)
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        self.tmp.cleanup()

    def test_actual_win32_stat_and_same_handle_read(self):
        result = broker.handle_native_request("hermes", r"src\safe.py", "read")
        self.assertEqual(result["size_bytes"], len(self.data))
        self.assertEqual(result["sha256"], hashlib.sha256(self.data).hexdigest())
        self.assertEqual(base64.b64decode(result["data"]), self.data)
        self.assertEqual(result["status"], "ok")
        meta = broker.handle_native_request("hermes", r"src\safe.py", "stat")
        self.assertEqual(meta["size_bytes"], len(self.data))
        self.assertNotIn("data", meta)
        directory = broker.handle_native_request("hermes", "", "stat")
        self.assertEqual(directory["kind"], "directory")
        self.assertNotIn("data", directory)

    def test_actual_outside_path_and_oversized_file_denied(self):
        with self.assertRaises(broker.NativeReadRefused):
            broker.handle_native_request("hermes", r"..\private-canary\private.py", "read")
        too_large = self.root / "big.py"
        too_large.write_bytes(b"x" * (broker.MAX_FILE_BYTES + 1))
        with self.assertRaisesRegex(broker.NativeReadRefused, "too_large"):
            broker.handle_native_request("hermes", "big.py", "read")

    def test_actual_hardlink_does_not_leak_other_file_aliases(self):
        link = self.root / "alias.py"
        os.link(self.file, link)
        with self.assertRaisesRegex(broker.NativeReadRefused, "hardlink_denied"):
            broker.handle_native_request("hermes", "alias.py", "read")

    def test_actual_reparse_target_and_root_denied(self):
        # GitHub-hosted Windows runner is an isolated, ephemeral machine with
        # symlink support; never make links on the owner's original D: drive.
        link = self.root / "out"
        os.symlink(self.outside, link, target_is_directory=True)
        with self.assertRaises(broker.NativeReadRefused):
            broker.handle_native_request("hermes", r"out\private.py", "read")
        file_link = self.root / "linked.py"
        os.symlink(self.file, file_link)
        with self.assertRaises(broker.NativeReadRefused):
            broker.handle_native_request("hermes", "linked.py", "read")
        redirected_root = Path(self.tmp.name) / "redirected-root"
        os.symlink(self.root, redirected_root, target_is_directory=True)
        with patch.dict(broker.READ_ROOTS, {"hermes": str(redirected_root)}, clear=True):
            with self.assertRaises(broker.NativeReadRefused):
                broker.handle_native_request("hermes", "src\\safe.py", "read")

    def test_broker_never_creates_or_changes_source_fixture(self):
        before = self.file.read_bytes()
        with self.assertRaises(broker.NativeReadRefused):
            broker.build_request("hermes", "src\\safe.py", "execute")
        with self.assertRaises(broker.NativeReadRefused):
            broker.build_request("hermes", "src\\safe.py", "write")
        self.assertEqual(self.file.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
