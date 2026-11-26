import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import h454_windows_personal_yfc_action as action


class ActionValidationTests(unittest.TestCase):
    def test_invalid_path_and_pins_are_sanitized(self):
        with self.assertRaises(action.YfcActionDenied) as error:
            action.build_action(Path("relative/pythonw.exe"), pythonw_sha256="x",
                                bootstrap_sha256="x", manifest_sha256="x", verifier_sha256="x")
        self.assertEqual(str(error.exception), "yfc_action_denied")


if os.name == "nt":
    class WindowlessActionTests(unittest.TestCase):
        def setUp(self):
            self.temp = tempfile.TemporaryDirectory(prefix="h454-action-")
            self.addCleanup(self.temp.cleanup)
            self.env = patch.dict(os.environ, {"LOCALAPPDATA": str(Path(self.temp.name).resolve())})
            self.env.start()
            self.addCleanup(self.env.stop)
            directory = Path(self.temp.name).resolve() / action.APP_NAME / "bootstrap"
            directory.mkdir(parents=True)
            self.bootstrap = directory / action.BOOTSTRAP_NAME
            self.bootstrap.write_text("import sys\nraise SystemExit(17 if sys.argv[1:]==["
                                      + repr("a" * 64) + "," + repr("b" * 64) + "] else 3)\n",
                                      encoding="ascii")
            self.pythonw = Path(sys.executable).resolve().with_name("pythonw.exe")
            self.python_sha = hashlib.sha256(self.pythonw.read_bytes()).hexdigest()
            self.bootstrap_sha = hashlib.sha256(self.bootstrap.read_bytes()).hexdigest()

        def build(self):
            return action.build_action(self.pythonw, pythonw_sha256=self.python_sha,
                bootstrap_sha256=self.bootstrap_sha, manifest_sha256="a" * 64, verifier_sha256="b" * 64)

        def test_pythonw_executes_pinned_bootstrap_without_a_window(self):
            built = self.build()
            self.assertEqual(built.arguments[:3], ("-I", "-B", "-c"))
            self.assertEqual(built.windows_arguments, subprocess.list2cmdline(built.arguments))
            command_line = subprocess.list2cmdline([built.executable]) + " " + built.windows_arguments
            result = subprocess.run(command_line, timeout=30,
                                    creationflags=subprocess.CREATE_NO_WINDOW)
            self.assertEqual(result.returncode, 17)

        def test_changed_bootstrap_is_refused_at_launch_and_setup(self):
            built = self.build()
            self.bootstrap.write_text("raise SystemExit(99)\n", encoding="ascii")
            result = subprocess.run([built.executable, *built.arguments], timeout=30,
                                    creationflags=subprocess.CREATE_NO_WINDOW)
            self.assertEqual(result.returncode, 2)
            with self.assertRaises(action.YfcActionDenied):
                self.build()
