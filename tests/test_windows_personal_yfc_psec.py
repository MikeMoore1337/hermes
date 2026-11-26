import os
import ctypes
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from device_fabric import windows_personal_yfc_psec as yfc


if os.name == "nt":
    class YfcScopeTests(unittest.TestCase):
        def setUp(self):
            self.temp = tempfile.TemporaryDirectory(prefix="h454-yfc-scope-")
            self.addCleanup(self.temp.cleanup)
            self.base = Path(self.temp.name).resolve()
            self.project = self.base / "project"
            self.git = self.base / "git"
            app = self.base / yfc.APP_NAME
            self.state, self.release = app / "adapter-state", app / "release"
            for path in (self.project, self.git, self.state, self.release):
                path.mkdir(parents=True)
            (self.project / "code.txt").write_text("synthetic", encoding="ascii")
            self.patches = [patch.object(yfc, "YFC_DEV", self.project), patch.object(yfc, "GIT_ROOT", self.git),
                            patch.dict(os.environ, {"LOCALAPPDATA": str(self.base)})]
            for item in self.patches:
                item.start()
                self.addCleanup(item.stop)
            self.terminal = object.__new__(yfc.YfcDevPsecTerminal)

        def validate(self, root=None, writable=None, readonly=None):
            self.terminal._validate_paths(root or str(self.project), writable or (str(self.state),),
                readonly or (str(self.release), str(self.git)))

        def test_exact_scope_produces_a_metadata_snapshot(self):
            self.validate()
            self.assertEqual(self.terminal.project_snapshot.files, 1)

        def test_terminal_git_environment_is_limited_to_the_approved_project(self):
            with patch.dict(os.environ, {"PATH": "C:\\untrusted", "GIT_CONFIG_GLOBAL": "C:\\secret"}):
                env = self.terminal._environment_variables()
            self.assertNotIn("C:\\untrusted", env["PATH"])
            self.assertIn(str(self.git / "cmd"), env["PATH"].split(os.pathsep))
            self.assertIn(str(self.release / "runner"), env["PATH"].split(os.pathsep))
            self.assertEqual(env["GIT_CONFIG_GLOBAL"], "NUL")
            self.assertEqual(env["GIT_CONFIG_NOSYSTEM"], "1")
            self.assertEqual(env["GIT_CONFIG_COUNT"], "1")
            self.assertEqual(env["GIT_CONFIG_KEY_0"], "safe.directory")
            self.assertEqual(env["GIT_CONFIG_VALUE_0"], str(self.project).replace("\\", "/"))

        def test_plain_git_status_runs_in_the_restricted_terminal(self):
            try:
                getattr(ctypes.WinDLL("processmodel", use_last_error=True, winmode=0x800),
                        "CreateProcessSecurityEnvironment")
            except (OSError, AttributeError):
                self.skipTest("Windows runner does not expose the PSEC API")
            git = shutil.which("git")
            if not git:
                self.skipTest("Git is unavailable")
            git_root = Path(git).resolve().parent.parent
            if not (git_root / "cmd" / "git.exe").is_file():
                self.skipTest("Git for Windows layout is unavailable")
            host_env = os.environ.copy()
            host_env.update({"GIT_CONFIG_GLOBAL": "NUL", "GIT_CONFIG_NOSYSTEM": "1"})
            subprocess.run([git, "init", "-q", "-b", "h454-test", str(self.project)],
                           check=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, env=host_env, creationflags=subprocess.CREATE_NO_WINDOW)
            with patch.object(yfc, "GIT_ROOT", git_root):
                terminal = yfc.YfcDevPsecTerminal(str(self.project),
                    command="git status --short --branch --untracked-files=no",
                    writable=(str(self.state),), readonly=(str(self.release), str(git_root)))
                try:
                    deadline = time.monotonic() + 20
                    output = []
                    while terminal.poll() is None and time.monotonic() < deadline:
                        output.append(terminal.read())
                        time.sleep(0.02)
                    output.append(terminal.read())
                    self.assertEqual(terminal.poll(), 0)
                    self.assertIn(b"h454-test", b"".join(output))
                finally:
                    terminal.close()

        def test_other_project_state_or_readonly_path_is_denied(self):
            for args in ({"root": str(self.base)}, {"writable": (str(self.base),)},
                         {"readonly": (str(self.release), str(self.base))}):
                with self.subTest(args=args), self.assertRaises(ValueError):
                    self.validate(**args)

        def test_existing_hardlink_refuses_launch_scope(self):
            os.link(self.project / "code.txt", self.project / "alias.txt")
            with self.assertRaises(ValueError):
                self.validate()
