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


class SimpleDeleteCommandTests(unittest.TestCase):
    def test_only_single_file_delete_inside_root_is_translated(self):
        root = r'D:\project'
        for command, suffix in ((r'del /q example.txt', r'D:\project\example.txt'),
                                (r'erase "nested\file name.txt"', r'D:\project\nested\file name.txt'),
                                (r'DEL /Q "D:\project\nested\file.txt"', r'D:\project\nested\file.txt')):
            with self.subTest(command=command):
                translated = yfc._single_file_delete(command, root)
                self.assertTrue(translated.startswith('node -e '))
                self.assertTrue(translated.endswith('"' + suffix + '"'))
        for command in (r'del /q ..\other.txt', r'del /q D:\private\file.txt',
                        r'del /q *.txt', r'del /q file.txt & echo unsafe',
                        r'del /q %TEMP%\file.txt', r'del /q file.txt:stream',
                        r'del /s /q nested', 'del\nfile.txt', r'echo file.txt'):
            with self.subTest(command=command):
                self.assertEqual(yfc._single_file_delete(command, root), command)


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

        def test_simple_del_removes_only_a_file_in_restricted_terminal(self):
            try:
                getattr(ctypes.WinDLL("processmodel", use_last_error=True, winmode=0x800),
                        "CreateProcessSecurityEnvironment")
            except (OSError, AttributeError):
                self.skipTest("Windows runner does not expose the PSEC API")
            node = shutil.which("node")
            if not node:
                self.skipTest("Node is unavailable")
            runner = self.release / "runner"
            runner.mkdir()
            shutil.copyfile(node, runner / "node.exe")
            target = self.project / "delete-me.txt"
            target.write_text("synthetic", encoding="ascii")
            terminal = yfc.YfcDevPsecTerminal(str(self.project), command='del /q "delete-me.txt"',
                writable=(str(self.state),), readonly=(str(self.release), str(self.git)))
            try:
                deadline = time.monotonic() + 20
                while terminal.poll() is None and time.monotonic() < deadline:
                    terminal.read()
                    time.sleep(0.02)
                self.assertEqual(terminal.poll(), 0)
                self.assertFalse(target.exists())
                self.assertTrue((self.project / "code.txt").is_file())
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

        def test_two_explicit_projects_allow_write_and_deny_an_unlisted_directory(self):
            try:
                getattr(ctypes.WinDLL('processmodel', use_last_error=True, winmode=0x800),
                        'CreateProcessSecurityEnvironment')
            except (OSError, AttributeError):
                self.skipTest('Windows runner does not expose the PSEC API')
            node = shutil.which('node')
            if not node:
                self.skipTest('Node is unavailable')
            second, outside = self.base / 'second', self.base / 'outside'
            second.mkdir(); outside.mkdir()
            (outside / 'private.txt').write_text('fixture', encoding='ascii')
            for project in (self.project, second):
                (project / '.artifacts').mkdir()
                (project / '.artifacts' / 'fixture.txt').write_text('fixture', encoding='ascii')
            runner = self.release / 'runner'
            runner.mkdir()
            shutil.copyfile(node, runner / 'node.exe')
            target = second / 'created.txt'
            script = ("const f=require('fs');f.writeFileSync(process.argv[1],'fixture');"
                      "for(let p of process.argv.slice(2)){try{f.readFileSync(p);process.exit(9)}"
                      "catch(e){console.log('DENIED')}}")
            command = (f'node -e "{script}" "{target}" "{outside / "private.txt"}" '
                       f'"{self.project / ".artifacts" / "fixture.txt"}" '
                       f'"{second / ".artifacts" / "fixture.txt"}"')
            roots = (str(self.project), str(second))
            with patch('device_fabric.windows_personal_commander_config.roots_for', return_value=roots):
                terminal = yfc.YfcDevPsecTerminal(str(self.project), command=command, project_roots=roots,
                    writable=(str(self.state), str(second)), readonly=(str(self.release), str(self.git)))
            try:
                deadline = time.monotonic() + 20
                output = []
                while terminal.poll() is None and time.monotonic() < deadline:
                    output.append(terminal.read())
                    time.sleep(0.02)
                output.append(terminal.read())
                self.assertEqual(terminal.poll(), 0)
                self.assertEqual(b''.join(output).count(b'DENIED'), 3)
                self.assertEqual(target.read_text(), 'fixture')
            finally:
                terminal.close()
