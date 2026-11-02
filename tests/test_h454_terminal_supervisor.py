"""Real Linux session processes; fixtures use only temporary files."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from scripts import h454_terminal_supervisor as supervisor


SUPERVISOR = Path(__file__).resolve().parents[1] / "scripts/h454_terminal_supervisor.py"


@unittest.skipUnless(sys.platform == "linux", "Linux subreaper required")
class TerminalSupervisorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="h454-session-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.processes = []
        self.pidfds = []
        self.addCleanup(self.cleanup_processes)

    def cleanup_processes(self):
        for process in self.processes:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
        for fd in self.pidfds:
            try:
                signal.pidfd_send_signal(fd, signal.SIGKILL)
            except ProcessLookupError:
                pass
            finally:
                os.close(fd)

    def launch(self, command):
        process = subprocess.Popen(
            [sys.executable, "-I", "-B", str(SUPERVISOR), str(os.getpid()), *command],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        self.processes.append(process)
        return process

    def wait_for_file(self, path):
        deadline = time.monotonic() + 5
        while not path.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertTrue(path.exists(), "fixture process did not start")
        return int(path.read_text(encoding="ascii"))

    @staticmethod
    def running(pid):
        try:
            return Path(f"/proc/{pid}/stat").read_text().split(") ", 1)[1][0] != "Z"
        except FileNotFoundError:
            return False

    def test_detached_descendant_terminates_and_other_session_continues(self):
        marker = self.root / "detached.pid"
        escaped = ("import os,time;from pathlib import Path;os.setsid();"
                   f"Path({str(marker)!r}).write_text(str(os.getpid()));time.sleep(30)")
        worker = ("import subprocess,sys,time;"
                  f"subprocess.Popen([sys.executable,'-c',{escaped!r}]);time.sleep(0.2)")
        first = self.launch([sys.executable, "-c", worker])
        second = self.launch([sys.executable, "-c", "import time;time.sleep(30)"])
        descendant = self.wait_for_file(marker)
        self.pidfds.append(os.pidfd_open(descendant))
        self.assertTrue(self.running(descendant))
        time.sleep(0.4)
        self.assertIsNone(first.poll(), "supervisor must retain an orphaned descendant")
        first.terminate()
        self.assertEqual(first.wait(timeout=5), 128 + signal.SIGTERM)
        self.assertFalse(self.running(descendant))
        self.assertIsNone(second.poll())

    def test_normal_exit_preserves_output_and_status(self):
        result = subprocess.run(
            [sys.executable, "-I", "-B", str(SUPERVISOR), str(os.getpid()), sys.executable,
             "-c", "import sys;print('fixture output');sys.exit(7)"],
            capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(result.returncode, 7)
        self.assertEqual(result.stdout, "fixture output\n")

    @unittest.skipUnless(os.getpid() == 1, "requires test process as container PID 1")
    def test_container_pid1_can_own_a_session(self):
        result = subprocess.run(
            [sys.executable, "-I", "-B", str(SUPERVISOR), "1", sys.executable,
             "-c", "raise SystemExit(7)"], capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(result.returncode, 7, result.stderr)

    def test_pid1_parent_is_accepted_without_running_as_pid1(self):
        libc = Mock()
        libc.prctl.return_value = 0
        child = Mock(pid=42)
        with patch.object(supervisor.sys, "argv", ["supervisor", "1", "fixture"]), \
             patch.object(supervisor.signal, "signal"), \
             patch.object(supervisor.ctypes, "CDLL", return_value=libc), \
             patch.object(supervisor.Path, "read_text", return_value=""), \
             patch.object(supervisor.os, "getppid", return_value=1), \
             patch.object(supervisor.subprocess, "Popen", return_value=child), \
             patch.object(supervisor.os, "waitpid", side_effect=[(42, 7 << 8), ChildProcessError]):
            self.assertEqual(supervisor.main(), 7)

    def test_inherited_ignored_sigchld_does_not_hide_child_exit(self):
        result = subprocess.run(
            [sys.executable, "-I", "-B", str(SUPERVISOR), str(os.getpid()),
             sys.executable, "-c", "raise SystemExit(7)"],
            preexec_fn=lambda: signal.signal(signal.SIGCHLD, signal.SIG_IGN),
            capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(result.returncode, 7)

    def test_wrong_parent_cannot_start_command(self):
        marker = self.root / "should-not-exist"
        result = subprocess.run(
            [sys.executable, "-I", "-B", str(SUPERVISOR), str(os.getpid() + 100000),
             sys.executable, "-c", f"from pathlib import Path;Path({str(marker)!r}).touch()"],
            capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(result.returncode, 125)
        self.assertIn("HERMES_TERMINAL_SUPERVISOR_UNAVAILABLE", result.stderr)
        self.assertFalse(marker.exists())

    def test_zero_parent_cannot_start_command(self):
        result = subprocess.run(
            [sys.executable, "-I", "-B", str(SUPERVISOR), "0", sys.executable,
             "-c", "raise SystemExit(7)"], capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(result.returncode, 125)
        self.assertIn("HERMES_TERMINAL_SUPERVISOR_UNAVAILABLE", result.stderr)

    def test_parent_death_terminates_supervisor_and_descendant(self):
        supervisor_marker = self.root / "supervisor.pid"
        child_marker = self.root / "child.pid"
        child = ("import os,time;from pathlib import Path;"
                 f"Path({str(child_marker)!r}).write_text(str(os.getpid()));time.sleep(30)")
        parent = ("import os,subprocess,sys,time;from pathlib import Path;"
                  f"p=subprocess.Popen([sys.executable,'-I','-B',{str(SUPERVISOR)!r},"
                  f"str(os.getpid()),sys.executable,'-c',{child!r}],"
                  "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);"
                  f"Path({str(supervisor_marker)!r}).write_text(str(p.pid));time.sleep(30)")
        owner = subprocess.Popen([sys.executable, "-c", parent])
        self.processes.append(owner)
        supervisor = self.wait_for_file(supervisor_marker)
        descendant = self.wait_for_file(child_marker)
        self.pidfds.extend((os.pidfd_open(supervisor), os.pidfd_open(descendant)))
        owner.kill()
        owner.wait(timeout=3)
        deadline = time.monotonic() + 5
        while (self.running(supervisor) or self.running(descendant)) and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertFalse(self.running(descendant))
        self.assertFalse(self.running(supervisor))


if __name__ == "__main__":
    unittest.main()
