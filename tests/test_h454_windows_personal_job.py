"""The hidden worker owns its test child; no desktop processes are touched."""
import ctypes
from ctypes import wintypes
import os
import subprocess
import sys
import time
import unittest

from device_fabric import windows_personal_job as jobs


class PersonalJobTests(unittest.TestCase):
    def _refuses_non_windows(self):
        with self.assertRaises(jobs.PersonalJobDenied):
            jobs.attach_current_worker()

    def _worker_exit_terminates_its_child_without_a_console(self):
        worker = r'''
import subprocess,sys
from device_fabric.windows_personal_job import attach_current_worker
attach_current_worker()
p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'],
    stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
    creationflags=subprocess.CREATE_NO_WINDOW)
print(p.pid,flush=True)
sys.stdin.readline()
'''
        proc = subprocess.Popen([sys.executable, "-B", "-c", worker], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        handle = None
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel.GetExitCodeProcess.restype = wintypes.BOOL
        kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        try:
            line = proc.stdout.readline().strip()
            self.assertTrue(line.isdigit(), "worker did not start its test child")
            handle = kernel.OpenProcess(0x1000 | 0x0001, False, int(line))
            self.assertTrue(handle, "could not inspect the exact test child")
            proc.stdin.write("exit\n")
            proc.stdin.flush()
            self.assertEqual(proc.wait(timeout=10), 0)
            deadline = time.monotonic() + 5
            code = wintypes.DWORD(259)
            while time.monotonic() < deadline:
                self.assertTrue(kernel.GetExitCodeProcess(handle, ctypes.byref(code)))
                if code.value != 259:
                    break
                time.sleep(0.05)
            self.assertNotEqual(code.value, 259, "worker left its owned child running")
        finally:
            if handle:
                code = wintypes.DWORD(0)
                if kernel.GetExitCodeProcess(handle, ctypes.byref(code)) and code.value == 259:
                    kernel.TerminateProcess(handle, 1)
                kernel.CloseHandle(handle)
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                if stream:
                    stream.close()


if os.name == "nt":
    PersonalJobTests.test_worker_exit_terminates_its_child_without_a_console = (
        PersonalJobTests._worker_exit_terminates_its_child_without_a_console)
else:
    PersonalJobTests.test_refuses_non_windows = PersonalJobTests._refuses_non_windows

if __name__ == "__main__":
    unittest.main()
