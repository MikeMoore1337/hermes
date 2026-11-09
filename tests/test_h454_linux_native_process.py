"""Hermes #454: disposable Linux native process execution under signed grants.

Runs real bounded subprocesses only on GitHub/isolated Linux temp fixtures.
Never touches owner Windows originals, VPS services, production or credentials.
"""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import platform
import sys
import subprocess
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

from device_fabric.linux_native_files import LinuxNativeFiles
from device_fabric.linux_native_process import (
    LinuxNativeOneShotProcess, LocalProcessPolicy, NativeProcessDenied,
    MAX_STDOUT_BYTES, SCHEMA, encode_process_request,
)
from device_fabric.native_effect_admission import (
    LocalAdmissionConfig, NativeEffectAdmission,
)
from device_fabric.native_effect_grants import NativeEffect, SCHEMA as GRANT_SCHEMA, sign_envelope
from scripts import h15_native_effect_receipts as ledger

KEY = b"synthetic-test-only-h454-grant-key-" + b"x" * 24
NOW = 1_800_000_000
DEVICE = "h454-linux-process-ci"
OPID = "7138d606-5cfb-41fb-8021-b0628b3e6e32"


@unittest.skipUnless(sys.platform == "linux" and platform.machine().lower() in ("x86_64", "aarch64")
                     and hasattr(os, "geteuid") and os.geteuid() != 0,
                     "real unprivileged Linux runner required")
class NativeProcessOneShotTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="h454-process-fixture-")
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        self.project = root / "original-test-project"
        self.project.mkdir(mode=0o700)
        self.home = root / "private-home"
        self.home.mkdir(mode=0o700)
        self.state = root / "receipt-state"
        self.state.mkdir(mode=0o700)
        self.files = LinuxNativeFiles(root=self.project, project="hermes")
        self.addCleanup(self.files.close)
        self.program = str(Path(sys.executable).resolve(strict=True))
        self.policy = LocalProcessPolicy(
            private_home=self.home,
            executable_paths=frozenset({self.program}),
            isolation_verified=lambda: True,
        )
        self.config = LocalAdmissionConfig(
            state_directory=self.state, device_id=DEVICE,
            projects=frozenset({"hermes", "financial-horizon"}), verifier_key=KEY)
        self.admission = NativeEffectAdmission(self.config, is_revoked=lambda: False)
        self.runner = LinuxNativeOneShotProcess(self.files, self.admission, self.policy)

    def signed(self, argv=None, *, opid=OPID, project="hermes",
               action="process_run", relative="", ttl=90, timeout=4):
        argv = [self.program, "-I", "-B", "-c", "print(42)"] if argv is None else argv
        request = encode_process_request(argv, timeout)
        effect = NativeEffect(
            GRANT_SCHEMA, DEVICE, project, opid, action, relative,
            hashlib.sha256(request).hexdigest(), NOW + ttl)
        return sign_envelope(effect, issuer_key=KEY, now=NOW), request

    def test_real_signed_python_process_in_pinned_original_root(self):
        frame, payload = self.signed(
            [self.program, "-I", "-B", "-c",
             "import os;print(os.getcwd());print(os.getenv('HOME'))"])
        outcome = self.runner.run(frame, payload, now=NOW)
        self.assertEqual(outcome["status"], "finished")
        self.assertEqual(outcome["exit_code"], 0)
        self.assertEqual(outcome["project"], "hermes")
        self.assertEqual(outcome["operation_id"], OPID)
        self.assertEqual(outcome["stdout"].splitlines(),
                         [str(self.project), str(self.home)])
        self.assertEqual(ledger.inspect(self.state, OPID), "completed")

    def test_child_launcher_fails_closed_for_expired_signed_time(self):
        from device_fabric import linux_native_child
        marker = self.project / "must-not-exist"
        child = str(Path(linux_native_child.__file__).resolve(strict=True))
        command = ("from pathlib import Path;"
                   f"Path({str(marker)!r}).write_text('unexpected')")
        result = subprocess.run(
            [sys.executable, "-I", "-B", child, str(os.getpid()),
             "1", self.program, "-I", "-B", "-c", command],
            cwd=self.project, capture_output=True, timeout=5,
            check=False)
        self.assertEqual(result.returncode, 125)
        self.assertFalse(marker.exists())
        self.assertNotIn(b"unexpected", result.stderr)
        self.assertIn(b"H454_NATIVE_PROCESS_CHILD_REFUSED", result.stderr)

    def test_child_denies_grant_expired_during_resource_setup(self):
        # Reproduce a scheduler/rlimit delay after the early expiry gate
        # and before kernel execve. Do not change real test-process limits.
        from device_fabric import linux_native_child as child
        fake_libc = MagicMock()
        fake_libc.prctl.return_value = 0
        with patch.object(child.os, "getppid", return_value=3456), \
             patch.object(child.os, "geteuid", return_value=1001), \
             patch.object(child.time, "time",
                          side_effect=[NOW + 89, NOW + 91]), \
             patch.object(child.ctypes, "CDLL", return_value=fake_libc), \
             patch.object(child.os, "umask"), \
             patch.object(child.resource, "setrlimit") as setrlimit, \
             patch.object(child.os, "execve") as execve:
            self.assertEqual(child.main(
                ["3456", str(NOW + 90), self.program, "-c", "print('unsafe')"]),
                125)
            self.assertEqual(setrlimit.call_count, 5)
            execve.assert_not_called()

    def test_child_enforces_no_new_privileges(self):
        script = ("import ctypes;"
                  "api=ctypes.CDLL(None);"
                  "print(api.prctl(39,0,0,0,0))")
        frame, payload = self.signed(
            [self.program, "-I", "-B", "-c", script])
        result = self.runner.run(frame, payload, now=NOW)
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["stdout"].strip(), "1")

    def test_real_process_does_not_inherit_secret_environment(self):
        frame, payload = self.signed(
            [self.program, "-I", "-B", "-c",
             "import os;print(os.getenv('OPENAI_API_KEY','ABSENT'))"])
        with patch.dict(os.environ, {"OPENAI_API_KEY": "SYNTHETIC_SECRET"}):
            out = self.runner.run(frame, payload, now=NOW)
        self.assertEqual(out["stdout"].strip(), "ABSENT")
        self.assertNotIn("SYNTHETIC_SECRET", repr(out))

    def test_nonzero_exit_is_reported_without_untrusted_stderr(self):
        frame, payload = self.signed(
            [self.program, "-I", "-B", "-c",
             "import sys;sys.stderr.write('PRIVATE_SECRET');sys.exit(7)"])
        out = self.runner.run(frame, payload, now=NOW)
        self.assertEqual(out["exit_code"], 7)
        self.assertEqual(out["stdout"], "")
        self.assertNotIn("PRIVATE", str(out))
        self.assertEqual(ledger.inspect(self.state, OPID), "completed")

    def test_positive_stdout_at_limit(self):
        frame, payload = self.signed(
            [self.program, "-I", "-B", "-c",
             "import sys;sys.stdout.write('x'*16384)"])
        out = self.runner.run(frame, payload, now=NOW)
        self.assertEqual(len(out["stdout"]), MAX_STDOUT_BYTES)
        self.assertEqual(out["stdout_sha256"], hashlib.sha256(
            b"x" * MAX_STDOUT_BYTES).hexdigest())

    def test_stdout_overflow_is_denied_and_consumes_uuid(self):
        frame, payload = self.signed(
            [self.program, "-I", "-B", "-c",
             "import sys;sys.stdout.write('PRIVATE'*10000)"])
        with self.assertRaisesRegex(NativeProcessDenied, "^native_process_denied$"):
            self.runner.run(frame, payload, now=NOW)
        self.assertEqual(ledger.inspect(self.state, OPID), "failed")

    def test_stderr_overflow_does_not_leak_private_content(self):
        frame, payload = self.signed(
            [self.program, "-I", "-B", "-c",
             "import sys;sys.stderr.write('PRIVATE'*10000)"])
        with self.assertRaises(NativeProcessDenied) as failed:
            self.runner.run(frame, payload, now=NOW)
        self.assertNotIn("PRIVATE", str(failed.exception))
        self.assertEqual(ledger.inspect(self.state, OPID), "failed")

    def test_timeout_kills_bounded_child_and_disallows_replay(self):
        frame, payload = self.signed(
            [self.program, "-I", "-B", "-c",
             "import time;time.sleep(10)"], timeout=1)
        with self.assertRaisesRegex(NativeProcessDenied, "^native_process_denied$"):
            self.runner.run(frame, payload, now=NOW)
        self.assertEqual(ledger.inspect(self.state, OPID), "failed")
        with self.assertRaises(NativeProcessDenied):
            self.runner.run(frame, payload, now=NOW + 1)

    def test_exited_parent_with_inherited_pipe_child_is_killed_on_timeout(self):
        marker = self.project / "escaped-child"
        grandchild = ("import time;from pathlib import Path;"
                      "time.sleep(2);"
                      f"Path({str(marker)!r}).write_text('escaped')")
        parent = ("import subprocess,sys;"
                  f"subprocess.Popen([sys.executable,'-I','-B','-c',{grandchild!r}])")
        frame, payload = self.signed(
            [self.program, "-I", "-B", "-c", parent], timeout=1)
        with self.assertRaisesRegex(NativeProcessDenied, "^native_process_denied$"):
            self.runner.run(frame, payload, now=NOW)
        self.assertEqual(ledger.inspect(self.state, OPID), "failed")
        # Original leader exited before timeout, but its child retained
        # stdout/stderr pipes. SIGKILL must reach the whole process group.
        time.sleep(2.2)
        self.assertFalse(marker.exists(), "descendant escaped process group termination")

    def test_binary_stdout_is_denied(self):
        frame, payload = self.signed(
            [self.program, "-I", "-B", "-c",
             "import os;os.write(1,bytes([255]))"])
        with self.assertRaises(NativeProcessDenied):
            self.runner.run(frame, payload, now=NOW)
        self.assertEqual(ledger.inspect(self.state, OPID), "failed")

    def test_signed_payload_mutation_and_wrong_key_denied(self):
        frame, payload = self.signed()
        changed = encode_process_request(
            [self.program, "-I", "-B", "-c", "print(999)"], 4)
        with self.assertRaises(NativeProcessDenied):
            self.runner.run(frame, changed, now=NOW)
        other = NativeEffectAdmission(
            replace(self.config, verifier_key=b"y" * 40),
            is_revoked=lambda: False)
        runner = LinuxNativeOneShotProcess(self.files, other, self.policy)
        with self.assertRaises(NativeProcessDenied):
            runner.run(frame, payload, now=NOW)
        self.assertFalse((self.state / "native-effects.sqlite3").exists())

    def test_unapproved_executable_refused_before_admission(self):
        frame, payload = self.signed(["/usr/bin/true"])
        with self.assertRaises(NativeProcessDenied):
            self.runner.run(frame, payload, now=NOW)
        self.assertFalse((self.state / "native-effects.sqlite3").exists())

    def test_os_isolation_probe_must_be_true_and_nonroot(self):
        frame, payload = self.signed()
        for result in (False, None, "true"):
            with self.subTest(probe=result):
                config = replace(self.policy, isolation_verified=lambda: result)
                unapproved = LinuxNativeOneShotProcess(self.files, self.admission, config)
                with self.assertRaises(NativeProcessDenied):
                    unapproved.run(frame, payload, now=NOW)
        with patch("device_fabric.linux_native_process.os.geteuid", return_value=0):
            with self.assertRaises(NativeProcessDenied):
                self.runner.run(frame, payload, now=NOW)
        self.assertFalse((self.state / "native-effects.sqlite3").exists())

    def test_revoked_before_admission_prevents_process_execution(self):
        frame, payload = self.signed()
        denied = NativeEffectAdmission(self.config, is_revoked=lambda: True)
        runner = LinuxNativeOneShotProcess(self.files, denied, self.policy)
        with self.assertRaises(NativeProcessDenied):
            runner.run(frame, payload, now=NOW)
        self.assertFalse((self.state / "native-effects.sqlite3").exists())

    def test_revoked_before_spawn_consumes_effect_without_starting(self):
        frame, payload = self.signed()
        check = iter((False, False, True))
        revoked = NativeEffectAdmission(self.config, is_revoked=lambda: next(check))
        runner = LinuxNativeOneShotProcess(self.files, revoked, self.policy)
        with patch("device_fabric.linux_native_process.subprocess.Popen") as popen:
            with self.assertRaises(NativeProcessDenied):
                runner.run(frame, payload, now=NOW)
            popen.assert_not_called()
        self.assertEqual(ledger.inspect(self.state, OPID), "failed")

    def test_grant_expires_between_reservation_and_spawn(self):
        frame, payload = self.signed(ttl=1)
        with patch("device_fabric.linux_native_process.time.time",
                   return_value=NOW + 2):
            with patch("device_fabric.linux_native_process.subprocess.Popen") as popen:
                with self.assertRaises(NativeProcessDenied):
                    self.runner.run(frame, payload, now=NOW)
                popen.assert_not_called()
        self.assertEqual(ledger.inspect(self.state, OPID), "failed")

    def test_different_signed_action_or_project_denied(self):
        # file_write needs a nonempty relative path by signed-grant schema;
        # each negative scenario has its OWN UUID to test the actual scope
        # guard rather than a replay denial from the previous case.
        cases = (("file_write", "hermes", "src/new.py"),
                 ("process_run", "financial-horizon", ""))
        for index, (action, project, relative) in enumerate(cases):
            opid = OPID[:-1] + str(index)
            with self.subTest(action=action, project=project):
                frame, payload = self.signed(
                    action=action, project=project, relative=relative,
                    opid=opid)
                with patch("device_fabric.linux_native_process.subprocess.Popen") as popen:
                    with self.assertRaises(NativeProcessDenied):
                        self.runner.run(frame, payload, now=NOW)
                    popen.assert_not_called()
                self.assertEqual(ledger.inspect(self.state, opid), "failed")

    def test_malformed_requests_refused_before_reservation(self):
        frame, _ = self.signed()
        invalid = (b"", b"{}", b"[]",
                   b'{"argv":[],"timeout_seconds":5,"schema":"'+SCHEMA.encode()+b'"}',
                   b'{"argv":["x"],"argv":["x"],"schema":"'+SCHEMA.encode()+b'","timeout_seconds":1}',
                   b'{"argv":["/usr/bin/true"],"schema":"'+SCHEMA.encode()+b'","timeout_seconds":true}',
                   b'{"schema":"'+SCHEMA.encode()+b'","argv":["x"],"timeout_seconds":0}')
        for payload in invalid:
            with self.subTest(payload=payload[:42]):
                with self.assertRaises(NativeProcessDenied):
                    self.runner.run(frame, payload, now=NOW)
        self.assertFalse((self.state / "native-effects.sqlite3").exists())

    def test_no_automatic_replay_after_completed_process(self):
        frame, payload = self.signed()
        self.runner.run(frame, payload, now=NOW)
        with self.assertRaises(NativeProcessDenied):
            self.runner.run(frame, payload, now=NOW + 1)
        self.assertEqual(ledger.inspect(self.state, OPID), "completed")


if __name__ == "__main__":
    unittest.main()
