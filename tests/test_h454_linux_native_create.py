"""Stage 2A: real Linux openat2 exclusive create in disposable temp roots ONLY.

No original VPS folders, no MCP transport, no actual owner credentials.
The tests exercise the kernel create path and durable SQLite admission.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import os
from pathlib import Path
import platform
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

from device_fabric.native_effect_grants import GrantDenied, NativeEffect, SCHEMA, sign_envelope
from device_fabric.native_effect_admission import LocalAdmissionConfig, NativeEffectAdmission
from device_fabric.linux_native_files import LinuxNativeFiles, NativeLinuxDenied
from device_fabric import linux_native_create as native
from scripts import h15_native_effect_receipts as ledger

NOW = 1_800_000_000
KEY = b"synthetic-only-owner-grant-key-0123456789ab"
DEVICE = "h454-test-linux-native"
UUID = "7138d606-5cfb-41fb-8021-b0628b3e6e32"


@unittest.skipUnless(
    sys.platform == "linux" and platform.machine().lower() in ("x86_64", "aarch64"),
    "openat2 exclusive create tested only on real Linux x86_64/aarch64")
class LinuxExclusiveCreateContracts(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="h454-native-create-ci-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name) / "original-fixture"
        self.root.mkdir()
        (self.root / "src").mkdir()
        self.state = Path(tmp.name) / "native-ledger"
        self.state.mkdir(mode=0o700)
        self.external = Path(tmp.name) / "outside"
        self.external.mkdir()
        self.config = LocalAdmissionConfig(
            state_directory=self.state, device_id=DEVICE,
            projects=frozenset({"hermes"}), verifier_key=KEY)
        self.files = LinuxNativeFiles(root=self.root, project="hermes")
        self.addCleanup(self.files.close)
        self.admission = NativeEffectAdmission(self.config, is_revoked=lambda: False)
        self.create = native.LinuxNativeExclusiveCreate(self.files, self.admission)

    def frame(self, *, content: bytes = b"hello\n", path: str = "src/new.py",
              op: str = "file_write", uuid: str = UUID,
              project: str = "hermes", expires: int = NOW + 90) -> bytes:
        effect = NativeEffect(
            SCHEMA, DEVICE, project, uuid, op, path,
            hashlib.sha256(content).hexdigest(), expires)
        return sign_envelope(effect, issuer_key=KEY, now=NOW)

    def test_real_kernel_signed_create_binary_sha_and_mode(self):
        contents = b"\x00\xff\xfe\n" * 1024
        output = self.create.create(self.frame(content=contents), contents, now=NOW)
        target = self.root / "src" / "new.py"
        self.assertEqual(target.read_bytes(), contents)
        self.assertEqual(output["status"], "created")
        self.assertEqual(output["operation_id"], UUID)
        self.assertEqual(output["sha256"], hashlib.sha256(contents).hexdigest())
        self.assertEqual(output["size_bytes"], len(contents))
        self.assertEqual(stat.S_IMODE(target.stat().st_mode) & ~0o600, 0)
        self.assertEqual(target.stat().st_nlink, 1)
        self.assertEqual(ledger.inspect(self.state, UUID), "completed")

    def test_create_empty_file_at_project_root(self):
        wire = self.frame(content=b"", path="new.txt")
        result = self.create.create(wire, b"", now=NOW)
        self.assertEqual((self.root / "new.txt").read_bytes(), b"")
        self.assertEqual(result["size_bytes"], 0)
        self.assertEqual(ledger.inspect(self.state, UUID), "completed")

    def test_existing_directory_cannot_be_replaced(self):
        (self.root / "src" / "new.py").mkdir()
        with self.assertRaises(NativeLinuxDenied):
            self.create.create(self.frame(), b"hello\n", now=NOW)
        self.assertTrue((self.root / "src" / "new.py").is_dir())

    def test_invalid_kernel_create_mode_denied_before_syscall(self):
        from device_fabric.linux_native_files import _kernel_openat2
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
        with self.assertRaisesRegex(NativeLinuxDenied, "^native_linux_denied$"):
            _kernel_openat2(self.files._root_fd, "src/no-file.py",
                            flags, mode=0o777)
        self.assertFalse((self.root / "src" / "no-file.py").exists())

    def test_exclusive_create_never_overwrites_original(self):
        original = self.root / "src" / "new.py"
        original.write_bytes(b"original bytes")
        with self.assertRaisesRegex(NativeLinuxDenied, "^native_linux_denied$"):
            self.create.create(self.frame(), b"hello\n", now=NOW)
        self.assertEqual(original.read_bytes(), b"original bytes")
        self.assertEqual(ledger.inspect(self.state, UUID), "failed")

    def test_replay_after_success_consumed_without_second_file_change(self):
        frame = self.frame()
        self.create.create(frame, b"hello\n", now=NOW)
        with self.assertRaises(NativeLinuxDenied):
            self.create.create(frame, b"hello\n", now=NOW+1)
        self.assertEqual((self.root / "src" / "new.py").read_bytes(), b"hello\n")
        self.assertEqual(ledger.inspect(self.state, UUID), "completed")

    def test_signed_project_mismatch_or_unrelated_action_cannot_write(self):
        cases = (("financial-horizon", "file_write"),
                 ("hermes", "file_edit"), ("hermes", "file_delete"))
        for index, (project, op) in enumerate(cases):
            with self.subTest(project=project, op=op):
                with self.assertRaises(NativeLinuxDenied):
                    self.create.create(
                        self.frame(project=project, op=op, uuid=UUID[:-1] + str(index)),
                        b"hello\n", now=NOW)
                self.assertFalse((self.root / "src" / "new.py").exists())

    def test_unsafe_secret_path_and_traversal_denied_pre_effect(self):
        for path in (".env", "src/../.env", "../outside/private.py",
                     "src/.git/config", "src/CONIN$.py", "/etc/shadow",
                     "src/service-account.json", r"src/folder\file.py"):
            with self.subTest(path=path), self.assertRaises(GrantDenied):
                self.frame(path=path)
        self.assertEqual(list(self.root.glob("src/*.py")), [])

    def test_symlink_parent_and_symlink_destination_never_followed(self):
        (self.root / "redirected").symlink_to(self.external, target_is_directory=True)
        (self.root / "src" / "new.py").symlink_to(self.external / "new.py")
        for index, name in enumerate(("redirected/new.py", "src/new.py")):
            with self.subTest(name=name), self.assertRaises(NativeLinuxDenied):
                self.create.create(
                    self.frame(path=name, uuid=UUID[:-1] + str(index)),
                    b"hello\n", now=NOW)
        self.assertFalse((self.external / "new.py").exists())
        self.assertTrue((self.root / "src" / "new.py").is_symlink())

    def test_hardlinked_existing_file_cannot_be_replaced(self):
        target = self.external / "original.py"
        target.write_bytes(b"protected")
        os.link(target, self.root / "src" / "new.py")
        with self.assertRaises(NativeLinuxDenied):
            self.create.create(self.frame(), b"hello\n", now=NOW)
        self.assertEqual(target.read_bytes(), b"protected")

    def test_modified_payload_and_wrong_key_never_create(self):
        with self.assertRaises(NativeLinuxDenied):
            self.create.create(self.frame(content=b"correct"), b"evil", now=NOW)
        other = NativeEffectAdmission(
            LocalAdmissionConfig(
                self.state, DEVICE, frozenset({"hermes"}), b"K" * 48),
            is_revoked=lambda: False)
        bad = native.LinuxNativeExclusiveCreate(self.files, other)
        with self.assertRaises(NativeLinuxDenied):
            bad.create(self.frame(), b"hello\n", now=NOW)
        self.assertFalse((self.root / "src" / "new.py").exists())

    def test_revoked_device_denies_before_creating_file_or_ledger(self):
        revoked = NativeEffectAdmission(self.config, is_revoked=lambda: True)
        runner = native.LinuxNativeExclusiveCreate(self.files, revoked)
        with self.assertRaises(NativeLinuxDenied):
            runner.create(self.frame(), b"hello\n", now=NOW)
        self.assertFalse((self.root / "src" / "new.py").exists())
        self.assertFalse((self.state / "native-effects.sqlite3").exists())

    def test_revoked_after_reserving_uuid_consumes_grant(self):
        statuses = iter((False, False, True))
        agent = NativeEffectAdmission(self.config, is_revoked=lambda: next(statuses))
        runner = native.LinuxNativeExclusiveCreate(self.files, agent)
        with self.assertRaises(NativeLinuxDenied):
            runner.create(self.frame(), b"hello\n", now=NOW)
        self.assertEqual(ledger.inspect(self.state, UUID), "failed")
        self.assertFalse((self.root / "src" / "new.py").exists())

    def test_expired_after_reservation_before_syscall_refused(self):
        # The signed grant was valid when SQLite reserved its UUID, but the
        # actual owner-host clock crossed expiration before kernel openat2.
        with patch.object(native.time, "time", return_value=NOW + 91):
            with self.assertRaisesRegex(NativeLinuxDenied, "^native_linux_denied$"):
                self.create.create(self.frame(expires=NOW + 90),
                                   b"hello\n", now=NOW)
        self.assertEqual(ledger.inspect(self.state, UUID), "failed")
        self.assertFalse((self.root / "src" / "new.py").exists())

    def test_grant_valid_just_before_expiration_can_create(self):
        with patch.object(native.time, "time", return_value=NOW + 89):
            result = self.create.create(self.frame(expires=NOW + 90),
                                        b"hello\n", now=NOW)
        self.assertEqual(result["status"], "created")
        self.assertEqual((self.root / "src" / "new.py").read_bytes(), b"hello\n")

    def test_no_parent_directory_may_be_created_implicitly(self):
        with self.assertRaises(NativeLinuxDenied):
            self.create.create(self.frame(path="missing/file.py"),
                               b"hello\n", now=NOW)
        self.assertFalse((self.root / "missing").exists())
        self.assertEqual(ledger.inspect(self.state, UUID), "failed")

    def test_unsupported_extension_and_oversize_refused(self):
        for index, extension in enumerate(("data.db", "package.exe")):
            with self.subTest(extension=extension), self.assertRaises(NativeLinuxDenied):
                self.create.create(
                    self.frame(path="src/" + extension,
                               uuid=UUID[:-1] + str(index)),
                    b"hello\n", now=NOW)
        with self.assertRaises(GrantDenied):
            self.frame(path="src/secrets.pfx")
        huge = b"X" * (256 * 1024 + 1)
        with self.assertRaises(NativeLinuxDenied):
            self.create.create(self.frame(content=huge), huge, now=NOW)
        self.assertFalse((self.root / "src" / "new.py").exists())

    def test_concurrent_same_uuid_only_one_effect_occurs(self):
        frame = self.frame()
        def attempt(_):
            try:
                self.create.create(frame, b"hello\n", now=NOW)
                return "created"
            except NativeLinuxDenied:
                return "denied"
        with ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(attempt, range(16)))
        self.assertEqual(outcomes.count("created"), 1)
        self.assertEqual(outcomes.count("denied"), 15)
        self.assertEqual((self.root/"src"/"new.py").read_bytes(), b"hello\n")

    def test_two_independent_grants_same_filename_never_overwrite(self):
        first = self.frame(uuid=UUID)
        second = self.frame(uuid="6138d606-5cfb-41fb-8021-b0628b3e6e33", content=b"second")
        self.create.create(first, b"hello\n", now=NOW)
        with self.assertRaises(NativeLinuxDenied):
            self.create.create(second, b"second", now=NOW)
        self.assertEqual((self.root/"src"/"new.py").read_bytes(), b"hello\n")
        self.assertEqual(ledger.inspect(self.state, "6138d606-5cfb-41fb-8021-b0628b3e6e33"), "failed")

    def test_io_error_leaves_consumed_receipt_no_automatic_cleanup(self):
        original_write = os.write
        calls = 0
        def partial(fd, data):
            nonlocal calls
            calls += 1
            if calls == 1:
                return original_write(fd, data[:2])
            raise OSError("sensitive-private-path")
        with patch.object(native.os, "write", side_effect=partial):
            with self.assertRaisesRegex(NativeLinuxDenied, "^native_linux_denied$"):
                self.create.create(self.frame(), b"hello\n", now=NOW)
        self.assertEqual(ledger.inspect(self.state, UUID), "failed")
        self.assertEqual((self.root/"src"/"new.py").read_bytes(), b"he")
        with self.assertRaises(NativeLinuxDenied):
            self.create.create(self.frame(), b"hello\n", now=NOW+1)

    def test_kernel_openat2_unsupported_fail_closed_no_fallback(self):
        with patch.object(native, "_kernel_openat2", side_effect=NativeLinuxDenied("native_linux_denied")):
            with self.assertRaises(NativeLinuxDenied):
                self.create.create(self.frame(), b"hello\n", now=NOW)
        self.assertFalse((self.root/"src"/"new.py").exists())
        self.assertEqual(ledger.inspect(self.state, UUID), "failed")

    def test_crash_before_completion_refuses_replay_without_host_effect(self):
        # Simulate an unexpected interpreter exit immediately after durable
        # reservation by intercepting the effect-scoped open.
        class SimulatedCrash(BaseException):
            pass
        with patch.object(native, "_kernel_openat2", side_effect=SimulatedCrash):
            with self.assertRaises(SimulatedCrash):
                self.create.create(self.frame(), b"hello\n", now=NOW)
        self.assertEqual(ledger.inspect(self.state, UUID), "reserved")
        with self.assertRaises(NativeLinuxDenied):
            self.create.create(self.frame(), b"hello\n", now=NOW+1)
        self.assertFalse((self.root/"src"/"new.py").exists())


if __name__ == "__main__":
    unittest.main()
