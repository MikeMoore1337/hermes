"""Offline contract tests for the Windows native read helper (#454).

The Win32 handle API is simulated, so these are not Windows host E2E.
"""
from __future__ import annotations

import contextlib
import ctypes
import hashlib
import io
import json
import ntpath
import unittest
from unittest.mock import patch

from scripts import h15_native_windows_read as broker
from control_center.native_windows_policy import READ_ROOTS


class FakeWin32:
    def __init__(self, *, project="hermes", relative="README.md",
                 data=b"# Hermes\n"):
        self.root = READ_ROOTS[project]
        self.filename = ntpath.join(self.root, relative)
        self.data = data
        self.root_final = "\\\\?\\" + self.root
        self.target_final = "\\\\?\\" + self.filename
        self.root_flags = broker.FILE_ATTRIBUTE_DIRECTORY
        self.target_flags = 0
        self.hardlinks = 1
        self.closed = []
        self.handles = {}
        self.next_handle = 1000
        self.offsets = {}

    def CreateFileW(self, path, access, share, security, disposition, flags, template):
        assert disposition == broker.OPEN_EXISTING
        assert flags & broker.FILE_FLAG_OPEN_REPARSE_POINT
        assert flags & broker.FILE_FLAG_BACKUP_SEMANTICS
        self.next_handle += 1
        self.handles[self.next_handle] = ("root" if
            ntpath.normcase(path) == ntpath.normcase(self.root) else "file")
        self.offsets[self.next_handle] = 0
        return self.next_handle

    def GetFileInformationByHandle(self, h, info_ptr):
        obj = info_ptr._obj
        is_root = self.handles[h] == "root"
        obj.dwFileAttributes = self.root_flags if is_root else self.target_flags
        obj.nFileSizeHigh = (len(self.data) >> 32)
        obj.nFileSizeLow = len(self.data) & 0xFFFFFFFF
        obj.nNumberOfLinks = 1 if is_root else self.hardlinks
        return True

    def GetFinalPathNameByHandleW(self, h, buffer, size, flags):
        assert flags == 0
        path = self.root_final if self.handles[h] == "root" else self.target_final
        buffer.value = path
        return len(path)

    def ReadFile(self, h, buffer, requested, count_ptr, overlapped):
        assert self.handles[h] == "file"
        cursor = self.offsets[h]
        chunk = self.data[cursor:cursor + requested]
        ctypes.memmove(buffer, chunk, len(chunk))
        count_ptr._obj.value = len(chunk)
        self.offsets[h] += len(chunk)
        return True

    def CloseHandle(self, h):
        self.closed.append(h)
        return True


class NativeWindowsReadTests(unittest.TestCase):
    def test_exact_owner_scopes_and_file_extension(self):
        for project in READ_ROOTS:
            with self.subTest(project=project):
                root, full = broker.build_request(project, r"src\main.py", "read")
                self.assertEqual(root, READ_ROOTS[project])
                self.assertEqual(full, ntpath.join(root, r"src\main.py"))
                self.assertEqual(broker.build_request(project, "", "stat"),
                                 (root, root))

    def test_all_mutating_actions_and_directory_reads_denied(self):
        for op in ("write", "create", "delete", "execute", "list", "run"):
            with self.subTest(op=op), self.assertRaises(broker.NativeReadRefused):
                broker.build_request("hermes", "README.md", op)
        for file in ("", "foo.exe", "id_ed25519", ".git\\config",
                     "secrets\\foo.md", ".env", ".env.prod",
                     "private-vault\\entry.md", "dump.sqlite",
                     "node_modules\\foo.js"):
            with self.subTest(file=file), self.assertRaises(broker.NativeReadRefused):
                broker.build_request("hermes", file, "read")

    def test_parent_escape_ads_unc_dos_device_and_hidden_filename_denied(self):
        invalid = ("..\\private.md", ".\\README.md", "\\\\server\\share.md",
                   "C:\\Windows\\system.md", r"file.txt:secret",
                   "CON", "COM1.txt", "LPT9.md", "name.\\read.md",
                   "name \\README.md", "folder\\\\README.md",
                   "README.md\n", "a/README.md", "e" * 1025,
                   "D:README.md", "first\\..\\README.md",
                   ".ssh\\config.md")
        for relative in invalid:
            with self.subTest(relative=relative):
                with self.assertRaises(broker.NativeReadRefused):
                    broker.build_request("hermes", relative, "read")

    def test_handle_verified_read_hash_and_exact_cleanup(self):
        mock = FakeWin32(data=b"test-body\n")
        with patch.object(broker, "_winapi", return_value=mock):
            result = broker.handle_native_request("hermes", "README.md", "read")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["sha256"], hashlib.sha256(b"test-body\n").hexdigest())
        self.assertEqual(result["data"], "dGVzdC1ib2R5Cg==")
        self.assertEqual(result["size_bytes"], 10)
        self.assertEqual(len(mock.closed), 2)
        self.assertEqual(set(mock.closed), set(mock.handles))

    def test_stat_directory_and_file_never_emit_contents(self):
        file = FakeWin32()
        with patch.object(broker, "_winapi", return_value=file):
            result = broker.handle_native_request("hermes", "README.md", "stat")
        self.assertEqual(result["kind"], "file")
        self.assertNotIn("data", result)
        root = FakeWin32()
        root.target_final = root.root_final
        root.target_flags = broker.FILE_ATTRIBUTE_DIRECTORY
        with patch.object(broker, "_winapi", return_value=root):
            result = broker.handle_native_request("hermes", "", "stat")
        self.assertEqual(result["kind"], "directory")
        self.assertIsNone(result["size_bytes"])

    def test_reparse_and_root_or_target_redirection_denied(self):
        variations = [
            ("root_redirect", "root_final", r"\\?\C:\private"),
            ("file_redirect", "target_final", r"\\?\C:\secrets\README.md"),
            ("inner_alias", "target_final", r"\\?\D:\Pet-projects\hermes\other.md"),
            ("root_reparse", "root_flags",
             broker.FILE_ATTRIBUTE_DIRECTORY | broker.FILE_ATTRIBUTE_REPARSE_POINT),
            ("file_reparse", "target_flags", broker.FILE_ATTRIBUTE_REPARSE_POINT),
            ("hardlink", "hardlinks", 2),
        ]
        for label, key, changed in variations:
            with self.subTest(label=label):
                mock = FakeWin32()
                setattr(mock, key, changed)
                with patch.object(broker, "_winapi", return_value=mock):
                    with self.assertRaises(broker.NativeReadRefused):
                        broker.handle_native_request("hermes", "README.md", "read")
                self.assertEqual(len(mock.closed), 2)

    def test_maximum_read_bytes_enforced_even_when_file_grows(self):
        big = FakeWin32(data=b"z" * (broker.MAX_FILE_BYTES + 1))
        with patch.object(broker, "_winapi", return_value=big):
            with self.assertRaisesRegex(broker.NativeReadRefused, "too_large"):
                broker.handle_native_request("hermes", "README.md", "read")
        growth = FakeWin32(data=b"x" * (broker.MAX_FILE_BYTES + 1))
        with patch.object(broker, "_winapi", return_value=growth):
            with self.assertRaises(broker.NativeReadRefused):
                broker._read_file_handle(growth, 2000, initial_size=1)

    def test_non_windows_api_fails_closed(self):
        if broker.os.name != "nt":
            with self.assertRaises(broker.NativeReadRefused):
                broker._winapi()

    def test_canonical_win32_namespace_refuses_unc(self):
        self.assertEqual(broker.canonical_windows_path(r"\\?\D:\Pet-projects\hermes"),
                         r"d:\pet-projects\hermes")
        for value in (r"\\?\UNC\host\share", r"\\.\COM1", r"\Device\HarddiskVolume3"):
            with self.subTest(value=value), self.assertRaises(broker.NativeReadRefused):
                broker.canonical_windows_path(value)

    def test_cli_denial_does_not_leak_original_path_or_secret(self):
        with patch.object(broker, "handle_native_request",
                          side_effect=broker.NativeReadRefused("C:\\SECRET\\token")):
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = broker.main(["--project", "hermes", "--relative", "README.md",
                                  "--operation", "read"])
        self.assertEqual(rc, 2)
        self.assertEqual(json.loads(stdout.getvalue()),
                         {"status": "refused", "reason": "native_read_denied"})
        self.assertNotIn("SECRET", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
