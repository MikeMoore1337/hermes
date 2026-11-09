"""Hermes #454: actual Linux kernel openat2 tests on disposable temp files.

These tests NEVER mount or inspect owner VPS folders. GitHub Linux runners
exercise actual kernel handles, not a mocked path validator.
"""
from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
import platform
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

from device_fabric.linux_native_files import (
    LinuxNativeFiles, NativeLinuxDenied, MAX_READ_BYTES, MAX_LIST_ENTRIES,
    MAX_SCAN_ENTRIES, RESOLVE_FLAGS, RESOLVE_BENEATH, RESOLVE_NO_XDEV,
    RESOLVE_NO_SYMLINKS, RESOLVE_NO_MAGICLINKS,
)


@unittest.skipUnless(sys.platform == "linux" and
                     platform.machine().lower() in ("x86_64", "aarch64"),
                     "native openat2 requires Linux x86_64/aarch64")
class OriginalLinuxHandleContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="h454-linux-native-ci-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "approved-project"
        self.root.mkdir()
        (self.root / "nested").mkdir()
        (self.root / "README.md").write_bytes(b"original\n")
        (self.root / "nested" / "file.py").write_bytes(b"print(42)\n")
        (self.root / ".env").write_bytes(b"DO_NOT_LEAK")
        (self.root / "service-account.json").write_bytes(b"DO_NOT_LEAK")
        (self.root / ".git").mkdir()
        (self.root / ".git" / "config").write_bytes(b"secret")
        self.outside = Path(self.temp.name) / "outside"
        self.outside.mkdir()
        (self.outside / "outside.txt").write_bytes(b"OUTSIDE_SECRET")

    def open(self) -> LinuxNativeFiles:
        return LinuxNativeFiles(root=self.root, project="hermes")

    def test_actual_openat2_handle_file_read_and_sha256(self):
        with self.open() as adapter:
            out = adapter.read_file("README.md")
            self.assertEqual(base64.b64decode(out["data"]), b"original\n")
            self.assertEqual(out["sha256"], hashlib.sha256(b"original\n").hexdigest())
            self.assertEqual(out["size_bytes"], 9)
            nested = adapter.read_file("nested/file.py")
            self.assertEqual(base64.b64decode(nested["data"]), b"print(42)\n")
            item = adapter.stat_file("nested/file.py")
            self.assertEqual((item["kind"], item["size_bytes"]), ("file", 10))
            self.assertEqual(adapter.stat_file("")["kind"], "directory")

    def test_actual_binary_file_bytes_preserved(self):
        data = b"\x00\xff\xfe\x01binary"
        (self.root / "bytes.txt").write_bytes(data)
        with self.open() as adapter:
            out = adapter.read_file("bytes.txt")
        self.assertEqual(base64.b64decode(out["data"]), data)
        self.assertEqual(out["sha256"], hashlib.sha256(data).hexdigest())

    def test_list_directory_excludes_secrets_links_and_unapproved_extensions(self):
        (self.root / "image.webp").write_bytes(b"public? undecoded")
        (self.root / "escape.txt").symlink_to(self.outside / "outside.txt")
        with self.open() as adapter:
            out = adapter.list_directory()
            entries = {x["name"]: x["kind"] for x in out["entries"]}
            self.assertEqual(entries, {"README.md": "file", "nested": "directory"})
            self.assertFalse(out["truncated"])
            self.assertEqual(adapter.list_directory("nested")["entries"],
                             [{"name": "file.py", "kind": "file"}])

    def test_actual_symlink_and_intermediate_symlink_escape_denied(self):
        (self.root / "link.txt").symlink_to(self.outside / "outside.txt")
        (self.root / "linkdir").symlink_to(self.outside, target_is_directory=True)
        with self.open() as adapter:
            for file in ("link.txt", "linkdir/outside.txt", "linkdir"):
                for command in ("stat", "read"):
                    with self.subTest(file=file, command=command):
                        with self.assertRaises(NativeLinuxDenied):
                            (adapter.stat_file(file) if command == "stat"
                             else adapter.read_file(file))
            with self.assertRaises(NativeLinuxDenied):
                adapter.list_directory("linkdir")

    def test_actual_hardlink_alias_to_outside_refused(self):
        os.link(self.outside / "outside.txt", self.root / "hardlink.txt")
        with self.open() as adapter:
            with self.assertRaises(NativeLinuxDenied):
                adapter.read_file("hardlink.txt")
            with self.assertRaises(NativeLinuxDenied):
                adapter.stat_file("hardlink.txt")
            self.assertNotIn("hardlink.txt",
                             [x["name"] for x in adapter.list_directory()["entries"]])

    def test_refuses_path_traversal_private_paths_and_win_devices(self):
        bad = ("../outside/outside.txt", "nested/../README.md", "/etc/passwd",
               "", "./README.md", "nested//file.py", "nested/.git/config",
               ".env", "service-account.json", ".git/config",
               "CONIN$", "COM¹.txt", "NUL .txt", "nested\\file.py",
               "README.md:secret", "a\x00b.txt", "nested/file.py/..",
               "nested/secret.key")
        with self.open() as adapter:
            for relative in bad:
                with self.subTest(relative=repr(relative)):
                    with self.assertRaises(NativeLinuxDenied):
                        adapter.read_file(relative)
        self.assertEqual((self.outside / "outside.txt").read_bytes(), b"OUTSIDE_SECRET")

    def test_non_source_extensions_and_oversize_read_refused(self):
        (self.root / "data.db").write_bytes(b"database")
        (self.root / "large.txt").write_bytes(b"X" * (MAX_READ_BYTES + 1))
        with self.open() as adapter:
            for relative in ("data.db", "large.txt", "nested"):
                with self.subTest(relative=relative), self.assertRaises(NativeLinuxDenied):
                    adapter.read_file(relative)

    def test_bound_and_truncated_directory_listing(self):
        for i in range(MAX_LIST_ENTRIES + 3):
            (self.root / ("a%03d.txt" % i)).write_text("x")
        with self.open() as adapter:
            out = adapter.list_directory()
        self.assertEqual(len(out["entries"]), MAX_LIST_ENTRIES)
        self.assertTrue(out["truncated"])
        self.assertEqual(out["entries"], sorted(out["entries"],
                         key=lambda x: (x["name"].casefold(), x["name"])))

    def test_too_large_directory_fails_closed(self):
        for i in range(MAX_SCAN_ENTRIES + 1):
            (self.root / ("c%03d.txt" % i)).write_text("x")
        with self.open() as adapter:
            with self.assertRaises(NativeLinuxDenied):
                adapter.list_directory()

    def test_root_symlink_and_parent_symlink_denied(self):
        alias = Path(self.temp.name) / "redirected"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(NativeLinuxDenied):
            LinuxNativeFiles(root=alias, project="hermes")
        wrapper = Path(self.temp.name) / "parentlink"
        wrapper.symlink_to(self.root.parent, target_is_directory=True)
        with self.assertRaises(NativeLinuxDenied):
            LinuxNativeFiles(root=wrapper / self.root.name, project="hermes")

    def test_root_argument_cannot_be_supplied_as_relative_or_unknown_project(self):
        with self.assertRaises(NativeLinuxDenied):
            LinuxNativeFiles(root=Path("relative"), project="hermes")
        with self.assertRaises(NativeLinuxDenied):
            LinuxNativeFiles(root=self.root, project="../somewhere")
        with self.assertRaises(NativeLinuxDenied):
            LinuxNativeFiles(root=self.root, project=42)

    def test_fd_is_closed_and_future_calls_refused(self):
        adapter = self.open()
        fd = adapter._root_fd
        adapter.close()
        with self.assertRaises(NativeLinuxDenied):
            adapter.read_file("README.md")
        with self.assertRaises(OSError):
            os.fstat(fd)

    def test_kernel_openat2_resolution_flags_include_no_xdev_no_magiclinks(self):
        self.assertEqual(RESOLVE_FLAGS, RESOLVE_BENEATH | RESOLVE_NO_XDEV
                         | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)
        with self.open() as adapter:
            self.assertEqual(adapter.stat_file("README.md")["status"], "ok")

    def test_os_error_messages_never_return_original_paths(self):
        with self.open() as adapter:
            with self.assertRaisesRegex(NativeLinuxDenied, "^native_linux_denied$") as caught:
                adapter.read_file("../../etc/shadow")
        self.assertNotIn(str(self.root), str(caught.exception))
        self.assertNotIn("etc/shadow", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
