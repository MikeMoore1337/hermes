"""Dormant Linux original-files READ adapter for Hermes #454 Stage 2A.

Pass an independently owner-approved, locally configured original project
root. This module has NO network listener, service, shell, subprocess, write,
delete or pairing code. It is not registered as a Hermes MCP tool.

All file lookups are relative to a pinned root directory fd using the kernel
openat2 syscall with RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV. Unsupported kernels, architectures,
seccomp policies, permissions and suspicious file types fail closed.
"""
from __future__ import annotations

import base64
import ctypes
import hashlib
import os
from pathlib import Path
import platform
import re
import stat
import sys

from device_fabric.native_effect_grants import (
    GrantDenied, validate_native_file_relative,
)

MAX_READ_BYTES = 256 * 1024
MAX_LIST_ENTRIES = 64
MAX_SCAN_ENTRIES = 256
RESOLVE_NO_XDEV = 0x01
RESOLVE_NO_MAGICLINKS = 0x02
RESOLVE_NO_SYMLINKS = 0x04
RESOLVE_BENEATH = 0x08
RESOLVE_FLAGS = (RESOLVE_NO_XDEV | RESOLVE_NO_MAGICLINKS |
                 RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH)
OPENAT2_SYSCALL = 437   # Linux x86_64 and aarch64; NEVER guess for other ABIs.
PROJECT_ID = re.compile(r"[a-z][a-z0-9_-]{1,63}\Z")
READ_EXTENSIONS = frozenset({
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".md", ".mdx",
    ".txt", ".json", ".toml", ".yaml", ".yml", ".html", ".css", ".scss",
    ".sql", ".sh", ".ps1", ".go", ".rs", ".c", ".h", ".cpp", ".cs", ".xml",
})


class NativeLinuxDenied(ValueError):
    """Sanitized refusal: no original paths, filesystem contents or errno."""


class _OpenHow(ctypes.Structure):
    _fields_ = [("flags", ctypes.c_uint64), ("mode", ctypes.c_uint64),
                ("resolve", ctypes.c_uint64)]


def _kernel_openat2(root_fd: int, relative: str, flags: int) -> int:
    """Enforce kernel relative-to-fd resolution; NO userspace fallback."""
    if sys.platform != "linux" or platform.machine().lower() not in ("x86_64", "aarch64"):
        raise NativeLinuxDenied("native_linux_unavailable")
    # The path has already passed a conservative shared lexical validator.
    # No TOCTOU path checks or os.path.realpath() are security boundaries.
    how = _OpenHow(flags | os.O_CLOEXEC | os.O_NOFOLLOW, 0, RESOLVE_FLAGS)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    result = libc.syscall(ctypes.c_long(OPENAT2_SYSCALL),
                          ctypes.c_int(root_fd),
                          ctypes.c_char_p(relative.encode("utf-8")),
                          ctypes.byref(how), ctypes.c_size_t(ctypes.sizeof(how)))
    if result < 0:
        raise NativeLinuxDenied("native_linux_denied")
    return int(result)


def _relative(relative: str, *, allow_root: bool = False) -> str:
    if allow_root and relative == "":
        return ""
    try:
        validate_native_file_relative(relative)
    except (GrantDenied, UnicodeError, TypeError, ValueError) as exc:
        raise NativeLinuxDenied("native_linux_denied") from None
    return relative


class LinuxNativeFiles:
    """Read-only capability bound to one trusted original Linux directory.

    The caller must obtain root/project from owner-verified LOCAL config,
    never from MCP request fields. A separate restricted systemd identity and
    mount/ACL sandbox are mandatory before a real-host service can start.
    """

    def __init__(self, *, root: Path, project: str):
        if (sys.platform != "linux"
            or platform.machine().lower() not in ("x86_64", "aarch64")
            or type(project) is not str or PROJECT_ID.fullmatch(project) is None):
            raise NativeLinuxDenied("native_linux_unavailable")
        if (type(root) is not Path and not isinstance(root, Path)):
            raise NativeLinuxDenied("native_linux_denied")
        if not root.is_absolute() or ".." in root.parts:
            raise NativeLinuxDenied("native_linux_denied")
        # Root path is a trusted local config value, not an MCP argument.
        # Refuse redirects in ALL directory ancestors during setup. Its parent
        # hierarchy must additionally be OS-protected from hostile rename.
        fd: int | None = None
        try:
            for ancestor in (root, *root.parents):
                node = ancestor.lstat()
                if stat.S_ISLNK(node.st_mode):
                    raise NativeLinuxDenied("native_linux_denied")
            before = root.lstat()
            if not stat.S_ISDIR(before.st_mode):
                raise NativeLinuxDenied("native_linux_denied")
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY |
                         os.O_CLOEXEC | os.O_NOFOLLOW)
            after = os.fstat(fd)
            latest = root.lstat()
            if ((before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
                or (after.st_dev, after.st_ino) != (latest.st_dev, latest.st_ino)):
                raise NativeLinuxDenied("native_linux_denied")
        except (OSError, ValueError):
            if fd is not None:
                os.close(fd)
            raise NativeLinuxDenied("native_linux_denied") from None
        self._root_fd = fd
        self.project = project

    def close(self) -> None:
        if self._root_fd >= 0:
            os.close(self._root_fd)
            self._root_fd = -1

    def __enter__(self) -> "LinuxNativeFiles":
        if self._root_fd < 0:
            raise NativeLinuxDenied("native_linux_denied")
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def _open(self, relative: str, *, directory: bool = False,
              metadata: bool = False) -> int:
        if self._root_fd < 0:
            raise NativeLinuxDenied("native_linux_denied")
        _relative(relative, allow_root=directory or metadata)
        if relative == "":
            return os.dup(self._root_fd)
        flags = (os.O_PATH if metadata else os.O_RDONLY | os.O_NONBLOCK)
        if directory:
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NONBLOCK
        return _kernel_openat2(self._root_fd, relative, flags)

    @staticmethod
    def _kind(info: os.stat_result) -> str:
        if stat.S_ISDIR(info.st_mode):
            return "directory"
        if stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
            return "file"
        raise NativeLinuxDenied("native_linux_denied")

    def stat_file(self, relative: str) -> dict[str, object]:
        """Handle-bound stat; reject symlinks, devices and hard-linked files."""
        try:
            fd = self._open(relative, metadata=True)
            try:
                info = os.fstat(fd)
                kind = self._kind(info)
                return {"status": "ok", "project": self.project,
                        "relative": relative, "action": "stat",
                        "kind": kind,
                        "size_bytes": info.st_size if kind == "file" else None}
            finally:
                os.close(fd)
        except (OSError, ValueError, UnicodeError) as exc:
            raise NativeLinuxDenied("native_linux_denied") from None

    def read_file(self, relative: str) -> dict[str, object]:
        """Binary-safe bounded read, verified against the pinned file handle."""
        _relative(relative)
        if Path(relative).suffix.lower() not in READ_EXTENSIONS:
            raise NativeLinuxDenied("native_linux_denied")
        try:
            fd = self._open(relative)
            try:
                before = os.fstat(fd)
                if (self._kind(before) != "file" or before.st_size < 0
                    or before.st_size > MAX_READ_BYTES):
                    raise NativeLinuxDenied("native_linux_denied")
                # Allow one byte beyond reported size to catch growing files.
                data = os.read(fd, MAX_READ_BYTES + 1)
                after = os.fstat(fd)
                if (len(data) != before.st_size or len(data) > MAX_READ_BYTES
                    or (before.st_dev, before.st_ino, before.st_size,
                        before.st_mtime_ns, before.st_ctime_ns)
                       != (after.st_dev, after.st_ino, after.st_size,
                           after.st_mtime_ns, after.st_ctime_ns)):
                    raise NativeLinuxDenied("native_linux_denied")
                return {"status": "ok", "project": self.project,
                        "relative": relative, "action": "read", "kind": "file",
                        "size_bytes": len(data), "encoding": "base64",
                        "sha256": hashlib.sha256(data).hexdigest(),
                        "data": base64.b64encode(data).decode("ascii")}
            finally:
                os.close(fd)
        except (OSError, ValueError, UnicodeError) as exc:
            raise NativeLinuxDenied("native_linux_denied") from None

    def list_directory(self, relative: str = "") -> dict[str, object]:
        """At most 64 safe entries; bounded scan; no symlink disclosure."""
        try:
            fd = self._open(relative, directory=True)
            try:
                entries: list[dict[str, str]] = []
                scanned = 0
                with os.scandir(fd) as listing:
                    for entry in listing:
                        scanned += 1
                        if scanned > MAX_SCAN_ENTRIES:
                            raise NativeLinuxDenied("native_linux_denied")
                        full = relative + "/" + entry.name if relative else entry.name
                        try:
                            _relative(full)
                            child = self._open(full, metadata=True)
                            try:
                                kind = self._kind(os.fstat(child))
                            finally:
                                os.close(child)
                            if (kind == "directory"
                                or Path(entry.name).suffix.lower() in READ_EXTENSIONS):
                                entries.append({"name": entry.name, "kind": kind})
                        except (NativeLinuxDenied, OSError, ValueError):
                            continue
                entries.sort(key=lambda x: (x["name"].casefold(), x["name"]))
                return {"status": "ok", "project": self.project,
                        "relative": relative, "action": "list",
                        "kind": "directory", "entries": entries[:MAX_LIST_ENTRIES],
                        "truncated": len(entries) > MAX_LIST_ENTRIES}
            finally:
                os.close(fd)
        except (OSError, ValueError, UnicodeError) as exc:
            raise NativeLinuxDenied("native_linux_denied") from None
