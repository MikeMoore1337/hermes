"""Source-only Windows handle-bound *read/stat* helper for Hermes #454.

NOT deployed or exposed as MCP. Running this on the native Windows host
requires a separate owner approval for that exact process invocation.

The script takes only one of five owner-approved project identifiers and
a relative file path. It never writes, deletes, launches a subprocess, or
opens a network listener. Contents are emitted only on an explicit read.
Directory listing is bounded to the approved project root; no shell bridge.

Real Windows handles are checked for reparse points and compared against
the opened original-root handle using GetFinalPathNameByHandleW. A pure
lexical path check is not sufficient; do not bypass the handle checks.
"""
from __future__ import annotations

import argparse
import base64
import ctypes
from ctypes import wintypes
import hashlib
import json
import ntpath
import os
import re
import sys
import time

from device_fabric.native_effect_grants import windows_reserved_component
from device_fabric.native_list_pages import PAGE_SIZE, SCAN_LIMIT, SCAN_SECONDS, page
from control_center.native_windows_policy import (READ_ROOTS, SENSITIVE_STEM,
                                                  classify_native_request)

MAX_FILE_BYTES = 256 * 1024
MAX_PATH_LENGTH = 1024
MAX_LIST_ENTRIES = PAGE_SIZE
MAX_SCAN_ENTRIES = SCAN_LIMIT
# The project root's own ancestors plus up to 64 search path components.
MAX_LIST_ANCESTORS = 80
ALLOWED_EXTENSIONS = frozenset({
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".md", ".mdx", ".txt", ".json", ".toml", ".yaml", ".yml",
    ".html", ".css", ".scss", ".sql", ".sh", ".ps1",
    ".go", ".rs", ".c", ".h", ".cpp", ".cs", ".xml",
})
DENIED_COMPONENTS = frozenset({
    ".git", ".hg", ".svn", ".ssh", ".aws", ".gnupg", "secrets",
    ".secrets", ".vault", "vault", "private-vault", "node_modules",
    "__pycache__", ".terraform", ".next", ".cache",
})
DENIED_NAMES = frozenset({"id_rsa", "id_ed25519", "credentials", "config.local"})
DENIED_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".kdbx", ".sqlite", ".sqlite3", ".db")

FILE_ATTRIBUTE_DIRECTORY = 0x10
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_READ_ATTRIBUTES = 0x80
FILE_READ_DATA = 0x1  # FILE_LIST_DIRECTORY for directories
GENERIC_READ = 0x80000000
OPEN_EXISTING = 3
FILE_SHARE_READ = 0x1
FILE_SHARE_WRITE = 0x2
FILE_SHARE_DELETE = 0x4


class NativeReadRefused(Exception):
    """Bounded generic refusal; do not leak paths or secrets."""


def build_request(project: str, relative: str, operation: str) -> tuple[str, str]:
    """Validate user-supplied relative path. This is only the FIRST gate."""
    if project not in READ_ROOTS or operation not in {"read", "stat"}:
        raise NativeReadRefused("unknown_project_or_action")
    if not isinstance(relative, str) or len(relative) > MAX_PATH_LENGTH:
        raise NativeReadRefused("unsafe_relative_path")
    if relative:
        if relative.startswith("\\") or "/" in relative or "\x00" in relative:
            raise NativeReadRefused("unsafe_relative_path")
        pieces = relative.split("\\")
        if any(not part or part in {".", ".."} or part.endswith((" ", "."))
               or ":" in part or any(ord(c) < 32 for c in part)
               or windows_reserved_component(part) for part in pieces):
            raise NativeReadRefused("unsafe_relative_path")
        lowered = [p.casefold() for p in pieces]
        if any(p in DENIED_COMPONENTS or p.startswith(".env.")
               or p in DENIED_NAMES or SENSITIVE_STEM.match(p) for p in lowered):
            raise NativeReadRefused("protected_project_content")
        if lowered[-1].endswith(DENIED_SUFFIXES):
            raise NativeReadRefused("protected_project_content")
    if operation == "read" and (
        not relative or ntpath.splitext(relative)[1].lower() not in ALLOWED_EXTENSIONS
    ):
        raise NativeReadRefused("unsupported_read_file_type")
    path = ntpath.join(READ_ROOTS[project], relative) if relative else READ_ROOTS[project]
    policy = classify_native_request(path, "read" if operation == "read" else "stat")
    if policy.status != "read_policy_approved" or policy.project != project:
        raise NativeReadRefused("path_not_in_approved_scope")
    return READ_ROOTS[project], path


class FileTime(ctypes.Structure):
    _fields_ = [("dwLowDateTime", wintypes.DWORD),
                ("dwHighDateTime", wintypes.DWORD)]


class ByHandleFileInformation(ctypes.Structure):
    _fields_ = [
        ("dwFileAttributes", wintypes.DWORD),
        ("ftCreationTime", FileTime),
        ("ftLastAccessTime", FileTime),
        ("ftLastWriteTime", FileTime),
        ("dwVolumeSerialNumber", wintypes.DWORD),
        ("nFileSizeHigh", wintypes.DWORD),
        ("nFileSizeLow", wintypes.DWORD),
        ("nNumberOfLinks", wintypes.DWORD),
        ("nFileIndexHigh", wintypes.DWORD),
        ("nFileIndexLow", wintypes.DWORD),
    ]


def canonical_windows_path(value: str) -> str:
    """Compare DOS final paths, refusing Win32 device and UNC namespace."""
    if not value.startswith("\\\\?\\") or value.startswith("\\\\?\\UNC\\"):
        raise NativeReadRefused("unexpected_windows_namespace")
    path = value[4:]
    if not re.match(r"^[A-Za-z]:\\", path):
        raise NativeReadRefused("unexpected_windows_namespace")
    return ntpath.normcase(ntpath.normpath(path))


def _winapi():
    if os.name != "nt":
        raise NativeReadRefused("native_windows_required")
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    api.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
        wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
        wintypes.HANDLE]
    api.CreateFileW.restype = wintypes.HANDLE
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    api.CloseHandle.restype = wintypes.BOOL
    api.GetFileInformationByHandle.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(ByHandleFileInformation)]
    api.GetFileInformationByHandle.restype = wintypes.BOOL
    api.GetFinalPathNameByHandleW.argtypes = [
        wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
    api.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    api.ReadFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
        wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    api.ReadFile.restype = wintypes.BOOL
    return api


class _DirectoryWatch:
    """Fail a pathname-based scan if its directory changes while scanning."""

    def __init__(self, path: str):
        api = ctypes.WinDLL("kernel32", use_last_error=True)
        api.FindFirstChangeNotificationW.argtypes = [wintypes.LPCWSTR, wintypes.BOOL, wintypes.DWORD]
        api.FindFirstChangeNotificationW.restype = wintypes.HANDLE
        api.FindCloseChangeNotification.argtypes = [wintypes.HANDLE]
        api.FindCloseChangeNotification.restype = wintypes.BOOL
        api.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        api.WaitForSingleObject.restype = wintypes.DWORD
        # The listing exposes names and kinds, not file contents or metadata.
        # Name events catch create, delete and rename without spurious delayed
        # file-write notifications from changes completed before this scan.
        handle = api.FindFirstChangeNotificationW(path, False, 0x1 | 0x2)
        if handle == ctypes.c_void_p(-1).value or not handle:
            raise NativeReadRefused("directory_watch_unavailable")
        self._api, self._handle = api, handle

    def unchanged(self) -> bool:
        # WAIT_TIMEOUT is the only successful no-change result; all other
        # statuses, including errors and signalled notifications, deny.
        return self._api.WaitForSingleObject(self._handle, 0) == 258

    def close(self) -> None:
        if self._handle is not None:
            handle, self._handle = self._handle, None
            if not self._api.FindCloseChangeNotification(handle):
                raise NativeReadRefused("directory_watch_unavailable")


def _opened(api, path: str, *, content: bool, lock_rename: bool = False):
    flags = FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS
    access = GENERIC_READ if content else FILE_READ_ATTRIBUTES
    # Keep a content read stable while another process wants to write or rename.
    shares = FILE_SHARE_READ
    if not content:
        shares |= FILE_SHARE_WRITE
    if lock_rename:
        # Attribute-only handles do not enforce the deny-delete share on Windows.
        access |= FILE_READ_DATA
    elif not content:
        shares |= FILE_SHARE_DELETE
    h = api.CreateFileW(path, access, shares,
        None, OPEN_EXISTING, flags, None)
    if h == ctypes.c_void_p(-1).value:
        if content and getattr(ctypes, "get_last_error", lambda: 0)() == 32:
            raise NativeReadRefused("file_busy")
        raise NativeReadRefused("open_denied")
    return h


def _metadata(api, h):
    info = ByHandleFileInformation()
    if not api.GetFileInformationByHandle(h, ctypes.byref(info)):
        raise NativeReadRefused("metadata_denied")
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT:
        raise NativeReadRefused("reparse_point_denied")
    return info


def _final_path(api, h):
    buf = ctypes.create_unicode_buffer(32768)
    n = api.GetFinalPathNameByHandleW(h, buf, len(buf), 0)
    if n == 0 or n >= len(buf):
        raise NativeReadRefused("final_path_unavailable")
    return canonical_windows_path(buf.value)


def _read_file_handle(api, handle, *, initial_size: int) -> bytes:
    if initial_size > MAX_FILE_BYTES:
        raise NativeReadRefused("file_too_large")
    chunks = []
    total = 0
    while total <= MAX_FILE_BYTES:
        room = min(65536, MAX_FILE_BYTES + 1 - total)
        buf = ctypes.create_string_buffer(room)
        count = wintypes.DWORD(0)
        if not api.ReadFile(handle, buf, room, ctypes.byref(count), None):
            raise NativeReadRefused("read_denied")
        if count.value == 0:
            return b"".join(chunks)
        total += count.value
        if total > MAX_FILE_BYTES:
            raise NativeReadRefused("file_too_large")
        chunks.append(buf.raw[:count.value])
    raise NativeReadRefused("file_too_large")


def handle_native_request(project: str, relative: str, operation: str) -> dict:
    """Use only verified live handles; no second path-based file open."""
    root, requested = build_request(project, relative, operation)
    api = _winapi()
    root_handle = _opened(api, root, content=False, lock_rename=True)
    try:
        root_info = _metadata(api, root_handle)
        if not root_info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY:
            raise NativeReadRefused("root_not_directory")
        root_final = _final_path(api, root_handle)
        if root_final != ntpath.normcase(ntpath.normpath(root)):
            raise NativeReadRefused("root_redirected")
        # Keep root handle open so its physical identity is stable while
        # the target is opened and checked.
        target = _opened(api, requested, content=operation == "read")
        try:
            info = _metadata(api, target)
            resolved = _final_path(api, target)
            if resolved != ntpath.normcase(ntpath.normpath(requested)) or not (
                resolved == root_final or resolved.startswith(root_final + "\\")
            ):
                raise NativeReadRefused("target_redirected")
            is_directory = bool(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            if not is_directory and info.nNumberOfLinks != 1:
                raise NativeReadRefused("hardlink_denied")
            size = (info.nFileSizeHigh << 32) | info.nFileSizeLow
            result = {"status": "ok", "project": project,
                      "relative": relative, "action": operation,
                      "kind": "directory" if is_directory else "file"}
            if operation == "stat":
                result["size_bytes"] = None if is_directory else size
                return result
            if is_directory:
                raise NativeReadRefused("directory_not_readable_as_file")
            body = _read_file_handle(api, target, initial_size=size)
            return {**result, "encoding": "base64",
                    "size_bytes": len(body),
                    "sha256": hashlib.sha256(body).hexdigest(),
                    "data": base64.b64encode(body).decode("ascii")}
        finally:
            api.CloseHandle(target)
    finally:
        api.CloseHandle(root_handle)



def handle_native_list(project: str, relative: str = "", *, cursor: str | None = None) -> dict:
    """Enumerate safe immediate code names within one approved project.

    No recursive walk, no file contents, no alternate host directories.
    Every ancestor, from the drive root through the requested directory, is
    held without FILE_SHARE_DELETE while the path-based iterator is open.
    Every returned entry is independently opened and handle-verified.
    """
    root, requested = build_request(project, relative, "stat")
    drive, tail = ntpath.splitdrive(root)
    if (len(drive) != 2 or drive[1] != ':' or not ntpath.isabs(root)
        or ntpath.normpath(root) != root):
        raise NativeReadRefused("unsafe_project_root")
    parts = [part for part in tail.split('\\') if part]
    if relative:
        parts.extend(relative.split('\\'))
    if len(parts) + 1 > MAX_LIST_ANCESTORS:
        raise NativeReadRefused("directory_depth_limit")
    api = _winapi()
    handles = []
    watch = None
    try:
        path = drive + '\\'
        for part in [None, *parts]:
            if part is not None:
                path = ntpath.join(path, part)
            handle = _opened(api, path, content=False, lock_rename=True)
            handles.append(handle)
            info = _metadata(api, handle)
            if (not info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY
                or _final_path(api, handle) != ntpath.normcase(ntpath.normpath(path))):
                raise NativeReadRefused("directory_redirected")
        if ntpath.normcase(ntpath.normpath(path)) != ntpath.normcase(ntpath.normpath(requested)):
            raise NativeReadRefused("directory_redirected")
        resolved_root = ntpath.normcase(ntpath.normpath(root))
        watch = _DirectoryWatch(requested)
        visible = []
        scanned = 0
        deadline = time.monotonic() + SCAN_SECONDS
        try:
            with os.scandir(requested) as iterator:
                for entry in iterator:
                    scanned += 1
                    if scanned > MAX_SCAN_ENTRIES or time.monotonic() >= deadline:
                        raise NativeReadRefused("directory_too_large")
                    name = entry.name
                    if not isinstance(name, str):
                        continue
                    try:
                        # Reuse the EXACT path restrictions of the native
                        # read broker for each disclosed file or directory.
                        child_relative = relative + '\\' + name if relative else name
                        _, path = build_request(project, child_relative, "stat")
                        if entry.is_symlink() or (
                            hasattr(entry, "is_junction") and entry.is_junction()
                        ):
                            continue
                        candidate = _opened(api, path, content=False, lock_rename=True)
                        try:
                            child = _metadata(api, candidate)
                            expected = ntpath.normcase(ntpath.normpath(path))
                            if _final_path(api, candidate) != expected or (
                                not expected.startswith(resolved_root + "\\")
                            ):
                                continue
                            directory = bool(child.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                            if not directory and child.nNumberOfLinks != 1:
                                continue
                            if not directory and ntpath.splitext(name)[1].lower() not in ALLOWED_EXTENSIONS:
                                continue
                            visible.append({"name": name, "kind": "directory" if directory else "file"})
                        finally:
                            api.CloseHandle(candidate)
                    except (NativeReadRefused, OSError, ValueError):
                        # Exclude inaccessible/forbidden entries by name, never
                        # disclose details, resolve symlinks, or follow into them.
                        continue
        except (OSError, UnicodeError) as exc:
            raise NativeReadRefused("enumeration_unavailable") from exc
        visible.sort(key=lambda item: (item["name"].casefold(), item["name"]))
        if not watch.unchanged():
            raise NativeReadRefused("directory_changed")
        if cursor is not None:
            try:
                selected, next_cursor = page(visible, project, relative, cursor)
            except ValueError as exc:
                raise NativeReadRefused("invalid_page") from exc
            return {"status": "ok", "project": project, "relative": relative,
                    "action": "list", "kind": "directory", "entries": selected,
                    "truncated": bool(next_cursor), "next_cursor": next_cursor}
        return {
            "status": "ok", "project": project, "relative": relative,
            "action": "list", "kind": "directory",
            "entries": visible[:MAX_LIST_ENTRIES],
            "truncated": len(visible) > MAX_LIST_ENTRIES,
        }
    finally:
        try:
            if watch is not None:
                watch.close()
        finally:
            for handle in reversed(handles):
                api.CloseHandle(handle)



def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Owner-gated native Windows file reader")
    p.add_argument("--project", required=True, choices=sorted(READ_ROOTS))
    p.add_argument("--relative", required=True)
    p.add_argument("--operation", required=True, choices=("stat", "read"))
    args = p.parse_args(argv)
    try:
        result = handle_native_request(args.project, args.relative, args.operation)
    except (NativeReadRefused, OSError, ValueError):
        print(json.dumps({"status": "refused", "reason": "native_read_denied"}))
        return 2
    print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
