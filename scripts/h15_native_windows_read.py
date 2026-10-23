"""Source-only Windows handle-bound *read/stat* helper for Hermes #454.

NOT deployed or exposed as MCP. Running this on the native Windows host
requires a separate owner approval for that exact process invocation.

The script takes only one of four owner-approved project identifiers and
a relative file path. It never writes, deletes, launches a subprocess, or
opens a network listener. Contents are emitted only on an explicit read.
No directory listing or shell/command bridge is provided.

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

from control_center.native_windows_policy import READ_ROOTS, classify_native_request

MAX_FILE_BYTES = 256 * 1024
MAX_PATH_LENGTH = 1024
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
DOS_RESERVED = re.compile(r"^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$", re.I)

FILE_ATTRIBUTE_DIRECTORY = 0x10
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_READ_ATTRIBUTES = 0x80
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
               or DOS_RESERVED.fullmatch(part) for part in pieces):
            raise NativeReadRefused("unsafe_relative_path")
        lowered = [p.casefold() for p in pieces]
        if any(p in DENIED_COMPONENTS or p.startswith(".env.")
               or p in DENIED_NAMES for p in lowered):
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


def _opened(api, path: str, *, content: bool):
    flags = FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS
    access = GENERIC_READ if content else FILE_READ_ATTRIBUTES
    h = api.CreateFileW(path, access,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        None, OPEN_EXISTING, flags, None)
    if h == ctypes.c_void_p(-1).value:
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
    root_handle = _opened(api, root, content=False)
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
