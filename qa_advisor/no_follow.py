"""Open one regular file without following a final-component symlink.

Linux uses O_NOFOLLOW. Windows uses CreateFileW OPEN_REPARSE_POINT plus
handle-bound FILE_ATTRIBUTE_REPARSE_POINT verification; no path-based
precheck is used as a substitute for this handle check.

This protects the final path component, not arbitrary untrusted parent
directory junctions. The caller must restrict the parent directory.
"""
from __future__ import annotations

import os
from pathlib import Path


def open_nofollow(path: Path) -> int:
    """Return an owned file descriptor; caller must close it."""
    if os.name != "nt":
        flag = getattr(os, "O_NOFOLLOW", None)
        if flag is None:
            raise OSError("no_follow_unavailable")
        return os.open(path, os.O_RDONLY | flag | getattr(os, "O_CLOEXEC", 0))
    return _windows_open_nofollow(path)


def _windows_open_nofollow(path: Path) -> int:
    """On Windows inspect the opened handle, never the potentially raced path."""
    import ctypes
    from ctypes import wintypes
    import msvcrt

    class ByHandleFileInformation(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", wintypes.FILETIME),
            ("ftLastAccessTime", wintypes.FILETIME),
            ("ftLastWriteTime", wintypes.FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        ]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel.CreateFileW
    create.argtypes = (
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    )
    create.restype = wintypes.HANDLE
    info_fn = kernel.GetFileInformationByHandle
    info_fn.argtypes = (wintypes.HANDLE, ctypes.POINTER(ByHandleFileInformation))
    info_fn.restype = wintypes.BOOL
    close = kernel.CloseHandle
    close.argtypes = (wintypes.HANDLE,)
    close.restype = wintypes.BOOL

    handle = create(
        str(path), 0x80000000, 0x00000001 | 0x00000002 | 0x00000004,
        None, 3, 0x00200000, None,
    )
    if handle is None or handle == ctypes.c_void_p(-1).value:
        raise OSError("safe_open_failed")
    try:
        info = ByHandleFileInformation()
        if not info_fn(handle, ctypes.byref(info)):
            raise OSError("safe_info_unavailable")
        # The handle refers to the reparse point itself, never its target.
        if info.dwFileAttributes & 0x00000400:
            raise OSError("symlink_or_reparse_point_denied")
        # msvcrt takes ownership of the HANDLE on successful conversion.
        return msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except Exception:
        close(handle)
        raise
