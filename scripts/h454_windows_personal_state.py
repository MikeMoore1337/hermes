"""Persist a newly paired personal Windows bearer with current-user DPAPI.

Local setup code only; it does not issue a pairing code or launch the worker.
An existing state directory is never replaced or cleaned up automatically.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import hashlib
import os
from pathlib import Path
import time
from typing import Callable

from device_fabric import native_private_tls as private_tls
from device_fabric import windows_personal_session as personal
from device_fabric.native_brc_enrollment import Paired
from scripts.h454_windows_personal_worker import current_sid, load_ca


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p),
                ("bInheritHandle", wintypes.BOOL)]


def _create_private_directory(path: Path, sid: str) -> None:
    """Create with a protected owner/SYSTEM/Administrators DACL atomically."""
    if os.name != "nt" or personal.SID.fullmatch(sid) is None:
        raise personal.PersonalSessionDenied("personal_windows_denied")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.DWORD)]
    kernel.CreateDirectoryW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(_SecurityAttributes)]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    descriptor = ctypes.c_void_p()
    sddl = f"O:{sid}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{sid})"
    try:
        if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, ctypes.byref(descriptor), None):
            raise ValueError()
        attrs = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), descriptor, False)
        if not kernel.CreateDirectoryW(str(path), ctypes.byref(attrs)):
            raise ValueError()
    except Exception:
        raise personal.PersonalSessionDenied("personal_windows_denied") from None
    finally:
        if descriptor.value:
            kernel.LocalFree(descriptor)


def persist_new(paired: Paired, *, release_sha: str, ca: bytes,
                sid_provider: Callable[[], str] = current_sid,
                directory_create: Callable[[Path, str], None] = _create_private_directory,
                now: Callable[[], float] = time.time) -> None:
    """Check owner binding, seal, then exclusively write one protected file."""
    try:
        base = os.environ.get("LOCALAPPDATA", "")
        if os.name != "nt" or not os.path.isabs(base):
            raise ValueError()
        parent = Path(base)
        if parent.lstat().st_file_attributes & 0x400:
            raise ValueError()
        sid = sid_provider()
        if type(sid) is not str or personal.SID.fullmatch(sid) is None:
            raise ValueError()
        root = parent / "HermesCommanderPersonal"
        if root.exists():
            raise ValueError()
        if type(ca) is not bytes or load_ca(hashlib.sha256(ca).hexdigest()) != ca:
            raise ValueError()
        relay = private_tls.PrivateRelay("windows", release_sha, private_tls.WINDOWS_LOOPBACK, ca)
        if not private_tls.current_bearer(relay, target="windows", device_id=paired.device_id,
                                          bearer=paired.token):
            raise ValueError()
        raw = personal.prepare_config(paired, owner_sid=sid, release_sha=release_sha,
                                      ca=ca, now=int(now()))
        # Create-new stops on collisions, including a partially completed setup.
        directory_create(root, sid)
        fd = os.open(root / "device.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_BINARY, 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        except Exception:
            # Leave an interrupted private state for inspection; never retry it.
            raise
    except Exception:
        raise personal.PersonalSessionDenied("personal_windows_denied") from None
