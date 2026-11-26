"""Experimental, non-interactive Windows BFS process primitive.

This does not verify project paths, install a worker, or establish a complete
privacy boundary. In particular, a permitted hard-link path can address an
outside file. Callers must not use this on original projects until that and
project scope have been addressed independently.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import ntpath
import os
from pathlib import Path
import struct
import tempfile
import uuid

from device_fabric.windows_appcontainer_terminal import _ProcessInfo, _Startup, _apis
from device_fabric.windows_personal_job import _Extended


class BfsProcessDenied(ValueError):
    """Sanitized failure, never containing a command or filesystem path."""


def build_spec(paths: list[str]) -> bytes:
    """Encode the pinned, minimal SBOX 0.1.0 table without external libraries."""
    if type(paths) is not list or not 1 <= len(paths) <= 8:
        raise BfsProcessDenied("bfs_process_denied")
    seen = set()
    for path in paths:
        if (type(path) is not str or not 3 <= len(path) <= 2048 or "\0" in path
            or not ntpath.isabs(path) or ntpath.normpath(path) != path):
            raise BfsProcessDenied("bfs_process_denied")
        drive, tail = ntpath.splitdrive(path)
        if (len(drive) != 2 or not drive[0].isascii() or not drive[0].isalpha()
            or drive[1] != ":" or tail in ("", "\\") or path.casefold() in seen
            or any(ch in tail for ch in ':*?"<>|') or any(ord(ch) < 32 for ch in path)):
            raise BfsProcessDenied("bfs_process_denied")
        try:
            path.encode("utf-8")
        except UnicodeEncodeError:
            raise BfsProcessDenied("bfs_process_denied") from None
        seen.add(path.casefold())
    # Field slots and widths from Microsoft/mxc's BaseContainerSpecification.fbs
    # at c47ab4f1db7215ca7305ba32a0996ea243806b76. Omitted fields use defaults.
    data = bytearray(56)
    struct.pack_into("<I4s", data, 0, 36, b"SBOX")
    struct.pack_into("<HH", data, 8, 28, 20)
    struct.pack_into("<H", data, 12, 4)  # version
    struct.pack_into("<H", data, 14, 8)  # app_container
    struct.pack_into("<H", data, 26, 12)  # fs_read_write
    struct.pack_into("<i", data, 36, 28)
    data[44] = 1

    def string(value: str) -> int:
        while len(data) % 4:
            data.append(0)
        offset = len(data)
        encoded = value.encode("utf-8")
        data.extend(struct.pack("<I", len(encoded)) + encoded + b"\0")
        return offset

    version = string("0.1.0")
    struct.pack_into("<I", data, 40, version - 40)
    while len(data) % 4:
        data.append(0)
    vector = len(data)
    data.extend(struct.pack("<I", len(paths)) + bytes(4 * len(paths)))
    for index, path in enumerate(paths):
        value = string(path)
        slot = vector + 4 + index * 4
        struct.pack_into("<I", data, slot, value - slot)
    struct.pack_into("<I", data, 48, vector - 48)
    return bytes(data)


class BfsProcess:
    """Launch one hidden command under a disposable synthetic TEMP fixture."""

    def __init__(self, paths: list[str], cwd: str, command: str):
        self._kernel = self._profile_api = None
        self._process = self._job = None
        self._identity = None
        self.profile_deleted = None
        info = _ProcessInfo()
        sid = ctypes.c_void_p()
        try:
            data = build_spec(paths)
            if (os.name != "nt" or type(cwd) is not str or cwd not in paths
                or type(command) is not str or not 0 < len(command) <= 4096 or "\0" in command):
                raise ValueError()
            temp = Path(tempfile.gettempdir()).resolve(strict=True)
            for path in paths:
                resolved = Path(path).resolve(strict=True)
                relative = resolved.relative_to(temp)
                if (not resolved.is_dir() or not relative.parts
                    or not relative.parts[0].startswith("h454-bfs-synthetic-")):
                    raise ValueError()
            kernel, adv = _apis()
            userenv = ctypes.WinDLL("userenv", use_last_error=True)
            model = ctypes.WinDLL("processmodel", use_last_error=True, winmode=0x800)
            userenv.DeriveAppContainerSidFromAppContainerName.argtypes = [
                wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
            userenv.DeleteAppContainerProfile.argtypes = [wintypes.LPCWSTR]
            adv.FreeSid.argtypes = [ctypes.c_void_p]
            launch = model.Experimental_CreateProcessInSandbox
            launch.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p,
                ctypes.c_void_p, wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p,
                wintypes.LPCWSTR, ctypes.POINTER(_Startup), wintypes.LPCWSTR,
                ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_ProcessInfo)]
            launch.restype = wintypes.BOOL
            self._kernel, self._profile_api = kernel, userenv
            self._identity = "HermesBfs" + uuid.uuid4().hex
            self._job = kernel.CreateJobObjectW(None, None)
            if not self._job:
                raise ValueError()
            limits = _Extended()
            limits.basic.flags = 0x2000  # kill-on-close
            if not kernel.SetInformationJobObject(self._job, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
                raise ValueError()
            root = os.environ.get("SYSTEMROOT", "")
            if not os.path.isabs(root):
                raise ValueError()
            shell = os.path.join(root, "System32", "cmd.exe")
            line = ctypes.create_unicode_buffer('"' + shell + '" /d /s /c "' + command + '"')
            names = ("SYSTEMROOT", "WINDIR", "USERPROFILE", "LOCALAPPDATA", "TEMP", "TMP")
            environment = ctypes.create_unicode_buffer("\0".join(
                name + "=" + os.environ[name] for name in names if name in os.environ) + "\0\0")
            startup = _Startup()
            startup.cb = ctypes.sizeof(startup)
            startup.flags = 1  # SW_HIDE; never create a visible console
            blob = ctypes.create_string_buffer(data)
            launched = launch(shell, line, None, None, False, 0x08000404, environment, cwd,
                              ctypes.byref(startup), self._identity, blob, len(data), ctypes.byref(info))
            self._process = info.process or None
            if not launched or not info.process or not info.thread:
                raise ValueError()
            if (not kernel.AssignProcessToJobObject(self._job, info.process)
                or userenv.DeriveAppContainerSidFromAppContainerName(self._identity, ctypes.byref(sid)) != 0):
                raise ValueError()
            token = wintypes.HANDLE()
            if not adv.OpenProcessToken(info.process, 0x8, ctypes.byref(token)):
                raise ValueError()
            try:
                container, size = wintypes.DWORD(), wintypes.DWORD()
                if (not adv.GetTokenInformation(token, 29, ctypes.byref(container), ctypes.sizeof(container),
                                                ctypes.byref(size)) or container.value != 1):
                    raise ValueError()
                adv.GetTokenInformation(token, 31, None, 0, ctypes.byref(size))
                if not 0 < size.value <= 65536:
                    raise ValueError()
                raw = ctypes.create_string_buffer(size.value)
                if not adv.GetTokenInformation(token, 31, raw, size, ctypes.byref(size)):
                    raise ValueError()
                actual = ctypes.cast(raw, ctypes.POINTER(ctypes.c_void_p)).contents.value
                if not actual or not adv.EqualSid(sid, actual):
                    raise ValueError()
            finally:
                kernel.CloseHandle(token)
            if kernel.ResumeThread(info.thread) != 1:
                raise ValueError()
        except Exception:
            self.close()
            raise BfsProcessDenied("bfs_process_denied") from None
        finally:
            if sid:
                adv.FreeSid(sid)
            if info.thread and self._kernel:
                self._kernel.CloseHandle(info.thread)

    def wait(self, timeout_ms: int = 10000) -> int:
        if type(timeout_ms) is not int or not 0 <= timeout_ms <= 30000 or not self._process:
            raise BfsProcessDenied("bfs_process_denied")
        if self._kernel.WaitForSingleObject(self._process, timeout_ms) != 0:
            raise BfsProcessDenied("bfs_process_denied")
        result = wintypes.DWORD()
        if not self._kernel.GetExitCodeProcess(self._process, ctypes.byref(result)):
            raise BfsProcessDenied("bfs_process_denied")
        return result.value

    def close(self) -> None:
        if self._kernel:
            if self._job:
                self._kernel.CloseHandle(self._job)
                self._job = None
            if self._process:
                if self._kernel.WaitForSingleObject(self._process, 0) != 0:
                    self._kernel.TerminateProcess(self._process, 1)
                    self._kernel.WaitForSingleObject(self._process, 5000)
                self._kernel.CloseHandle(self._process)
                self._process = None
        if self._identity and self._profile_api:
            self.profile_deleted = self._profile_api.DeleteAppContainerProfile(self._identity) == 0
            self._identity = None
