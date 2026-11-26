"""Synthetic-only interactive PSEC terminal; not an installed device.

PSEC path policy permits an allowed hardlink to reach its outside alias.
Until project-boundary handling exists, this module refuses real project paths.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import ntpath
import os
from pathlib import Path
import struct
import tempfile
import threading

from device_fabric.windows_appcontainer_terminal import (
    AppContainerTerminal, TerminalDenied, _ProcessInfo, _SecurityAttributes,
    _StartupEx, _apis,
)
from device_fabric.windows_personal_job import _Extended


def build_spec(root: str) -> bytes:
    """Encode PSEC schema 1.0 with a single writable directory."""
    if (type(root) is not str or not 3 <= len(root) <= 2048 or "\0" in root
        or not ntpath.isabs(root) or ntpath.normpath(root) != root):
        raise TerminalDenied("psec_terminal_denied")
    drive, tail = ntpath.splitdrive(root)
    if (len(drive) != 2 or not drive[0].isascii() or not drive[0].isalpha() or drive[1] != ":"
        or tail in ("", "\\") or any(ch in tail for ch in ':*?"<>|')
        or any(ord(ch) < 32 for ch in root)):
        raise TerminalDenied("psec_terminal_denied")
    try:
        encoded = root.encode("utf-8")
    except UnicodeEncodeError:
        raise TerminalDenied("psec_terminal_denied") from None
    # Microsoft/mxc ProcessSecurityEnvironment.fbs at
    # 383933e9dd4a6b068670767f5926adbdba2de6c9, version 1.0 subset.
    data = bytearray(44)
    struct.pack_into("<I4s", data, 0, 32, b"PSEC")
    struct.pack_into("<HH", data, 8, 22, 12)
    struct.pack_into("<H", data, 12, 4)  # version struct
    struct.pack_into("<H", data, 20, 8)  # fs_read_write
    struct.pack_into("<iHH", data, 32, 24, 1, 0)
    vector = len(data)
    data.extend(struct.pack("<II", 1, 0))
    path_offset = len(data)
    data.extend(struct.pack("<I", len(encoded)) + encoded + b"\0")
    struct.pack_into("<I", data, vector + 4, path_offset - (vector + 4))
    struct.pack_into("<I", data, 40, vector - 40)
    return bytes(data)


class SyntheticPsecTerminal(AppContainerTerminal):
    """A hidden process with inherited stdio and a kill-on-close job."""

    def __init__(self, root: str, *, command: str | None = None):
        self._k = self._model = self._environment = None
        self._process = self._input = self._output = self._job = None
        self.pid = 0
        self._write_lock = threading.Lock()
        self._closed = False
        handles = []
        info = _ProcessInfo()
        attributes = None
        initialized = False
        try:
            data = build_spec(root)
            if (os.name != "nt" or (command is not None and (type(command) is not str
                or not 0 < len(command) <= 4096 or "\0" in command))):
                raise ValueError()
            resolved = Path(root).resolve(strict=True)
            relative = resolved.relative_to(Path(tempfile.gettempdir()).resolve(strict=True))
            if (not resolved.is_dir() or not relative.parts
                or not relative.parts[0].startswith("h454-psec-synthetic-")):
                raise ValueError()
            kernel, adv = _apis()
            model = ctypes.WinDLL("processmodel", use_last_error=True, winmode=0x800)
            create = model.CreateProcessSecurityEnvironment
            create.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                               ctypes.POINTER(wintypes.HANDLE)]
            create.restype = ctypes.c_long
            model.CloseProcessSecurityEnvironment.argtypes = [wintypes.HANDLE]
            model.CloseProcessSecurityEnvironment.restype = None
            self._k, self._model = kernel, model
            security_environment = wintypes.HANDLE()
            raw_spec = ctypes.create_string_buffer(data)
            status = create(raw_spec, len(data), 0, ctypes.byref(security_environment))
            self._environment = security_environment if security_environment else None
            if status != 0 or not security_environment:
                raise ValueError()
            self._job = kernel.CreateJobObjectW(None, None)
            if not self._job:
                raise ValueError()
            limits = _Extended()
            limits.basic.flags = 0x2000
            if not kernel.SetInformationJobObject(self._job, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
                raise ValueError()
            read_in, write_in, read_out, write_out = (wintypes.HANDLE() for _ in range(4))
            pipe_security = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), None, True)
            if not kernel.CreatePipe(ctypes.byref(read_in), ctypes.byref(write_in), ctypes.byref(pipe_security), 0):
                raise ValueError()
            handles.extend((read_in, write_in))
            if not kernel.CreatePipe(ctypes.byref(read_out), ctypes.byref(write_out), ctypes.byref(pipe_security), 0):
                raise ValueError()
            handles.extend((read_out, write_out))
            if not kernel.SetHandleInformation(write_in, 1, 0) or not kernel.SetHandleInformation(read_out, 1, 0):
                raise ValueError()
            size = ctypes.c_size_t()
            kernel.InitializeProcThreadAttributeList(None, 2, 0, ctypes.byref(size))
            if not 0 < size.value <= 65536:
                raise ValueError()
            attributes = ctypes.create_string_buffer(size.value)
            if not kernel.InitializeProcThreadAttributeList(attributes, 2, 0, ctypes.byref(size)):
                raise ValueError()
            initialized = True
            inherited = (wintypes.HANDLE * 2)(read_in, write_out)
            if (not kernel.UpdateProcThreadAttribute(attributes, 0, 0x00020023,
                    ctypes.byref(security_environment), ctypes.sizeof(security_environment), None, None)
                or not kernel.UpdateProcThreadAttribute(attributes, 0, 0x00020002,
                    inherited, ctypes.sizeof(inherited), None, None)):
                raise ValueError()
            startup = _StartupEx()
            startup.startup.cb = ctypes.sizeof(startup)
            startup.startup.flags = 0x101
            startup.startup.stdin, startup.startup.stdout, startup.startup.stderr = read_in, write_out, write_out
            startup.attributes = ctypes.cast(attributes, ctypes.c_void_p)
            system_root = os.environ.get("SYSTEMROOT", "")
            if not os.path.isabs(system_root):
                raise ValueError()
            shell = os.path.join(system_root, "System32", "cmd.exe")
            arguments = ('"' + shell + '" /d /q' if command is None else
                         '"' + shell + '" /d /s /c "' + command + '"')
            command_line = ctypes.create_unicode_buffer(arguments)
            names = ("SYSTEMROOT", "WINDIR", "USERPROFILE", "LOCALAPPDATA", "TEMP", "TMP")
            environment = ctypes.create_unicode_buffer("\0".join(
                name + "=" + os.environ[name] for name in names if name in os.environ) + "\0\0")
            launched = kernel.CreateProcessW(shell, command_line, None, None, True, 0x08080404,
                environment, root, ctypes.byref(startup.startup), ctypes.byref(info))
            self._process = info.process or None
            if not launched or not info.process or not info.thread or not kernel.AssignProcessToJobObject(self._job, info.process):
                raise ValueError()
            token = wintypes.HANDLE()
            if not adv.OpenProcessToken(info.process, 0x8, ctypes.byref(token)):
                raise ValueError()
            try:
                is_container, returned = wintypes.DWORD(), wintypes.DWORD()
                if (not adv.GetTokenInformation(token, 29, ctypes.byref(is_container),
                                                ctypes.sizeof(is_container), ctypes.byref(returned))
                    or is_container.value != 1):
                    raise ValueError()
            finally:
                kernel.CloseHandle(token)
            if kernel.ResumeThread(info.thread) != 1 or info.pid <= 0:
                raise ValueError()
            self.pid = int(info.pid)
            self._input, self._output = write_in, read_out
            handles.remove(write_in)
            handles.remove(read_out)
        except Exception:
            self.close()
            raise TerminalDenied("psec_terminal_denied") from None
        finally:
            if self._k:
                if info.thread:
                    self._k.CloseHandle(info.thread)
                for handle in handles:
                    self._k.CloseHandle(handle)
                if initialized:
                    self._k.DeleteProcThreadAttributeList(attributes)

    def close(self) -> None:
        super().close()
        if self._environment and self._model:
            self._model.CloseProcessSecurityEnvironment(self._environment)
            self._environment = None
