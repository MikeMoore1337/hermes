"""Low-level hidden AppContainer cmd session for a trusted local broker.

The caller owns profile provisioning, directory authorization and ACLs. This
module does not select projects, create profiles, pair devices or expose an
MCP tool. A session must never receive a relay bearer or inherit host handles.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import os
import subprocess
import threading

from device_fabric.windows_personal_job import _Extended

MAX_WRITE = 4096
MAX_READ = 65536


class TerminalDenied(ValueError):
    """Constant error without commands, output or operating-system paths."""


class _Startup(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("reserved", wintypes.LPWSTR),
        ("desktop", wintypes.LPWSTR), ("title", wintypes.LPWSTR),
        ("x", wintypes.DWORD), ("y", wintypes.DWORD), ("x_size", wintypes.DWORD),
        ("y_size", wintypes.DWORD), ("x_count", wintypes.DWORD), ("y_count", wintypes.DWORD),
        ("fill", wintypes.DWORD), ("flags", wintypes.DWORD), ("show", wintypes.WORD),
        ("reserved2_len", wintypes.WORD), ("reserved2", ctypes.c_void_p),
        ("stdin", wintypes.HANDLE), ("stdout", wintypes.HANDLE), ("stderr", wintypes.HANDLE)]


class _StartupEx(ctypes.Structure):
    _fields_ = [("startup", _Startup), ("attributes", ctypes.c_void_p)]


class _Capabilities(ctypes.Structure):
    _fields_ = [("sid", ctypes.c_void_p), ("capabilities", ctypes.c_void_p),
                ("count", wintypes.DWORD), ("reserved", wintypes.DWORD)]


class _ProcessInfo(ctypes.Structure):
    _fields_ = [("process", wintypes.HANDLE), ("thread", wintypes.HANDLE),
                ("pid", wintypes.DWORD), ("tid", wintypes.DWORD)]


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [("length", wintypes.DWORD), ("descriptor", ctypes.c_void_p),
                ("inherit", wintypes.BOOL)]


class _Accounting(ctypes.Structure):
    _fields_ = [("user_time", ctypes.c_int64), ("kernel_time", ctypes.c_int64),
                ("period_user", ctypes.c_int64), ("period_kernel", ctypes.c_int64),
                ("faults", wintypes.DWORD), ("total", wintypes.DWORD),
                ("active", wintypes.DWORD), ("terminated", wintypes.DWORD)]


def _apis():
    if os.name != "nt":
        raise TerminalDenied("appcontainer_terminal_denied")
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    a = ctypes.WinDLL("advapi32", use_last_error=True)
    k.CreatePipe.argtypes = [ctypes.POINTER(wintypes.HANDLE), ctypes.POINTER(wintypes.HANDLE),
                             ctypes.POINTER(_SecurityAttributes), wintypes.DWORD]
    k.SetHandleInformation.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD]
    k.InitializeProcThreadAttributeList.argtypes = [ctypes.c_void_p, wintypes.DWORD,
                                                     wintypes.DWORD, ctypes.POINTER(ctypes.c_size_t)]
    k.UpdateProcThreadAttribute.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.c_size_t,
        ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p]
    k.DeleteProcThreadAttributeList.argtypes = [ctypes.c_void_p]
    k.CreateProcessW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p,
        wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR,
        ctypes.POINTER(_Startup), ctypes.POINTER(_ProcessInfo)]
    k.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    k.CreateJobObjectW.restype = wintypes.HANDLE
    k.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    k.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    k.QueryInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                             wintypes.DWORD, ctypes.c_void_p]
    k.ResumeThread.argtypes = [wintypes.HANDLE]
    k.ResumeThread.restype = wintypes.DWORD
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    k.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    k.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    k.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    k.WriteFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                            ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    k.ReadFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                           ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    k.PeekNamedPipe.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                               ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    a.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    a.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                      wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    a.EqualSid.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    return k, a


class AppContainerTerminal:
    """One broker-owned shell and its job; no policy or installation implied."""

    def __init__(self, appcontainer_sid: int, working_directory: str, *, command: str | None = None):
        self._k = None
        self._process = self._input = self._output = self._job = None
        self.pid = 0
        self._write_lock = threading.Lock()
        self._closed = False
        handles = []
        info = _ProcessInfo()
        attributes = None
        initialized = False
        try:
            if (type(appcontainer_sid) is not int or appcontainer_sid <= 0
                or type(working_directory) is not str or not os.path.isabs(working_directory)
                or len(working_directory) > 2048 or "\x00" in working_directory
                or (command is not None and (type(command) is not str or not 0 < len(command) <= 4096
                                             or "\x00" in command))):
                raise ValueError()
            k, a = _apis()
            self._k = k
            job = k.CreateJobObjectW(None, None)
            if not job:
                raise ValueError()
            self._job = job
            limits = _Extended()
            limits.basic.flags = 0x2000  # kill all job members on last handle close
            if not k.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
                raise ValueError()
            read_in, write_in, read_out, write_out = (wintypes.HANDLE() for _ in range(4))
            security = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), None, True)
            if not k.CreatePipe(ctypes.byref(read_in), ctypes.byref(write_in), ctypes.byref(security), 0):
                raise ValueError()
            handles.extend((read_in, write_in))
            if not k.CreatePipe(ctypes.byref(read_out), ctypes.byref(write_out), ctypes.byref(security), 0):
                raise ValueError()
            handles.extend((read_out, write_out))
            if not k.SetHandleInformation(write_in, 1, 0) or not k.SetHandleInformation(read_out, 1, 0):
                raise ValueError()
            size = ctypes.c_size_t()
            k.InitializeProcThreadAttributeList(None, 2, 0, ctypes.byref(size))
            if not 0 < size.value <= 65536:
                raise ValueError()
            attributes = ctypes.create_string_buffer(size.value)
            if not k.InitializeProcThreadAttributeList(attributes, 2, 0, ctypes.byref(size)):
                raise ValueError()
            initialized = True
            cap = _Capabilities(appcontainer_sid, None, 0, 0)
            inherited = (wintypes.HANDLE * 2)(read_in, write_out)
            if (not k.UpdateProcThreadAttribute(attributes, 0, 0x00020009, ctypes.byref(cap),
                    ctypes.sizeof(cap), None, None)
                or not k.UpdateProcThreadAttribute(attributes, 0, 0x00020002, inherited,
                    ctypes.sizeof(inherited), None, None)):
                raise ValueError()
            startup = _StartupEx()
            startup.startup.cb = ctypes.sizeof(startup)
            startup.startup.flags = 0x101  # hidden, use only the supplied stdio handles
            startup.startup.stdin, startup.startup.stdout, startup.startup.stderr = read_in, write_out, write_out
            startup.attributes = ctypes.cast(attributes, ctypes.c_void_p)
            system_root = os.environ.get("SYSTEMROOT", "")
            if not os.path.isabs(system_root):
                raise ValueError()
            shell = os.path.join(system_root, "System32", "cmd.exe")
            # cmd.exe parses /S /C itself; C-runtime quote escaping from
            # list2cmdline would change embedded quoted file paths.
            arguments = (subprocess.list2cmdline([shell, "/d", "/q"]) if command is None else
                         '"' + shell + '" /d /s /c "' + command + '"')
            command_line = ctypes.create_unicode_buffer(arguments)
            names = ("SYSTEMROOT", "WINDIR", "USERPROFILE", "LOCALAPPDATA", "TEMP", "TMP")
            environment = ctypes.create_unicode_buffer("\0".join(
                name + "=" + os.environ[name] for name in names if name in os.environ) + "\0\0")
            # CREATE_SUSPENDED ensures the shell cannot run before assignment
            # to the dedicated kill-on-close job and token verification.
            flags = 0x08000000 | 0x00080000 | 0x00000400 | 0x00000004
            if not k.CreateProcessW(shell, command_line, None, None, True, flags, environment,
                                    working_directory, ctypes.byref(startup.startup), ctypes.byref(info)):
                raise ValueError()
            self._process = info.process
            if not k.AssignProcessToJobObject(job, info.process):
                raise ValueError()
            token = wintypes.HANDLE()
            if not a.OpenProcessToken(info.process, 0x0008, ctypes.byref(token)):
                raise ValueError()
            try:
                is_container, returned = wintypes.DWORD(), wintypes.DWORD()
                if (not a.GetTokenInformation(token, 29, ctypes.byref(is_container),
                                              ctypes.sizeof(is_container), ctypes.byref(returned))
                    or is_container.value != 1):
                    raise ValueError()
                needed = wintypes.DWORD()
                a.GetTokenInformation(token, 31, None, 0, ctypes.byref(needed))
                if not 0 < needed.value <= 65536:
                    raise ValueError()
                raw = ctypes.create_string_buffer(needed.value)
                if not a.GetTokenInformation(token, 31, raw, needed, ctypes.byref(needed)):
                    raise ValueError()
                actual_sid = ctypes.cast(raw, ctypes.POINTER(ctypes.c_void_p)).contents.value
                if not actual_sid or not a.EqualSid(appcontainer_sid, actual_sid):
                    raise ValueError()
            finally:
                k.CloseHandle(token)
            if k.ResumeThread(info.thread) == 0xFFFFFFFF:
                raise ValueError()
            if info.pid <= 0:
                raise ValueError()
            self.pid = int(info.pid)
            self._input, self._output = write_in, read_out
            handles.remove(write_in)
            handles.remove(read_out)
        except Exception:
            self.close()
            raise TerminalDenied("appcontainer_terminal_denied") from None
        finally:
            if self._k:
                if info.thread:
                    self._k.CloseHandle(info.thread)
                for handle in handles:
                    self._k.CloseHandle(handle)
                if initialized:
                    self._k.DeleteProcThreadAttributeList(attributes)

    def write(self, data: bytes, *, timeout: float = 5.0) -> None:
        if (type(data) is not bytes or not 0 < len(data) <= MAX_WRITE
            or type(timeout) not in (int, float) or not 0 < timeout <= 10):
            raise TerminalDenied("appcontainer_terminal_denied")
        with self._write_lock:
            if self._closed:
                raise TerminalDenied("appcontainer_terminal_denied")
            result = []
            def send():
                amount = wintypes.DWORD()
                buf = ctypes.create_string_buffer(data)
                result.append(bool(self._k.WriteFile(self._input, buf, len(data), ctypes.byref(amount), None))
                              and amount.value == len(data))
            thread = threading.Thread(target=send, daemon=True)
            thread.start()
            thread.join(timeout)
            if thread.is_alive() or result != [True]:
                self.close()
                raise TerminalDenied("appcontainer_terminal_denied")

    def read(self) -> bytes:
        if self._closed:
            raise TerminalDenied("appcontainer_terminal_denied")
        available = wintypes.DWORD()
        if not self._k.PeekNamedPipe(self._output, None, 0, None, ctypes.byref(available), None):
            if ctypes.get_last_error() in (109, 232) or self.poll() is not None:
                return b""
            raise TerminalDenied("appcontainer_terminal_denied")
        count = min(available.value, MAX_READ)
        if not count:
            return b""
        buf, actual = ctypes.create_string_buffer(count), wintypes.DWORD()
        if not self._k.ReadFile(self._output, buf, count, ctypes.byref(actual), None):
            raise TerminalDenied("appcontainer_terminal_denied")
        return buf.raw[:actual.value]

    def poll(self) -> int | None:
        if self._closed:
            raise TerminalDenied("appcontainer_terminal_denied")
        state = self._k.WaitForSingleObject(self._process, 0)
        if state == 258:
            return None
        if state != 0:
            raise TerminalDenied("appcontainer_terminal_denied")
        accounting = _Accounting()
        if not self._k.QueryInformationJobObject(self._job, 1, ctypes.byref(accounting),
                                                 ctypes.sizeof(accounting), None):
            raise TerminalDenied("appcontainer_terminal_denied")
        if accounting.active:
            return None
        code = wintypes.DWORD()
        if not self._k.GetExitCodeProcess(self._process, ctypes.byref(code)):
            raise TerminalDenied("appcontainer_terminal_denied")
        return code.value

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._k:
            # Closing this dedicated job terminates the shell and descendants.
            if self._job:
                self._k.CloseHandle(self._job)
                self._job = None
            if self._process:
                self._k.TerminateProcess(self._process, 1)
                self._k.WaitForSingleObject(self._process, 5000)
            for handle in (self._input, self._output, self._process):
                if handle:
                    self._k.CloseHandle(handle)
            self._input = self._output = self._process = None
