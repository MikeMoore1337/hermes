"""Exercise native PSEC on disposable paths and report the hardlink boundary."""
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from device_fabric.windows_personal_psec_terminal import SyntheticPsecTerminal  # noqa: E402
from device_fabric.windows_personal_terminal_sessions import PersonalTerminalSessions  # noqa: E402

if os.name != "nt":
    raise SystemExit("WINDOWS_REQUIRED")

kernel = ctypes.WinDLL("kernel32", use_last_error=True)
adv = ctypes.WinDLL("advapi32", use_last_error=True)
kernel.LocalFree.argtypes = [ctypes.c_void_p]
kernel.GetCurrentProcess.restype = wintypes.HANDLE
kernel.DuplicateHandle.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.HANDLE,
    ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel.CloseHandle.argtypes = [wintypes.HANDLE]
adv.GetNamedSecurityInfoW.argtypes = [wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD,
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
adv.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [ctypes.c_void_p,
    wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR), ctypes.c_void_p]


def security(path, info):
    descriptor, text = ctypes.c_void_p(), wintypes.LPWSTR()
    status = adv.GetNamedSecurityInfoW(str(path), 1, info, None, None, None, None,
                                       ctypes.byref(descriptor))
    if status:
        raise OSError(status, "SYNTHETIC_SECURITY_READ_FAILED")
    try:
        if not adv.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor, 1, info, ctypes.byref(text), None):
            raise OSError(ctypes.get_last_error(), "SYNTHETIC_SECURITY_FORMAT_FAILED")
        return text.value
    finally:
        if text:
            kernel.LocalFree(ctypes.cast(text, ctypes.c_void_p))
        if descriptor:
            kernel.LocalFree(descriptor)


def wait_output(terminal):
    output = bytearray()
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        output.extend(terminal.read())
        if terminal.poll() is not None:
            output.extend(terminal.read())
            return terminal.poll(), bytes(output)
        time.sleep(0.02)
    raise RuntimeError("SYNTHETIC_TIMEOUT")


with tempfile.TemporaryDirectory(prefix="h454-psec-synthetic-") as tmp:
    root = Path(tmp)
    project, private = root / "project", root / "private"
    project.mkdir()
    private.mkdir()
    original, outside = project / "existing.txt", private / "outside.txt"
    original.write_text("original", encoding="ascii")
    outside.write_text("private-synthetic", encoding="ascii")
    alias = project / "external-hardlink.txt"
    os.link(outside, alias)
    before = {(name, info): security(path, info) for name, path in
              (("project", project), ("original", original), ("outside", outside)) for info in (4, 16)}
    result = {}
    interactive = SyntheticPsecTerminal(str(project), command="set /p H454=H454_READY & set H454")
    try:
        interactive.write(b"synthetic\r\n")
        code, output = wait_output(interactive)
        result["interactive"] = code == 0 and b"H454=synthetic" in output
    finally:
        interactive.close()
    result["policy_closed"] = interactive._environment is None
    manager = PersonalTerminalSessions(1, str(project),
        factory=lambda _sid, cwd, command: SyntheticPsecTerminal(cwd, command=command))
    try:
        started = manager.dispatch("start_process", {
            "command": "set /p H454=H454_MANAGER & set H454", "timeout_ms": 3000})
        match = re.search(r"Process ([0-9]+) ", started["content"][0]["text"])
        if started["isError"] or not match:
            raise RuntimeError("SYNTHETIC_MANAGER_START_FAILED")
        reply = manager.dispatch("interact_with_process", {
            "pid": int(match.group(1)), "input": "synthetic", "timeout_ms": 3000})
        result["manager_interactive"] = not reply["isError"] and "H454=synthetic" in reply["content"][0]["text"]
    finally:
        manager.close()
    created, denied = project / "new.txt", private / "denied.txt"
    command = ('(echo synthetic>"' + str(created) + '") || exit /b 10 & '
        + '(echo updated>"' + str(original) + '") || exit /b 11 & '
        + '(echo bad>"' + str(denied) + '") && exit /b 12 & '
        + '(echo alias>"' + str(alias) + '") && exit /b 13 & exit /b 0')
    process = SyntheticPsecTerminal(str(project), command=command)
    try:
        exit_code, _ = wait_output(process)
    finally:
        process.close()
    result.update({"created": created.is_file(), "existing_updated": original.read_text().strip() == "updated",
        "outside_path_denied": not denied.exists(), "hardlink_alias_writable": outside.read_text().strip() == "alias",
        "descriptors_unchanged": all(before[(name, info)] == security(path, info) for name, path in
            (("project", project), ("original", original), ("outside", outside)) for info in (4, 16)),
        "exit_code": exit_code})
    running = SyntheticPsecTerminal(str(project), command="for /L %i in (1,0,2) do @rem")
    duplicate = wintypes.HANDLE()
    own_process = kernel.GetCurrentProcess()
    try:
        if not kernel.DuplicateHandle(own_process, running._process, own_process,
                                      ctypes.byref(duplicate), 0, False, 2):
            raise OSError(ctypes.get_last_error(), "SYNTHETIC_PROCESS_HANDLE_FAILED")
        result["job_process_was_running"] = kernel.WaitForSingleObject(duplicate, 0) == 258
        running.close()
        result["job_process_stopped"] = kernel.WaitForSingleObject(duplicate, 5000) == 0
    finally:
        running.close()
        if duplicate:
            kernel.CloseHandle(duplicate)
    alias.unlink()
    if (not all(result[name] for name in ("interactive", "manager_interactive", "policy_closed", "created", "existing_updated",
        "outside_path_denied", "descriptors_unchanged", "job_process_was_running", "job_process_stopped"))
        or exit_code not in (0, 13) or result["hardlink_alias_writable"] != (exit_code == 13)):
        raise SystemExit("PSEC_SYNTHETIC_FAILED " + json.dumps(result))
    result["status"] = ("HARDLINK_BOUNDARY_NOT_ENFORCED" if result["hardlink_alias_writable"]
                        else "SYNTHETIC_BOUNDARY_ONLY")
    print(json.dumps(result))
