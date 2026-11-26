"""Check Windows BFS on disposable files, including its hardlink limitation."""
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from device_fabric.windows_personal_bfs_process import BfsProcess  # noqa: E402

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
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_void_p)]
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


with tempfile.TemporaryDirectory(prefix="h454-bfs-synthetic-") as tmp:
    root = Path(tmp)
    project, private = root / "project", root / "private"
    project.mkdir()
    private.mkdir()
    original = project / "existing.txt"
    outside = private / "outside.txt"
    original.write_text("original", encoding="ascii")
    outside.write_text("private-synthetic", encoding="ascii")
    alias = project / "external-hardlink.txt"
    os.link(outside, alias)
    before = {(name, info): security(path, info) for name, path in
              (("project", project), ("original", original), ("outside", outside)) for info in (4, 16)}
    created = project / "new.txt"
    denied = private / "denied.txt"
    command = ('(echo synthetic>"' + str(created) + '") || exit /b 10 & '
        + '(echo updated>"' + str(original) + '") || exit /b 11 & '
        + '(echo bad>"' + str(denied) + '") && exit /b 12 & '
        + '(echo alias>"' + str(alias) + '") && exit /b 13 & exit /b 0')
    process = BfsProcess([str(project)], str(project), command)
    try:
        exit_code = process.wait()
    finally:
        process.close()
    result = {"created": created.is_file(), "existing_updated": original.read_text().strip() == "updated",
        "outside_path_denied": not denied.exists(), "hardlink_alias_writable": outside.read_text().strip() == "alias",
        "descriptors_unchanged": all(before[(name, info)] == security(path, info) for name, path in
            (("project", project), ("original", original), ("outside", outside)) for info in (4, 16)),
        "profile_deleted": process.profile_deleted is True, "exit_code": exit_code}
    running = BfsProcess([str(project)], str(project), "for /L %i in (1,0,2) do @rem")
    duplicate = wintypes.HANDLE()
    own_process = kernel.GetCurrentProcess()
    try:
        if not kernel.DuplicateHandle(own_process, running._process, own_process,
                                      ctypes.byref(duplicate), 0, False, 2):
            raise OSError(ctypes.get_last_error(), "SYNTHETIC_PROCESS_HANDLE_FAILED")
        result["job_process_was_running"] = kernel.WaitForSingleObject(duplicate, 0) == 258
        running.close()
        result["job_process_stopped"] = kernel.WaitForSingleObject(duplicate, 5000) == 0
        result["second_profile_deleted"] = running.profile_deleted is True
    finally:
        running.close()
        if duplicate:
            kernel.CloseHandle(duplicate)
    alias.unlink()
    if (not all(result[name] for name in ("created", "existing_updated", "outside_path_denied",
                                          "descriptors_unchanged", "profile_deleted",
                                          "job_process_was_running", "job_process_stopped",
                                          "second_profile_deleted"))
        or exit_code not in (0, 13) or result["hardlink_alias_writable"] != (exit_code == 13)):
        raise SystemExit("BFS_SYNTHETIC_FAILED " + json.dumps(result))
    result["status"] = ("HARDLINK_BOUNDARY_NOT_ENFORCED" if result["hardlink_alias_writable"]
                        else "SYNTHETIC_BOUNDARY_ONLY")
    print(json.dumps(result))
