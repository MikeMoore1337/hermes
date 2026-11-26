"""Synthetic Windows AppContainer proof; never access real projects or vaults."""
import ctypes
from ctypes import wintypes
import csv
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import time
import uuid

kernel = ctypes.WinDLL("kernel32", use_last_error=True)
userenv = ctypes.WinDLL("userenv", use_last_error=True)
adv = ctypes.WinDLL("advapi32", use_last_error=True)


class STARTUPINFO(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("reserved", wintypes.LPWSTR),
        ("desktop", wintypes.LPWSTR), ("title", wintypes.LPWSTR),
        ("x", wintypes.DWORD), ("y", wintypes.DWORD), ("x_size", wintypes.DWORD),
        ("y_size", wintypes.DWORD), ("x_count", wintypes.DWORD), ("y_count", wintypes.DWORD),
        ("fill", wintypes.DWORD), ("flags", wintypes.DWORD), ("show", wintypes.WORD),
        ("reserved2_len", wintypes.WORD), ("reserved2", ctypes.c_void_p),
        ("stdin", wintypes.HANDLE), ("stdout", wintypes.HANDLE), ("stderr", wintypes.HANDLE)]


class STARTUPINFOEX(ctypes.Structure):
    _fields_ = [("startup", STARTUPINFO), ("attributes", ctypes.c_void_p)]


class SECURITY_CAPABILITIES(ctypes.Structure):
    _fields_ = [("sid", ctypes.c_void_p), ("capabilities", ctypes.c_void_p),
                ("count", wintypes.DWORD), ("reserved", wintypes.DWORD)]


class PROCESSINFO(ctypes.Structure):
    _fields_ = [("process", wintypes.HANDLE), ("thread", wintypes.HANDLE),
                ("pid", wintypes.DWORD), ("tid", wintypes.DWORD)]


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("length", wintypes.DWORD), ("descriptor", ctypes.c_void_p),
                ("inherit", wintypes.BOOL)]


userenv.DeriveAppContainerSidFromAppContainerName.argtypes = [wintypes.LPCWSTR,
                                                              ctypes.POINTER(ctypes.c_void_p)]
userenv.DeriveAppContainerSidFromAppContainerName.restype = ctypes.c_long
userenv.CreateAppContainerProfile.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR,
    wintypes.LPCWSTR, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
userenv.CreateAppContainerProfile.restype = ctypes.c_long
userenv.DeleteAppContainerProfile.argtypes = [wintypes.LPCWSTR]
userenv.DeleteAppContainerProfile.restype = ctypes.c_long
adv.FreeSid.argtypes = [ctypes.c_void_p]
adv.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
adv.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
adv.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
    wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
adv.DuplicateToken.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.POINTER(wintypes.HANDLE)]
adv.ImpersonateLoggedOnUser.argtypes = [wintypes.HANDLE]
adv.RevertToSelf.argtypes = []
adv.GetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p,
                                 wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
adv.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [ctypes.c_void_p,
    wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR), ctypes.POINTER(wintypes.DWORD)]
kernel.InitializeProcThreadAttributeList.argtypes = [ctypes.c_void_p, wintypes.DWORD,
                                                      wintypes.DWORD, ctypes.POINTER(ctypes.c_size_t)]
kernel.UpdateProcThreadAttribute.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.c_size_t,
    ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p]
kernel.DeleteProcThreadAttributeList.argtypes = [ctypes.c_void_p]
kernel.CreateProcessW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p,
    ctypes.c_void_p, wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR,
    ctypes.POINTER(STARTUPINFO), ctypes.POINTER(PROCESSINFO)]
kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
kernel.GetCurrentProcessId.restype = wintypes.DWORD
kernel.ProcessIdToSessionId.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
kernel.CloseHandle.argtypes = [wintypes.HANDLE]
kernel.LocalFree.argtypes = [ctypes.c_void_p]
kernel.CreatePipe.argtypes = [ctypes.POINTER(wintypes.HANDLE), ctypes.POINTER(wintypes.HANDLE),
                              ctypes.POINTER(SECURITY_ATTRIBUTES), wintypes.DWORD]
kernel.SetHandleInformation.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD]
kernel.WriteFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                             ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
kernel.ReadFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                            ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]

sid = ctypes.c_void_p()
attributes_initialized = False
attributes = None
process = PROCESSINFO()
out = {"sid_derived": False, "process_started": False, "exit_code": None}
profile_name = "HermesSyntheticProbe" + uuid.uuid4().hex
profile_created = False
test_root = allowed = private = allowed_file = private_file = allowed_output = private_output = node_copy = diagnostic = stdio_file = gui = None
pipe_handles = []
interactive_test = False


class _BrokerComplete(Exception):
    pass


def _encodable(value, encoding):
    try:
        value.encode(encoding)
        return True
    except UnicodeEncodeError:
        return False


def security_descriptor(path, requested):
    """Read only the synthetic test file's descriptor."""
    size = wintypes.DWORD()
    adv.GetFileSecurityW(str(path), requested, None, 0, ctypes.byref(size))
    if not 0 < size.value <= 65536:
        return None
    descriptor = ctypes.create_string_buffer(size.value)
    if not adv.GetFileSecurityW(str(path), requested, descriptor, size, ctypes.byref(size)):
        return None
    sddl = wintypes.LPWSTR()
    if not adv.ConvertSecurityDescriptorToStringSecurityDescriptorW(
        descriptor, 1, requested, ctypes.byref(sddl), None):
        return None
    try:
        return str(sddl.value)
    finally:
        kernel.LocalFree(ctypes.cast(sddl, ctypes.c_void_p))


def synthetic_token_diagnostic(token, path):
    """CI-only: inspect access to our synthetic path without reporting names."""
    impersonation = wintypes.HANDLE()
    if not adv.DuplicateToken(token, 2, ctypes.byref(impersonation)):
        return {"stage": "duplicate", "winerror": ctypes.get_last_error()}
    try:
        if not adv.ImpersonateLoggedOnUser(impersonation):
            return {"stage": "impersonate", "winerror": ctypes.get_last_error()}
        try:
            failures = []
            for depth, item in enumerate((path, *path.parents)):
                try:
                    item.stat()
                except OSError as error:
                    failures.append({"depth": depth, "winerror": error.winerror})
            try:
                fd = os.open(path, os.O_RDONLY)
            except OSError as error:
                read_error = error.winerror
            else:
                os.close(fd)
                read_error = 0
            return {"stage": "checked", "stat_failures": failures, "read_winerror": read_error}
        finally:
            if not adv.RevertToSelf():
                os._exit(1)
    finally:
        kernel.CloseHandle(impersonation)


try:
    if sys.argv[1:] not in (["--interactive-test"], ["--broker-test"], ["--broker-command-test"], ["--sessions-test"],
                            ["--node-test"], ["--node-child-test"]):
        raise ValueError("INVALID_SYNTHETIC_TEST")
    session = wintypes.DWORD()
    if kernel.ProcessIdToSessionId(kernel.GetCurrentProcessId(), ctypes.byref(session)):
        out["session_zero"] = session.value == 0
    interactive_test = sys.argv[1:] == ["--interactive-test"]
    broker_test = sys.argv[1:] == ["--broker-test"]
    broker_command_test = sys.argv[1:] == ["--broker-command-test"]
    sessions_test = sys.argv[1:] == ["--sessions-test"]
    shell_test = sys.argv[1:] == ["--node-shell-test"]
    child_test = sys.argv[1:] == ["--node-child-test"] or shell_test
    node_test = sys.argv[1:] == ["--node-test"] or child_test
    filesystem_test = (sys.argv[1:] == ["--filesystem-test"] or node_test or interactive_test
                       or broker_test or broker_command_test or sessions_test)
    if sys.argv[1:] == ["--temporary-profile"] or filesystem_test:
        result = userenv.CreateAppContainerProfile(profile_name, "Hermes synthetic probe",
            "Temporary isolated process test", None, 0, ctypes.byref(sid))
        profile_created = result == 0
    else:
        result = userenv.DeriveAppContainerSidFromAppContainerName(profile_name, ctypes.byref(sid))
    if result != 0:
        raise OSError(result & 0xffffffff, "DeriveAppContainerSid")
    out["sid_derived"] = True
    size = ctypes.c_size_t()
    attribute_count = 2 if interactive_test else 1
    kernel.InitializeProcThreadAttributeList(None, attribute_count, 0, ctypes.byref(size))
    if not size.value or size.value > 65536:
        raise OSError(ctypes.get_last_error(), "AttributeListSize")
    attributes = ctypes.create_string_buffer(size.value)
    if not kernel.InitializeProcThreadAttributeList(attributes, attribute_count, 0, ctypes.byref(size)):
        raise OSError(ctypes.get_last_error(), "InitializeAttributes")
    attributes_initialized = True
    capabilities = SECURITY_CAPABILITIES(sid, None, 0, 0)
    if not kernel.UpdateProcThreadAttribute(attributes, 0, 0x00020009,
        ctypes.byref(capabilities), ctypes.sizeof(capabilities), None, None):
        raise OSError(ctypes.get_last_error(), "UpdateAttributes")
    startup = STARTUPINFOEX()
    startup.startup.cb = ctypes.sizeof(startup)
    startup.startup.flags = 1
    startup.attributes = ctypes.cast(attributes, ctypes.c_void_p)
    executable = os.path.join(os.environ["WINDIR"], "System32", "cmd.exe")
    command_text = '"' + executable + '" /d /c exit 0'
    if filesystem_test:
        # GitHub's checkout can live on a drive whose ancestor ACLs deny
        # AppContainer traversal even when the test directory grants access.
        # Use the normal Windows per-user temporary directory instead.
        base = (Path(os.environ["LOCALAPPDATA"]) / "Temp").resolve(strict=True)
        test_root = base / ("h454-appcontainer-synthetic-" + uuid.uuid4().hex)
        allowed, private = test_root / "allowed", test_root / "private"
        test_root.mkdir()
        identity = subprocess.run([os.path.join(os.environ["WINDIR"], "System32", "whoami.exe"),
            "/user", "/fo", "csv", "/nh"], capture_output=True, text=True, timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW, check=True)
        user_sid = next(csv.reader(identity.stdout.splitlines()))[1]
        if re.fullmatch(r"S-1-(?:[0-9]+-){1,14}[0-9]+", user_sid) is None:
            raise RuntimeError("SYNTHETIC_USER_SID_INVALID")
        user_acl = subprocess.run([os.path.join(os.environ["WINDIR"], "System32", "icacls.exe"),
            str(test_root), "/grant", "*" + user_sid + ":(OI)(CI)M"],
            capture_output=True, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
        if user_acl.returncode:
            raise RuntimeError("SYNTHETIC_USER_ACL_FAILED")
        # AppContainers run at low integrity. The disposable root and its
        # children must explicitly accept low-integrity writes on runners
        # whose temporary directories inherit a higher integrity label.
        label_result = subprocess.run([os.path.join(os.environ["WINDIR"], "System32", "icacls.exe"),
            str(test_root), "/setintegritylevel", "(OI)(CI)L"], capture_output=True,
            timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
        if label_result.returncode:
            raise RuntimeError("SYNTHETIC_INTEGRITY_FAILED")
        allowed.mkdir()
        private.mkdir()
        # These files predate the AppContainer grant, like an existing project.
        allowed_file, private_file = allowed / "allowed.txt", private / "sentinel.txt"
        allowed_output, private_output = allowed / "written.txt", private / "attempted.txt"
        allowed_file.write_text("synthetic-allowed", encoding="ascii")
        private_file.write_text("synthetic-private", encoding="ascii")
        text_sid = wintypes.LPWSTR()
        if not adv.ConvertSidToStringSidW(sid, ctypes.byref(text_sid)):
            raise OSError(ctypes.get_last_error(), "ConvertSidToStringSidW")
        sid_text = str(text_sid.value)
        try:
            for target, rights in ((test_root, ":RX"), (allowed, ":(OI)(CI)M")):
                acl = subprocess.run([os.path.join(os.environ["WINDIR"], "System32", "icacls.exe"),
                    str(target), "/grant", "*" + text_sid.value + rights],
                    capture_output=True, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
                if acl.returncode:
                    raise RuntimeError("SYNTHETIC_ACL_FAILED")
        finally:
            kernel.LocalFree(ctypes.cast(text_sid, ctypes.c_void_p))
        dacl = security_descriptor(allowed_file, 4)
        out["allowed_file_acl_has_sid"] = sid_text in dacl if dacl else None
        label = security_descriptor(allowed_file, 16)
        out["synthetic_file_label"] = ("high" if label and ";;;HI)" in label else
            "medium" if label and ";;;ME)" in label else "low" if label and ";;;LW)" in label else
            "other" if label else "none_or_unavailable")
        # Keep output in the explicitly inherited private pipe: an AppContainer
        # on Server runners may be unable to open the NUL device for redirection.
        shell_command = ('(type "' + str(allowed_file) + '") || exit /b 2 & '
            + '(echo synthetic>"' + str(allowed_output) + '") || exit /b 3 & '
            + '(type "' + str(private_file) + '") && exit /b 4 & '
            + '(echo bad>"' + str(private_output) + '") && exit /b 5 & exit /b 0')
        command_text = '"' + executable + '" /d /c ' + shell_command
        if interactive_test:
            command_text = '"' + executable + '" /d /q'
        if node_test:
            executable = shutil.which("node")
            if not executable:
                raise RuntimeError("NODE_UNAVAILABLE")
            js = ("const fs=require('node:fs');"
                  + "try{fs.readFileSync(" + json.dumps(str(allowed_file)) + ")}catch{process.exit(2)};"
                  + "try{fs.writeFileSync(" + json.dumps(str(allowed_output)) + ",'synthetic')}"
                  + "catch{process.exit(6)};"
                  + "try{fs.readFileSync(" + json.dumps(str(private_file)) + ");process.exit(3)}catch{};"
                  + "try{fs.writeFileSync(" + json.dumps(str(private_output)) + ",'bad');process.exit(4)}catch{};")
            if child_test:
                diagnostic = allowed / "diagnostic.json"
                stdio_file = allowed / "stdio.txt"
                if shell_test:
                    child_executable = os.path.join(os.environ["WINDIR"], "System32", "cmd.exe")
                    child_args = ["/d", "/c", shell_command]
                else:
                    node_copy = allowed / "node.exe"
                    shutil.copyfile(executable, node_copy)
                    child_executable = str(node_copy)
                    child_args = ["-e", js]
                js = ("const fs=require('node:fs');"
                      + "const input=fs.openSync(" + json.dumps(str(allowed_file)) + ",'r');"
                      + "const output=fs.openSync(" + json.dumps(str(stdio_file)) + ",'w');"
                      + "const c=require('node:child_process').spawnSync(" + json.dumps(child_executable) + ","
                      + json.dumps(child_args) + ",{windowsHide:true,timeout:3000,stdio:[input,output,output],cwd:"
                      + json.dumps(str(allowed)) + "});"
                      + "fs.closeSync(input);fs.closeSync(output);"
                      + "require('node:fs').writeFileSync(" + json.dumps(str(diagnostic))
                      + ",JSON.stringify({status:c.status,code:c.error?.code||null,signal:c.signal}));"
                      + "process.exit(c.status===0?0:c.error?.code==='EACCES'?21:"
                      + "c.error?.code==='EPERM'?22:c.error?.code==='ENOENT'?23:c.error?.code==='ETIMEDOUT'?27:"
                      + "c.error?24:c.status===null?25:c.status===3221225794?42:"
                      + "c.status>0&&c.status<20?c.status:26)")
            js = "Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,200);" + js
            command_text = subprocess.list2cmdline([executable, "-e", js])
        if sessions_test:
            sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
            from device_fabric.windows_personal_terminal_sessions import PersonalTerminalSessions
            manager = PersonalTerminalSessions(int(sid.value), str(allowed))
            try:
                # Give a disposable Node copy the GUI subsystem so this child
                # cannot create a console window on the developer's desktop.
                node = shutil.which("node")
                if not node:
                    raise RuntimeError("NODE_UNAVAILABLE")
                gui = allowed / "synthetic-gui.exe"
                shutil.copyfile(node, gui)
                with gui.open("r+b") as image:
                    image.seek(0x3c)
                    pe = struct.unpack("<I", image.read(4))[0]
                    image.seek(pe)
                    if image.read(4) != b"PE\0\0":
                        raise RuntimeError("SYNTHETIC_PE_INVALID")
                    image.seek(pe + 4 + 20 + 68)
                    if image.read(2) != b"\x03\x00":
                        raise RuntimeError("SYNTHETIC_SUBSYSTEM_INVALID")
                    image.seek(-2, 1)
                    image.write(b"\x02\x00")
                child_js = "console.log('H454_CHILD_PID='+process.pid);setInterval(()=>{},60000)"
                child_command = '"' + str(gui) + '" -e "' + child_js + '"'
                child = manager.dispatch("start_process", {"command": child_command, "timeout_ms": 5000})
                child_text = child["content"][0]["text"]
                parent_match = re.search(r"Process ([0-9]+) ", child_text)
                child_match = re.search(r"H454_CHILD_PID=([0-9]+)", child_text)
                out["child_started"] = bool(parent_match and child_match and not child["isError"])
                if out["child_started"]:
                    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
                    kernel.OpenProcess.restype = wintypes.HANDLE
                    child_handle = kernel.OpenProcess(0x100001, False, int(child_match.group(1)))
                    if not child_handle:
                        raise RuntimeError("SYNTHETIC_CHILD_HANDLE_FAILED")
                    try:
                        stopped = manager.dispatch("force_terminate", {"pid": int(parent_match.group(1))})
                        out["child_job_terminated"] = (not stopped["isError"] and
                                                       kernel.WaitForSingleObject(child_handle, 5000) == 0)
                    finally:
                        if kernel.WaitForSingleObject(child_handle, 0) != 0:
                            kernel.TerminateProcess(child_handle, 1)
                            kernel.WaitForSingleObject(child_handle, 5000)
                        kernel.CloseHandle(child_handle)
                finished = manager.dispatch("start_process", {"command": shell_command, "timeout_ms": 3000})
                failed = manager.dispatch("start_process", {"command": "exit /b 7", "timeout_ms": 3000})
                started = manager.dispatch("start_process", {
                    "command": "set /p H454=H454_READY & echo H454_DONE", "timeout_ms": 3000})
                started_text = started["content"][0]["text"]
                match = re.search(r"Process ([0-9]+) ", started_text)
                if not match:
                    raise RuntimeError("SESSION_START_FAILED")
                second = manager.dispatch("start_process", {
                    "command": "set /p H454=H454_SECOND", "timeout_ms": 3000})
                second_match = re.search(r"Process ([0-9]+) ", second["content"][0]["text"])
                if not second_match:
                    raise RuntimeError("SECOND_SESSION_START_FAILED")
                listing = manager.dispatch("list_sessions", {})["content"][0]["text"]
                out["multiple_sessions"] = (not second["isError"] and match.group(1) in listing
                                            and second_match.group(1) in listing)
                reply = manager.dispatch("interact_with_process", {
                    "pid": int(match.group(1)), "input": "synthetic", "timeout_ms": 3000})
                terminated = manager.dispatch("force_terminate", {"pid": int(second_match.group(1))})
                out["session_terminated"] = not terminated["isError"]
                sample = next(value for value in ("Привет", "é", "A")
                              if _encodable(value, manager._encoding))
                encoded_output = manager.dispatch("start_process", {
                    "command": "echo " + sample, "timeout_ms": 3000})
                encoded_input = manager.dispatch("start_process", {
                    "command": "set /p H454=H454_ENCODING & set H454", "timeout_ms": 3000})
                encoding_match = re.search(r"Process ([0-9]+) ", encoded_input["content"][0]["text"])
                if not encoding_match:
                    raise RuntimeError("ENCODING_SESSION_START_FAILED")
                encoded_reply = manager.dispatch("interact_with_process", {
                    "pid": int(encoding_match.group(1)), "input": sample, "timeout_ms": 3000})
                out["local_encoding_roundtrip"] = (not encoded_output["isError"]
                    and sample in encoded_output["content"][0]["text"]
                    and not encoded_reply["isError"] and sample in encoded_reply["content"][0]["text"])
                revoke = manager.dispatch("start_process", {
                    "command": 'set /p H454=H454_REVOKE & type "' + str(allowed_file) + '"',
                    "timeout_ms": 3000})
                revoke_text = revoke["content"][0]["text"]
                revoke_match = re.search(r"Process ([0-9]+) ", revoke_text)
                if revoke["isError"] or not revoke_match or "H454_REVOKE" not in revoke_text:
                    raise RuntimeError("REVOCATION_SESSION_START_FAILED")
                revoke_acl = subprocess.run([os.path.join(os.environ["WINDIR"], "System32", "icacls.exe"),
                    str(allowed), "/remove:g", "*" + sid_text], capture_output=True,
                    timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
                if revoke_acl.returncode:
                    raise RuntimeError("SYNTHETIC_REVOKE_FAILED")
                revoked = manager.dispatch("interact_with_process", {
                    "pid": int(revoke_match.group(1)), "input": "synthetic", "timeout_ms": 3000})
                remaining_dacl = security_descriptor(allowed_file, 4)
                out["revocation_denied"] = (bool(remaining_dacl) and sid_text not in remaining_dacl
                                             and revoked["isError"])
                out["process_started"] = not finished["isError"]
                out["is_appcontainer"] = out["process_started"]
                out["exit_code"] = 0 if out["process_started"] else 1
                out["allowed_write"] = allowed_output.is_file()
                out["private_write_blocked"] = not private_output.exists()
                out["nonzero_is_error"] = failed["isError"] and "code 7" in failed["content"][0]["text"]
                out["session_interaction"] = (not started["isError"] and "H454_READY" in started_text
                    and not reply["isError"] and "H454_DONE" in reply["content"][0]["text"])
            finally:
                manager.close()
            raise _BrokerComplete()
        if broker_test or broker_command_test:
            # Load the trusted repository module, not any project or vault.
            sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
            from device_fabric.windows_appcontainer_terminal import AppContainerTerminal
            terminal = AppContainerTerminal(int(sid.value), str(allowed),
                                             command=shell_command if broker_command_test else None)
            try:
                out["process_started"] = True
                # The broker has verified both TokenIsAppContainer and the
                # exact AppContainer SID before resuming the shell.
                out["is_appcontainer"] = True
                output = bytearray()
                if broker_test:
                    terminal.write(b"echo H454_INTERACTIVE_OK\r\n")
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline and b"H454_INTERACTIVE_OK" not in output:
                        output.extend(terminal.read())
                        time.sleep(0.05)
                    out["interactive_roundtrip"] = (b"H454_INTERACTIVE_OK" in output and terminal.poll() is None)
                    if not out["interactive_roundtrip"]:
                        raise RuntimeError("BROKER_INTERACTION_FAILED")
                    terminal.write((shell_command + "\r\n").encode("ascii"))
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    output.extend(terminal.read())
                    status = terminal.poll()
                    if status is not None:
                        output.extend(terminal.read())
                        break
                    time.sleep(0.05)
                else:
                    raise RuntimeError("BROKER_TIMEOUT")
                out["exit_code"] = status
                out["interactive_output"] = b"H454_INTERACTIVE_OK" in output
                out["allowed_write"] = allowed_output.is_file()
                out["private_write_blocked"] = not private_output.exists()
            finally:
                terminal.close()
            terminal = AppContainerTerminal(int(sid.value), str(allowed),
                                             command="exit /b 259" if broker_command_test else None)
            try:
                if broker_test:
                    terminal.write(b"exit /b 259\r\n")
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline and terminal.poll() is None:
                    time.sleep(0.05)
                out["exit_259"] = terminal.poll() == 259
            finally:
                terminal.close()
            raise _BrokerComplete()
    if interactive_test:
        input_read, input_write, output_read, output_write = (wintypes.HANDLE() for _ in range(4))
        security = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), None, True)
        if not kernel.CreatePipe(ctypes.byref(input_read), ctypes.byref(input_write), ctypes.byref(security), 0):
            raise OSError(ctypes.get_last_error(), "CreateInputPipe")
        pipe_handles.extend((input_read, input_write))
        if not kernel.CreatePipe(ctypes.byref(output_read), ctypes.byref(output_write), ctypes.byref(security), 0):
            raise OSError(ctypes.get_last_error(), "CreateOutputPipe")
        pipe_handles.extend((output_read, output_write))
        if not kernel.SetHandleInformation(input_write, 1, 0) or not kernel.SetHandleInformation(output_read, 1, 0):
            raise OSError(ctypes.get_last_error(), "SetHandleInformation")
        inherited = (wintypes.HANDLE * 2)(input_read, output_write)
        if not kernel.UpdateProcThreadAttribute(attributes, 0, 0x00020002, inherited,
            ctypes.sizeof(inherited), None, None):
            raise OSError(ctypes.get_last_error(), "HandleList")
        startup.startup.flags |= 0x100
        startup.startup.stdin, startup.startup.stdout, startup.startup.stderr = input_read, output_write, output_write
    command = ctypes.create_unicode_buffer(command_text)
    env_names = ("SYSTEMROOT", "WINDIR", "USERPROFILE", "LOCALAPPDATA", "TEMP", "TMP")
    environment = ctypes.create_unicode_buffer("\0".join(
        name + "=" + os.environ[name] for name in env_names if name in os.environ) + "\0\0")
    flags = 0x08000000 | 0x00080000 | 0x00000400
    if not kernel.CreateProcessW(executable, command, None, None, interactive_test, flags,
        environment, str(allowed) if interactive_test else os.path.dirname(executable),
        ctypes.byref(startup.startup), ctypes.byref(process)):
        raise OSError(ctypes.get_last_error(), "CreateProcessW")
    out["process_started"] = True
    token = wintypes.HANDLE()
    if adv.OpenProcessToken(process.process, 0x000A, ctypes.byref(token)):
        try:
            is_container, returned = wintypes.DWORD(), wintypes.DWORD()
            if adv.GetTokenInformation(token, 29, ctypes.byref(is_container),
                                       ctypes.sizeof(is_container), ctypes.byref(returned)):
                out["is_appcontainer"] = bool(is_container.value)
            if interactive_test and os.environ.get("GITHUB_ACTIONS") == "true":
                out["synthetic_token_access"] = synthetic_token_diagnostic(token, allowed_file)
        finally:
            kernel.CloseHandle(token)
    if interactive_test:
        for h in (input_read, output_write):
            kernel.CloseHandle(h)
            pipe_handles.remove(h)
        commands = ("echo H454_INTERACTIVE_OK\r\n" + shell_command + "\r\n").encode("ascii")
        written = wintypes.DWORD()
        buf = ctypes.create_string_buffer(commands)
        if not kernel.WriteFile(input_write, buf, len(commands), ctypes.byref(written), None) or written.value != len(commands):
            raise OSError(ctypes.get_last_error(), "WriteInput")
        kernel.CloseHandle(input_write)
        pipe_handles.remove(input_write)
    if kernel.WaitForSingleObject(process.process, 10000) != 0:
        kernel.TerminateProcess(process.process, 1)
        kernel.WaitForSingleObject(process.process, 5000)
        raise RuntimeError("PROCESS_TIMEOUT")
    code = wintypes.DWORD()
    if not kernel.GetExitCodeProcess(process.process, ctypes.byref(code)):
        raise OSError(ctypes.get_last_error(), "GetExitCodeProcess")
    out["exit_code"] = code.value
    if interactive_test:
        data, count = ctypes.create_string_buffer(4096), wintypes.DWORD()
        if kernel.ReadFile(output_read, data, len(data), ctypes.byref(count), None):
            content = data.raw[:count.value]
            out["interactive_output"] = b"H454_INTERACTIVE_OK" in content
            if code.value != 0:
                lower = content.lower()
                out["synthetic_error"] = ("access_denied" if b"access is denied" in lower else
                    "not_found" if b"cannot find" in lower else "other")
    if filesystem_test:
        out["allowed_write"] = allowed_output.is_file()
        out["private_write_blocked"] = not private_output.exists()
        if diagnostic is not None and diagnostic.is_file():
            out["child_status"] = json.loads(diagnostic.read_text(encoding="utf-8"))
except _BrokerComplete:
    pass
except OSError as exc:
    out["error"] = {"api": exc.strerror, "code": exc.errno}
except Exception as exc:
    out["error"] = type(exc).__name__
finally:
    if process.process:
        running_code = wintypes.DWORD()
        if kernel.GetExitCodeProcess(process.process, ctypes.byref(running_code)) and running_code.value == 259:
            kernel.TerminateProcess(process.process, 1)
            kernel.WaitForSingleObject(process.process, 5000)
    for handle in (process.thread, process.process):
        if handle:
            kernel.CloseHandle(handle)
    for handle in pipe_handles:
        if handle:
            kernel.CloseHandle(handle)
    if attributes_initialized:
        kernel.DeleteProcThreadAttributeList(attributes)
    if sid:
        adv.FreeSid(sid)
    if profile_created:
        out["temporary_profile_deleted"] = userenv.DeleteAppContainerProfile(profile_name) == 0
    for path in (allowed_file, private_file, allowed_output, private_output, node_copy, diagnostic, stdio_file, gui):
        if path is not None:
            path.unlink(missing_ok=True)
    for path in (allowed, private, test_root):
        if path is not None and path.exists():
            path.rmdir()
print(json.dumps(out))

required = ("sid_derived", "process_started", "is_appcontainer", "allowed_write",
            "private_write_blocked", "temporary_profile_deleted")
if (out.get("exit_code") != 0 or any(out.get(name) is not True for name in required)
    or ((interactive_test or sys.argv[1:] == ["--broker-test"]) and out.get("interactive_output") is not True)
    or (sys.argv[1:] == ["--broker-test"] and out.get("interactive_roundtrip") is not True)
    or (sys.argv[1:] in (["--broker-test"], ["--broker-command-test"]) and out.get("exit_259") is not True)
    or (sys.argv[1:] == ["--sessions-test"] and
        any(out.get(name) is not True for name in ("session_interaction", "nonzero_is_error",
                                                   "multiple_sessions", "session_terminated",
                                                   "revocation_denied", "local_encoding_roundtrip",
                                                   "child_started", "child_job_terminated")))):
    raise SystemExit(1)
