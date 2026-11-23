"""Current-user native READ worker; requires separately provisioned DPAPI state.

The process has the owner's Windows rights. This is not an OS sandbox. No
remote request can supply a state path, token, executable or network endpoint.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import hashlib
import os
from pathlib import Path
import stat
import sys

from device_fabric import windows_personal_session as personal
from device_fabric import native_private_tls as private_tls
from scripts.h454_native_win32_worker import _TokenUser

REPARSE = 0x400


def current_sid() -> str:
    """Read the actual process token SID without a shell or a window."""
    if os.name != "nt":
        return ""
    token = wintypes.HANDLE()
    sid_string = wintypes.LPWSTR()
    try:
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
        advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p,
                                                wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
        if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
            return ""
        size = wintypes.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
        if not 1 <= size.value <= 8192:
            return ""
        buf = ctypes.create_string_buffer(size.value)
        if not advapi.GetTokenInformation(token, 1, buf, size, ctypes.byref(size)):
            return ""
        ptr = ctypes.cast(buf, ctypes.POINTER(_TokenUser)).contents.user.sid
        if not ptr or not advapi.ConvertSidToStringSidW(ptr, ctypes.byref(sid_string)):
            return ""
        result = sid_string.value or ""
        return result if personal.SID.fullmatch(result) else ""
    except Exception:
        return ""
    finally:
        if sid_string:
            kernel.LocalFree(ctypes.cast(sid_string, ctypes.c_void_p))
        if token.value:
            kernel.CloseHandle(token)


def load_config() -> bytes:
    """Read only the fixed user-profile file, rejecting reparse/hardlinks."""
    try:
        base = os.environ.get("LOCALAPPDATA", "")
        if os.name != "nt" or not os.path.isabs(base):
            raise ValueError()
        root = Path(base) / "HermesCommanderPersonal"
        path = root / "device.json"
        for item in (root, path):
            info = item.lstat()
            if info.st_file_attributes & REPARSE:
                raise ValueError()
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= personal.MAX_CONFIG_BYTES:
            raise ValueError()
        with path.open("rb") as stream:
            raw = stream.read(personal.MAX_CONFIG_BYTES + 1)
            actual = os.fstat(stream.fileno())
        if (len(raw) != info.st_size or actual.st_ino != info.st_ino or actual.st_dev != info.st_dev
            or actual.st_size != info.st_size):
            raise ValueError()
        return raw
    except Exception:
        raise personal.PersonalSessionDenied("personal_windows_denied") from None


def load_ca(expected_hash: str) -> bytes:
    """Read the existing tunnel CA; DPAPI binds its hash to the device state."""
    try:
        base = os.environ.get("LOCALAPPDATA", "")
        if os.name != "nt" or not os.path.isabs(base) or personal.SHA64.fullmatch(expected_hash) is None:
            raise ValueError()
        root = Path(base) / "HermesH15WindowsPermanent"
        path = root / "wss-relay-ca.pem"
        for item in (root, path):
            if item.lstat().st_file_attributes & REPARSE:
                raise ValueError()
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= private_tls.CA_MAX_BYTES:
            raise ValueError()
        with path.open("rb") as stream:
            ca = stream.read(private_tls.CA_MAX_BYTES + 1)
            actual = os.fstat(stream.fileno())
        if (len(ca) != info.st_size or actual.st_ino != info.st_ino or actual.st_dev != info.st_dev
            or actual.st_size != info.st_size or hashlib.sha256(ca).hexdigest() != expected_hash
            or not ca.startswith(b"-----BEGIN CERTIFICATE-----")
            or not ca.rstrip().endswith(b"-----END CERTIFICATE-----")
            or ca.count(b"-----BEGIN CERTIFICATE-----") != 1):
            raise ValueError()
        return ca
    except Exception:
        raise personal.PersonalSessionDenied("personal_windows_denied") from None


def main() -> int:
    if sys.argv[1:] != ["--run"] or os.name != "nt":
        return 2
    try:
        from websockets.sync.client import connect
        config = load_config()
        candidate, _owner_sid, ca_sha256 = personal.parse_config(config)
        relay = private_tls.PrivateRelay("windows", candidate.release_sha,
                                         private_tls.WINDOWS_LOOPBACK, load_ca(ca_sha256))
        def status(*, target, device_id, bearer, base_url):
            if base_url != personal.PUBLIC:
                raise ValueError()
            return lambda: private_tls.current_bearer(relay, target=target,
                                                       device_id=device_id, bearer=bearer)
        personal.run(config, user_verified=current_sid,
                     connector=private_tls.private_websocket_connector(relay, connect),
                     owner_status=status)
        # Exhaustion or disconnect means the device is offline, not healthy.
        return 2
    except Exception:
        # A transport or path exception can contain private data.
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
