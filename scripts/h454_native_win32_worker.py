"""H454 original-Windows native READ worker for the existing authenticated BRC.

This runs ONE real outbound read-only WSS session as an isolated Windows
virtual service account. It reads only two fixed protected ProgramData files,
unseals the bearer under DPAPI CurrentUser for THAT service identity, verifies
live owner-bound status via the existing BRC relay, and calls the previously
reviewed Win32 handle-bound original-file adapter.

The Windows SCM binary/installer must independently check its service SID,
private ACLs and original-root permissions BEFORE launching this worker.
This module does not install, pair, change ACLs, create files or grant
process/write capabilities. No user-controlled file path, URL, token,
device ID or callback may be supplied on the public CLI.
"""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import os
from pathlib import Path
import re
import stat
import sys
import time
from typing import Any, Callable

from device_fabric.native_brc_status import PUBLIC, status_provider
from device_fabric.windows_native_dpapi import unseal_for_current_user
from device_fabric.windows_native_reenrollment import (
    PrivateWindowsSession, parse_local_session, run_once as read_session,
)

SERVICE_ACCOUNT = r"NT SERVICE\HermesCommanderNative"
STATE = Path(r"C:\ProgramData\HermesCommanderNative")
MANIFEST = STATE / "manifest.json"
CONFIG = STATE / "device.json"
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SHA64 = re.compile(r"[0-9a-f]{64}\Z")
MAX_MANIFEST = 8192
MAX_CONFIG = 8192
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
TOKEN_QUERY = 0x0008


class Win32WorkerDenied(ValueError):
    """Generic refusal: no host path, bearer, code or OS error message."""


class _SidAndAttributes(ctypes.Structure):
    _fields_ = [("sid", ctypes.c_void_p), ("attributes", wintypes.DWORD)]


class _TokenUser(ctypes.Structure):
    _fields_ = [("user", _SidAndAttributes)]


def service_sid_verified() -> bool:
    """Check the ACTUAL kernel process token SID, not an environment flag."""
    if os.name != "nt":
        return False
    token = wintypes.HANDLE()
    kernel = None
    try:
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        advapi.OpenProcessToken.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE),
        ]
        advapi.OpenProcessToken.restype = wintypes.BOOL
        advapi.GetTokenInformation.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p,
            wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
        ]
        advapi.GetTokenInformation.restype = wintypes.BOOL
        advapi.LookupAccountNameW.argtypes = [
            wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_void_p,
            ctypes.POINTER(wintypes.DWORD), wintypes.LPWSTR,
            ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
        ]
        advapi.LookupAccountNameW.restype = wintypes.BOOL
        advapi.EqualSid.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        advapi.EqualSid.restype = wintypes.BOOL
        if not advapi.OpenProcessToken(
            kernel.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(token),
        ):
            return False

        size = wintypes.DWORD(0)
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
        if not 1 <= size.value <= 8192:
            return False
        memory = ctypes.create_string_buffer(size.value)
        if not advapi.GetTokenInformation(
            token, 1, memory, size, ctypes.byref(size),
        ):
            return False
        current_sid = ctypes.cast(memory, ctypes.POINTER(_TokenUser)).contents.user.sid
        if not current_sid:
            return False
        sid_bytes = wintypes.DWORD(0)
        domain_chars = wintypes.DWORD(0)
        sid_type = wintypes.DWORD(0)
        advapi.LookupAccountNameW(
            None, SERVICE_ACCOUNT, None, ctypes.byref(sid_bytes),
            None, ctypes.byref(domain_chars), ctypes.byref(sid_type),
        )
        if not 1 <= sid_bytes.value <= 256 or domain_chars.value > 256:
            return False
        expected_sid = ctypes.create_string_buffer(sid_bytes.value)
        domain = ctypes.create_unicode_buffer(max(1, domain_chars.value))
        if not advapi.LookupAccountNameW(
            None, SERVICE_ACCOUNT, expected_sid, ctypes.byref(sid_bytes),
            domain, ctypes.byref(domain_chars), ctypes.byref(sid_type),
        ):
            return False
        return bool(advapi.EqualSid(current_sid, expected_sid))
    except Exception:
        return False
    finally:
        try:
            if token.value and kernel is not None:
                kernel.CloseHandle(token)
        except Exception:
            pass


def _private_file(path: Path, limit: int) -> bytes:
    """Read exact fixed local state, never paths chosen by remote requests.

    The enclosing SCM must have already verified the NTFS DACL and service
    SID. A privileged administrator changing its protected state is outside
    the unprivileged native service threat boundary.
    """
    try:
        if path not in (MANIFEST, CONFIG):
            raise Win32WorkerDenied("native_win32_worker_denied")
        for ancestor in (path, path.parent, path.parent.parent):
            entry = ancestor.lstat()
            if (entry.st_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT):
                raise Win32WorkerDenied("native_win32_worker_denied")
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode)
            or not 0 < info.st_size <= limit
            or info.st_nlink != 1):
            raise Win32WorkerDenied("native_win32_worker_denied")
        with path.open("rb") as stream:
            payload = stream.read(limit + 1)
            final = os.fstat(stream.fileno())
        if (len(payload) != info.st_size or len(payload) > limit
            or final.st_dev != info.st_dev or final.st_ino != info.st_ino
            or final.st_size != info.st_size):
            raise Win32WorkerDenied("native_win32_worker_denied")
        return payload
    except Exception:
        raise Win32WorkerDenied("native_win32_worker_denied") from None


def run_trusted_once(
    *, expected_release: str,
    connector: Callable[..., Any] | None = None,
    sid_gate: Callable[[], bool] = service_sid_verified,
    source_reader: Callable[[Path, int], bytes] = _private_file,
    unseal: Callable[..., str] = unseal_for_current_user,
    owner_status: Callable[..., Callable[[], bool]] = status_provider,
    on_verified_welcome: Callable[[], None] | None = None,
) -> str:
    """Execute bounded Win32 read via actual service ID + owner status.

    Injectable gates exist only for non-host unit tests. Production CLI does
    not accept callbacks, file paths, device IDs or network endpoints.
    """
    if (type(expected_release) is not str
        or SHA40.fullmatch(expected_release) is None
        or not all(callable(x) for x in
            (sid_gate, source_reader, unseal, owner_status))
        or (connector is not None and not callable(connector))
        or (on_verified_welcome is not None and not callable(on_verified_welcome))):
        raise Win32WorkerDenied("native_win32_worker_denied")
    try:
        if sys.platform != "win32" or sid_gate() is not True:
            raise Win32WorkerDenied("native_win32_worker_denied")
        manifest = source_reader(MANIFEST, MAX_MANIFEST)
        config = source_reader(CONFIG, MAX_CONFIG)
        if type(manifest) is not bytes or type(config) is not bytes:
            raise Win32WorkerDenied("native_win32_worker_denied")
        digest = hashlib.sha256(manifest).hexdigest()
        candidate: PrivateWindowsSession = parse_local_session(
            manifest, config,
            expected_release=expected_release,
            expected_manifest_sha256=digest,
        )
        # Reject an expired/far-future credential before even unsealing
        # DPAPI or contacting the owner relay; also rechecked per WSS IO.
        remaining = candidate.expires_at - time.time()
        if not 0 < remaining <= 3600:
            raise Win32WorkerDenied("native_win32_worker_denied")
        if sid_gate() is not True:
            raise Win32WorkerDenied("native_win32_worker_denied")
        bearer = unseal(
            candidate.sealed_bearer,
            manifest_sha256=digest, device_id=candidate.device_id,
        )
        if type(bearer) is not str:
            raise Win32WorkerDenied("native_win32_worker_denied")
        live = owner_status(
            target="windows", device_id=candidate.device_id,
            bearer=bearer, base_url=PUBLIC,
        )
        if not callable(live) or live() is not True:
            raise Win32WorkerDenied("native_win32_worker_denied")
        if connector is None:
            from websockets.sync.client import connect
            connector = connect

        def active() -> bool:
            return live() is True

        def revoke() -> bool:
            return active() is not True

        options = dict(
            connector=connector,
            service_os_verified=sid_gate,
            owner_pair_verified=active,
            is_device_revoked=revoke,
            unseal_bearer=lambda sealed: bearer
            if sealed == candidate.sealed_bearer else "",
        )
        if on_verified_welcome is not None:
            options["on_verified_welcome"] = on_verified_welcome
        return read_session(candidate, **options)
    except Exception:
        raise Win32WorkerDenied("native_win32_worker_denied") from None


class _SafeParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        # argparse's default error includes unknown values, which could
        # disclose a mistaken --token argument into a service journal.
        raise Win32WorkerDenied("native_win32_worker_denied")


def main(argv: list[str] | None = None) -> int:
    parser = _SafeParser(
        description="Hermes original Windows native owner-paired READ worker")
    parser.add_argument("--run-once", action="store_true")
    parser.add_argument("--service-supervised", action="store_true")
    parser.add_argument("--release-sha", required=True)
    try:
        opts = parser.parse_args(argv)
        if not opts.run_once:
            raise Win32WorkerDenied("native_win32_worker_denied")
        options = {}
        if opts.service_supervised:
            # Only a service-SID process may reach this marker after
            # owner status and an authenticated WSS welcome both pass.
            options["on_verified_welcome"] = lambda: print(
                "H454_NATIVE_BRC_SESSION_READY=YES", flush=True)
        run_trusted_once(expected_release=opts.release_sha, **options)
        return 0
    except Win32WorkerDenied:
        print("H454_NATIVE_WIN32_WORKER=DENIED", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
