"""Windows DPAPI CurrentUser bearer envelope for Hermes #454 Stage 2A.

No filesystem, registry, service, shell, network, enrollment, or installation
effects. The future SERVICE must run this code as the restricted identity that
enrolled the bearer. A caller-supplied 'owner approved' boolean is not a gate.

DPAPI CurrentUser, not LocalMachine: a different Windows identity must not
recover the bearer. NTFS ACLs and the exact service SID must be verified by a
separate owner-approved installer; DPAPI does not replace OS confinement.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import hashlib
import os
import re

SCHEMA = b"H454\0WIN32\0NATIVE_READ\0DPAPI_CURRENT_USER\0V1\0"
MAX_CIPHERTEXT = 4096
MAX_PLAINTEXT = 256
DEVICE = re.compile(r"h454-win-native-[0-9a-f]{32}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
TOKEN = re.compile(r"[A-Za-z0-9_.~-]{40,256}\Z")
CRYPTPROTECT_UI_FORBIDDEN = 0x01


class NativeDpapiDenied(ValueError):
    """Opaque, constant denial: never echo token, path or Win32 error."""


class _Blob(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


def _entropy(*, manifest_sha256: str, device_id: str) -> bytes:
    if (type(manifest_sha256) is not str
        or SHA256.fullmatch(manifest_sha256) is None
        or type(device_id) is not str
        or DEVICE.fullmatch(device_id) is None):
        raise NativeDpapiDenied("native_dpapi_denied")
    return hashlib.sha256(
        SCHEMA + manifest_sha256.encode("ascii") +
        b"\0" + device_id.encode("ascii")
    ).digest()


def _input_blob(value: bytes) -> tuple[_Blob, object]:
    # Hold a private ctypes copy alive until the Win32 call returns.
    if type(value) is not bytes or not 1 <= len(value) <= MAX_CIPHERTEXT:
        raise NativeDpapiDenied("native_dpapi_denied")
    buffer = (ctypes.c_ubyte * len(value)).from_buffer_copy(value)
    return _Blob(len(value), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))), buffer


def _winapi():
    if os.name != "nt":
        raise NativeDpapiDenied("native_dpapi_denied")
    try:
        crypt = ctypes.WinDLL("crypt32", use_last_error=True)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        crypt.CryptProtectData.argtypes = [
            ctypes.POINTER(_Blob), wintypes.LPCWSTR,
            ctypes.POINTER(_Blob), ctypes.c_void_p, ctypes.c_void_p,
            wintypes.DWORD, ctypes.POINTER(_Blob),
        ]
        crypt.CryptProtectData.restype = wintypes.BOOL
        crypt.CryptUnprotectData.argtypes = [
            ctypes.POINTER(_Blob), ctypes.c_void_p,
            ctypes.POINTER(_Blob), ctypes.c_void_p, ctypes.c_void_p,
            wintypes.DWORD, ctypes.POINTER(_Blob),
        ]
        crypt.CryptUnprotectData.restype = wintypes.BOOL
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        kernel.LocalFree.restype = ctypes.c_void_p
        return crypt, kernel
    except Exception:
        raise NativeDpapiDenied("native_dpapi_denied") from None


def _crypt(data: bytes, entropy: bytes, *, decrypt: bool) -> bytes:
    try:
        original, keep_original = _input_blob(data)
        supplementary, keep_entropy = _input_blob(entropy)
        # Pointers remain valid throughout this Win32 call.
        _ = (keep_original, keep_entropy)
        crypt, kernel = _winapi()
        out = _Blob()
        try:
            if decrypt:
                result = crypt.CryptUnprotectData(
                    ctypes.byref(original), None, ctypes.byref(supplementary),
                    None, None, CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out),
                )
            else:
                result = crypt.CryptProtectData(
                    ctypes.byref(original), None, ctypes.byref(supplementary),
                    None, None, CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out),
                )
            if not result or not out.pbData:
                raise NativeDpapiDenied("native_dpapi_denied")
            limit = MAX_PLAINTEXT if decrypt else MAX_CIPHERTEXT
            if not 1 <= out.cbData <= limit:
                raise NativeDpapiDenied("native_dpapi_denied")
            return ctypes.string_at(out.pbData, out.cbData)
        finally:
            try:
                if out.pbData:
                    try:
                        if decrypt and out.cbData:
                            ctypes.memset(out.pbData, 0, out.cbData)
                    finally:
                        kernel.LocalFree(ctypes.cast(out.pbData, ctypes.c_void_p))
            finally:
                # Limit the lifetime of the extra unmanaged plaintext copy
                # used to marshal a bearer into CryptProtectData.
                if not decrypt:
                    ctypes.memset(ctypes.addressof(keep_original), 0, len(data))
    except Exception:
        raise NativeDpapiDenied("native_dpapi_denied") from None


def seal_for_current_user(
    bearer: str, *, manifest_sha256: str, device_id: str,
) -> bytes:
    """Encrypt exactly one new owner-enrolled bearer in the current user scope.

    No automatic token creation, pairing or disk persistence occurs here.
    """
    if type(bearer) is not str or TOKEN.fullmatch(bearer) is None:
        raise NativeDpapiDenied("native_dpapi_denied")
    entropy = _entropy(manifest_sha256=manifest_sha256, device_id=device_id)
    return _crypt(bearer.encode("ascii"), entropy, decrypt=False)


def unseal_for_current_user(
    sealed: bytes, *, manifest_sha256: str, device_id: str,
) -> str:
    """Unseal only in the *same Windows identity*, bound to the exact manifest.

    The restricted installer must additionally enforce owner authentication,
    private-state NTFS ACLs, revocation and service identity before invoking it.
    """
    if type(sealed) is not bytes or not 32 <= len(sealed) <= MAX_CIPHERTEXT:
        raise NativeDpapiDenied("native_dpapi_denied")
    entropy = _entropy(manifest_sha256=manifest_sha256, device_id=device_id)
    plaintext = _crypt(sealed, entropy, decrypt=True)
    try:
        token = plaintext.decode("ascii")
        if TOKEN.fullmatch(token) is None:
            raise NativeDpapiDenied("native_dpapi_denied")
        return token
    except Exception:
        raise NativeDpapiDenied("native_dpapi_denied") from None
