"""Synthetic ACL experiment only; this is not an installer or an isolation verifier."""

import ctypes
from ctypes import wintypes
from pathlib import Path
import tempfile


class _Trustee(ctypes.Structure):
    _fields_ = [("multiple", ctypes.c_void_p), ("multiple_op", ctypes.c_int),
                ("form", ctypes.c_int), ("kind", ctypes.c_int), ("name", ctypes.c_void_p)]


class _Explicit(ctypes.Structure):
    _fields_ = [("permissions", wintypes.DWORD), ("mode", ctypes.c_int),
                ("inheritance", wintypes.DWORD), ("trustee", _Trustee)]


def change_acl(path, sid, *, inherit=False, revoke=False, read_only=False):
    """Modify only a uniquely named disposable fixture created under TEMP."""
    temp = Path(tempfile.gettempdir()).resolve(strict=True)
    target = Path(path).resolve(strict=True)
    parts = target.relative_to(temp).parts
    if len(parts) > 3 or not parts or not parts[0].startswith("h454-appcontainer-synthetic-"):
        raise ValueError("SYNTHETIC_PATH_REQUIRED")

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    adv.GetSecurityInfo.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD,
                                    ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
                                    ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    adv.SetEntriesInAclW.argtypes = [wintypes.DWORD, ctypes.POINTER(_Explicit), ctypes.c_void_p,
                                    ctypes.POINTER(ctypes.c_void_p)]
    adv.SetSecurityInfo.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD,
                                    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    # MAXIMUM_ALLOWED suppresses propagation to existing descendants.
    handle = kernel.CreateFileW(str(target), 0x02000000, 7, None, 3, 0x02200000, None)
    if not handle or handle == ctypes.c_void_p(-1).value:
        raise OSError(ctypes.get_last_error(), "SYNTHETIC_OPEN_FAILED")
    old_acl, descriptor, new_acl = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
    try:
        if adv.GetSecurityInfo(handle, 1, 4, None, None, ctypes.byref(old_acl), None,
                               ctypes.byref(descriptor)) != 0 or not old_acl:
            raise RuntimeError("SYNTHETIC_GET_ACL_FAILED")
        entry = _Explicit(0x00120089 if read_only else 0x001301BF, 4 if revoke else 1,
                          3 if inherit else 0, _Trustee(None, 0, 0, 0, sid))
        if adv.SetEntriesInAclW(1, ctypes.byref(entry), old_acl, ctypes.byref(new_acl)) != 0:
            raise RuntimeError("SYNTHETIC_EDIT_ACL_FAILED")
        if adv.SetSecurityInfo(handle, 1, 4, None, None, new_acl, None) != 0:
            raise RuntimeError("SYNTHETIC_SET_ACL_FAILED")
    finally:
        if new_acl:
            kernel.LocalFree(new_acl)
        if descriptor:
            kernel.LocalFree(descriptor)
        kernel.CloseHandle(handle)
