"""Keep a personal Windows worker and its subprocesses in one OS job.

The worker attaches itself before launching the Commander adapter. Closing
the job at worker exit terminates remaining descendants. This module never
starts a process or changes any job belonging to the calling desktop app.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import os


class PersonalJobDenied(ValueError):
    """Constant denial without OS details or process names."""


class _Basic(ctypes.Structure):
    _fields_ = [("per_process_time", ctypes.c_int64), ("per_job_time", ctypes.c_int64),
                ("flags", wintypes.DWORD), ("min_working_set", ctypes.c_size_t),
                ("max_working_set", ctypes.c_size_t), ("active_limit", wintypes.DWORD),
                ("affinity", ctypes.c_size_t), ("priority", wintypes.DWORD),
                ("scheduling", wintypes.DWORD)]


class _Io(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in
                ("read_operations", "write_operations", "other_operations",
                 "read_bytes", "write_bytes", "other_bytes")]


class _Extended(ctypes.Structure):
    _fields_ = [("basic", _Basic), ("io", _Io),
                ("process_memory", ctypes.c_size_t), ("job_memory", ctypes.c_size_t),
                ("peak_process_memory", ctypes.c_size_t), ("peak_job_memory", ctypes.c_size_t)]


_owned_job = None


def attach_current_worker() -> None:
    """Attach once before launching children; keep the handle until exit.

    Must run only in the dedicated worker process: closing the last handle
    terminates all members, including that worker. Nested job restrictions can
    make assignment impossible, in which case no child may be launched.
    """
    global _owned_job
    if os.name != "nt" or _owned_job is not None:
        raise PersonalJobDenied("personal_job_denied")
    job = None
    try:
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        kernel.CreateJobObjectW.restype = wintypes.HANDLE
        kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                                   ctypes.c_void_p, wintypes.DWORD]
        kernel.SetInformationJobObject.restype = wintypes.BOOL
        kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        job = kernel.CreateJobObjectW(None, None)
        if not job:
            raise ValueError()
        info = _Extended()
        info.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if (not kernel.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info))
            or not kernel.AssignProcessToJobObject(job, kernel.GetCurrentProcess())):
            raise ValueError()
        _owned_job = job
        job = None
    except Exception:
        raise PersonalJobDenied("personal_job_denied") from None
    finally:
        if job:
            kernel.CloseHandle(job)
