"""Dormant native Linux child launcher with kernel resource and privilege guards.

This is NOT a service, MCP tool, or host authorization mechanism. Only the
reviewed local native process adapter should start this pinned script under an
already OS-confined unprivileged identity. No shell and no network setup.
"""
from __future__ import annotations

import ctypes
import math
import os
from pathlib import Path
import signal
import socket
import stat
import sys
import time

try:
    import resource
except ImportError:  # Importable on Windows to keep cross-platform tests safe.
    resource = None

# Hard ceilings; OS cgroup controls and egress isolation remain mandatory.
CPU_SECONDS = 20
ADDRESS_BYTES = 768 * 1024 * 1024
FILE_BYTES = 1024 * 1024
OPEN_FILES = 64
PR_SET_NO_NEW_PRIVS = 38
PR_SET_PDEATHSIG = 1


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    try:
        if (sys.platform != "linux" or resource is None
            or not hasattr(os, "geteuid") or os.geteuid() == 0
            or len(args) < 5):
            raise ValueError("unavailable")
        parent_pid = int(args[0])
        expiry = int(args[1])
        gate_fd = int(args[2])
        deadline = float(args[3])
        program = args[4]
        monotonic_now = time.monotonic()
        # A valid grant at parent admission may expire during child startup.
        # The child must also refuse execution AFTER its actual expiry.
        if (parent_pid < 2 or os.getppid() != parent_pid
            or expiry < time.time() or not 3 <= gate_fd < OPEN_FILES
            or not math.isfinite(deadline)
            or not monotonic_now < deadline <= monotonic_now + 30
            or type(program) is not str or not program.startswith("/")):
            raise ValueError("invalid_parent_or_program")
        info = Path(program).lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022
            or not os.access(program, os.X_OK)):
            raise ValueError("unsafe_program")
        # This process is the private process supervisor's immediate child.
        # Prevent gaining privileges via setuid binaries and terminate if
        # the supervisor disappears unexpectedly before/during execution.
        libc = ctypes.CDLL(None, use_errno=True)
        libc.prctl.restype = ctypes.c_int
        if (libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
            or libc.prctl(PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) != 0
            or os.getppid() != parent_pid):
            raise OSError("native_no_new_privileges_required")
        os.umask(0o077)
        resource.setrlimit(resource.RLIMIT_CPU, (CPU_SECONDS, CPU_SECONDS))
        resource.setrlimit(resource.RLIMIT_AS, (ADDRESS_BYTES, ADDRESS_BYTES))
        resource.setrlimit(resource.RLIMIT_FSIZE, (FILE_BYTES, FILE_BYTES))
        resource.setrlimit(resource.RLIMIT_NOFILE, (OPEN_FILES, OPEN_FILES))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        # The trusted parent rechecks revocation AFTER child setup, as close
        # as possible to execve. No remote request can send GO on this
        # private AF_UNIX socketpair; only the authenticated local parent
        # holds the peer. EOF, timeout, or anything except exact G is denial.
        with socket.socket(fileno=gate_fd) as gate:
            gate.settimeout(3.0)
            gate.sendall(b"READY")
            if gate.recv(1) != b"G":
                raise ValueError("native_parent_authorization_absent")
        # Grant and signed wall budget may expire during prctl, rlimits,
        # revocation handshake or scheduling. The parent verifies the same
        # monotonic deadline before GO; the child checks it again at the
        # final instruction before execve.
        if time.time() > expiry or time.monotonic() >= deadline:
            raise ValueError("grant_or_deadline_expired_before_exec")
        os.execve(program, args[4:], os.environ.copy())
    except (OSError, ValueError, OverflowError):
        # Do not emit untrusted argv, environment, paths, or exception details.
        print("H454_NATIVE_PROCESS_CHILD_REFUSED", file=sys.stderr, flush=True)
        return 125
    return 125


if __name__ == "__main__":
    raise SystemExit(main())
