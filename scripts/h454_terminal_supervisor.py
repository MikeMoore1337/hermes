"""Linux session supervisor embedded in the pinned BRC agent at build time."""
import ctypes
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def main() -> int:
    try:
        parent = int(sys.argv[1])
        if parent <= 1 or len(sys.argv) < 3:
            raise ValueError("invalid parent or command")
        stopping = False

        def stop(_signal, _frame):
            nonlocal stopping
            stopping = True

        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(sig, stop)
        # Direct children remain unreaped until this supervisor examines them.
        signal.signal(signal.SIGCHLD, signal.SIG_DFL)
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(36, 1, 0, 0, 0) or libc.prctl(1, signal.SIGTERM, 0, 0, 0):
            raise OSError(ctypes.get_errno(), "session isolation unavailable")
        children = Path(f"/proc/{os.getpid()}/task/{os.getpid()}/children")
        children.read_text(encoding="ascii")
        if os.getppid() != parent or stopping:
            raise ValueError("parent unavailable")
        shell = subprocess.Popen(sys.argv[2:], start_new_session=True)
    except (OSError, ValueError, IndexError):
        print("HERMES_TERMINAL_SUPERVISOR_UNAVAILABLE", file=sys.stderr, flush=True)
        return 125

    exit_code = 125
    reported = False
    while True:
        if stopping:
            try:
                identifiers = children.read_text(encoding="ascii").split()
                for identifier in identifiers:
                    child = int(identifier)
                    if child <= 1:
                        raise ValueError("invalid child")
                    try:
                        os.kill(child, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            except (OSError, ValueError, UnicodeError):
                if not reported:
                    print("HERMES_TERMINAL_TERMINATION_INCOMPLETE", file=sys.stderr, flush=True)
                    reported = True
        try:
            while True:
                pid, status = os.waitpid(-1, os.WNOHANG)
                if not pid:
                    break
                if pid == shell.pid:
                    exit_code = (os.WEXITSTATUS(status) if os.WIFEXITED(status) else
                                 -os.WTERMSIG(status) if os.WIFSIGNALED(status) else 125)
                    shell.returncode = exit_code
        except ChildProcessError:
            if stopping:
                return 128 + signal.SIGTERM
            return 128 - exit_code if exit_code < 0 else exit_code
        time.sleep(0.05)


if __name__ == "__main__":
    sys.exit(main())
