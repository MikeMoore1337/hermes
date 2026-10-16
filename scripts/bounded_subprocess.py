"""Bounded, concurrent subprocess pipe capture for offline Docker inspectors.

No shell. Output is byte-limited *while read*, not after communicate().
Failures never echo subprocess stdout/stderr. Windows and Linux supported.
"""
from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
from typing import Any

STDERR_LIMIT = 16_384
CHUNK_SIZE = 8192


class BoundedProcessError(RuntimeError):
    """Stable, sanitized error code with no process output."""


def _stop_tree(proc: subprocess.Popen[bytes]) -> None:
    """Stop the process group, including possible inherited-pipe children."""
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL, check=False, timeout=4,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass
    else:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError:
            pass
    if proc.poll() is None:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        raise BoundedProcessError("child_not_reaped") from None


def run_bounded(
    args: list[str], *, timeout: float, stdout_limit: int,
    stderr_limit: int = STDERR_LIMIT, env: dict[str, str] | None = None,
    **_unused: Any,
) -> subprocess.CompletedProcess[bytes]:
    """Read stdout/stderr concurrently under strict byte and wall-time budgets.

    Result stdout is capped and validated as UTF-8. Stderr is never returned.
    Any limit, timeout, nonzero code, or malformed encoding is fail-closed.
    """
    if (type(args) is not list or not args
            or any(type(a) is not str or not a for a in args)
            or type(timeout) not in (int, float) or not 0 < timeout <= 180
            or type(stdout_limit) is not int or not 0 < stdout_limit <= 1_000_000
            or type(stderr_limit) is not int or not 0 < stderr_limit <= 65_536
            or (env is not None and (type(env) is not dict
                or len(env) > 32 or any(type(k) is not str
                    or not k or "=" in k or "\x00" in k
                    or type(v) is not str or "\x00" in v
                    or len(v) > 8192 for k, v in env.items())))):
        raise BoundedProcessError("invalid_subprocess_budget")
    flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    try:
        proc = subprocess.Popen(
            args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, shell=False, close_fds=True,
            start_new_session=(os.name != "nt"), creationflags=flags,
            env=env,
        )
    except OSError:
        raise BoundedProcessError("child_start_failed") from None

    stop = threading.Event()
    exceeded = threading.Event()
    outputs = [bytearray(), bytearray()]
    failures: list[bool] = []
    streams = (proc.stdout, proc.stderr)
    assert streams[0] is not None and streams[1] is not None

    def reader(index: int, limit: int) -> None:
        try:
            while not stop.is_set():
                chunk = streams[index].read1(CHUNK_SIZE)
                if not chunk:
                    return
                if len(outputs[index]) + len(chunk) > limit:
                    exceeded.set()
                    return
                outputs[index].extend(chunk)
        except (OSError, ValueError):
            failures.append(True)
            exceeded.set()

    threads = [
        threading.Thread(target=reader, args=(0, stdout_limit), daemon=True),
        threading.Thread(target=reader, args=(1, stderr_limit), daemon=True),
    ]
    for thread in threads:
        thread.start()

    started = time.monotonic()
    reason = None
    try:
        while True:
            if exceeded.is_set():
                reason = "output_limit_exceeded"
                break
            if time.monotonic() - started > timeout:
                reason = "child_timeout"
                break
            if proc.poll() is not None:
                break
            exceeded.wait(0.02)

        if reason is None:
            for thread in threads:
                thread.join(timeout=max(0.0, min(1.0, timeout - (time.monotonic() - started))))
            if any(thread.is_alive() for thread in threads):
                reason = "inherited_pipe_not_closed"
            elif exceeded.is_set():
                reason = "output_limit_exceeded"
            elif failures:
                reason = "pipe_read_failed"
            elif proc.returncode:
                reason = "child_nonzero_exit"
            else:
                try:
                    outputs[0].decode("utf-8", "strict")
                    outputs[1].decode("utf-8", "strict")
                except UnicodeError:
                    reason = "invalid_output_encoding"
        if reason is not None:
            _stop_tree(proc)
            raise BoundedProcessError(reason)
        return subprocess.CompletedProcess(["<redacted command>"], proc.returncode, bytes(outputs[0]), b"")
    finally:
        stop.set()
        if proc.poll() is None:
            _stop_tree(proc)
        for stream in streams:
            try:
                stream.close()
            except OSError:
                pass
        for thread in threads:
            thread.join(timeout=1)
