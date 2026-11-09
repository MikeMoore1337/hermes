"""Dormant signed, bounded Linux original-host one-shot process executor.

This is NOT a service or MCP tool. The owner-approved native agent must
construct it from protected LOCAL config, under a non-root OS identity whose
cgroup, filesystem ACL and network egress limits have been independently
verified. No shell is involved; Python/Node executables remain powerful and
MUST NOT receive broad host privileges merely because their argv is signed.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import sys
import time
from typing import Callable

from device_fabric.linux_native_files import LinuxNativeFiles
from device_fabric.native_effect_admission import (
    NativeEffectAdmission, AdmissionDenied,
)

SCHEMA = "h454-native-process-v1"
MAX_REQUEST_BYTES = 8192
MAX_ARG_COUNT = 16
MAX_ARG_BYTES = 4096
MAX_TOTAL_ARG_BYTES = 8192
MAX_WALL_SECONDS = 30
MAX_STDOUT_BYTES = 16 * 1024
MAX_STDERR_BYTES = 16 * 1024
CHUNK_BYTES = 4096


class NativeProcessDenied(ValueError):
    """Sanitized denial: never echo commands, paths, credentials or output."""


@dataclass(frozen=True, slots=True)
class LocalProcessPolicy:
    """Trusted on-host configuration; never deserialize from MCP arguments."""

    private_home: Path
    executable_paths: frozenset[str]
    isolation_verified: Callable[[], bool]


def _unique_object(pairs):
    out = {}
    for name, value in pairs:
        if name in out:
            raise NativeProcessDenied("native_process_denied")
        out[name] = value
    return out


def _request(payload: bytes) -> tuple[list[str], int]:
    if type(payload) is not bytes or not 0 < len(payload) <= MAX_REQUEST_BYTES:
        raise NativeProcessDenied("native_process_denied")
    try:
        data = json.loads(
            payload.decode("utf-8"), object_pairs_hook=_unique_object,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        canonical = json.dumps(data, sort_keys=True, ensure_ascii=True,
                               separators=(",", ":")).encode("ascii")
    except (ValueError, UnicodeError, TypeError, OverflowError):
        raise NativeProcessDenied("native_process_denied") from None
    if (type(data) is not dict or set(data) != {"schema", "argv", "timeout_seconds"}
        or data["schema"] != SCHEMA or type(data["argv"]) is not list
        or not 1 <= len(data["argv"]) <= MAX_ARG_COUNT
        or type(data["timeout_seconds"]) is not int
        or not 1 <= data["timeout_seconds"] <= MAX_WALL_SECONDS
        or canonical != payload):
        raise NativeProcessDenied("native_process_denied")
    argv = data["argv"]
    try:
        sizes = [len(value.encode("utf-8")) for value in argv]
    except (AttributeError, UnicodeError, TypeError):
        raise NativeProcessDenied("native_process_denied") from None
    if (any(type(v) is not str or not 0 < size <= MAX_ARG_BYTES
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in v)
            for v, size in zip(argv, sizes))
        or sum(sizes) > MAX_TOTAL_ARG_BYTES):
        raise NativeProcessDenied("native_process_denied")
    return argv, data["timeout_seconds"]


def encode_process_request(argv: list[str], timeout_seconds: int) -> bytes:
    """Canonical request bytes for an independently owner-reviewed issuer.

    This only serializes data; it does not create or sign an owner grant.
    """
    payload = json.dumps({"schema": SCHEMA, "argv": argv,
                          "timeout_seconds": timeout_seconds},
                         sort_keys=True, ensure_ascii=True,
                         separators=(",", ":")).encode("ascii")
    _request(payload)
    return payload


class LinuxNativeOneShotProcess:
    """Bounded single command rooted in one preapproved native project."""

    def __init__(self, files: LinuxNativeFiles,
                 admission: NativeEffectAdmission,
                 policy: LocalProcessPolicy):
        if (type(files) is not LinuxNativeFiles
            or type(admission) is not NativeEffectAdmission
            or type(policy) is not LocalProcessPolicy
            or type(policy.executable_paths) is not frozenset
            or not 1 <= len(policy.executable_paths) <= 12
            or not callable(policy.isolation_verified)
            or not isinstance(policy.private_home, Path)):
            raise NativeProcessDenied("native_process_denied")
        self._files = files
        self._admission = admission
        self._policy = policy

    def _preflight(self, executable: str) -> None:
        if (sys.platform != "linux" or not hasattr(os, "geteuid")
            or os.geteuid() == 0 or self._files._root_fd < 0
            or executable not in self._policy.executable_paths):
            raise NativeProcessDenied("native_process_denied")
        try:
            enabled = self._policy.isolation_verified()
            home = self._policy.private_home
            info = home.lstat()
            exe = Path(executable)
            binary = exe.lstat()
            if (enabled is not True or not home.is_absolute()
                or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077 or home.is_symlink()
                or not exe.is_absolute() or exe.is_symlink()
                or exe.resolve(strict=True) != exe
                or not stat.S_ISREG(binary.st_mode) or binary.st_mode & 0o022
                or not os.access(executable, os.X_OK)):
                raise NativeProcessDenied("native_process_denied")
            # Check that original root remains a pinned open directory.
            if not stat.S_ISDIR(os.fstat(self._files._root_fd).st_mode):
                raise NativeProcessDenied("native_process_denied")
        except Exception:
            raise NativeProcessDenied("native_process_denied") from None

    @staticmethod
    def _terminate_group(proc: subprocess.Popen[bytes]) -> None:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError:
            pass
        try:
            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=3)
        except (OSError, subprocess.TimeoutExpired):
            raise NativeProcessDenied("native_process_denied") from None

    def _capture(self, proc: subprocess.Popen[bytes], timeout_seconds: int) -> tuple[int, bytes]:
        stdout = bytearray()
        stderr_bytes = 0
        deadline = time.monotonic() + timeout_seconds
        with selectors.DefaultSelector() as selector:
            if proc.stdout is None or proc.stderr is None:
                raise NativeProcessDenied("native_process_denied")
            for stream in (proc.stdout, proc.stderr):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
            while proc.poll() is None or selector.get_map():
                self._admission.check_active()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise NativeProcessDenied("native_process_denied")
                for key, _ in selector.select(timeout=min(0.1, remaining)):
                    stream = key.fileobj
                    chunk = os.read(stream.fileno(), CHUNK_BYTES)
                    if not chunk:
                        selector.unregister(stream)
                    elif stream is proc.stdout:
                        if len(stdout) + len(chunk) > MAX_STDOUT_BYTES:
                            raise NativeProcessDenied("native_process_denied")
                        stdout.extend(chunk)
                    else:
                        stderr_bytes += len(chunk)
                        if stderr_bytes > MAX_STDERR_BYTES:
                            raise NativeProcessDenied("native_process_denied")
        return proc.wait(timeout=1), bytes(stdout)

    def run(self, frame: bytes, payload: bytes, *,
            now: int | None = None) -> dict[str, object]:
        """Run the exact signed argv once; no network, shell or replay.

        A committed UUID is permanently consumed even for a child start
        failure, timeout, output overflow, nonzero exit, or crash. The
        returned stdout is capped UTF-8; stderr is never exposed.
        """
        argv, timeout_seconds = _request(payload)
        self._preflight(argv[0])
        try:
            identity, effect = self._admission.reserve_effect(
                frame, payload, now=now)
        except AdmissionDenied:
            raise NativeProcessDenied("native_process_denied") from None
        proc = None
        completed = False
        terminated = False
        try:
            if (effect.action != "process_run" or effect.relative != ""
                or effect.project != self._files.project):
                raise NativeProcessDenied("native_process_denied")
            self._preflight(argv[0])
            self._admission.check_active()
            if time.time() > effect.expires_at:
                raise NativeProcessDenied("native_process_denied")
            launcher = Path(__file__).with_name("linux_native_child.py").resolve(strict=True)
            if (launcher.is_symlink() or not launcher.is_file()
                or not stat.S_ISREG(launcher.stat().st_mode)):
                raise NativeProcessDenied("native_process_denied")
            safe_env = {
                "HOME": str(self._policy.private_home),
                "PATH": "/usr/bin:/bin",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PYTHONNOUSERSITE": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PIP_NO_INDEX": "1",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_TERMINAL_PROMPT": "0",
            }
            # /proc/self/fd binds cwd to the reviewed original root FD,
            # not a raceable path string or a Docker workspace clone.
            root_fd = self._files._root_fd
            proc = subprocess.Popen(
                [sys.executable, "-I", "-B", str(launcher),
                 str(os.getpid()), str(effect.expires_at), *argv],
                cwd=f"/proc/self/fd/{root_fd}",
                pass_fds=(root_fd,),
                env=safe_env, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                shell=False, close_fds=True, start_new_session=True,
            )
            returncode, out = self._capture(proc, timeout_seconds)
            try:
                output = out.decode("utf-8", "strict")
            except UnicodeError:
                raise NativeProcessDenied("native_process_denied") from None
            if self._admission.complete(identity, success=True) != "RECORDED":
                raise NativeProcessDenied("native_process_denied")
            completed = True
            return {
                "status": "finished", "project": self._files.project,
                "exit_code": returncode, "stdout": output,
                "stdout_sha256": hashlib.sha256(out).hexdigest(),
                "operation_id": effect.operation_id,
            }
        except Exception:
            # Terminate the process GROUP before any potentially blocking
            # SQLite outcome write. A revoked/timed-out child must not keep
            # running while the replay ledger acquires its lock.
            if proc is not None:
                try:
                    self._terminate_group(proc)
                    terminated = True
                except Exception:
                    pass
            # Errors and stderr may contain secrets. Never disclose them.
            try:
                self._admission.complete(identity, success=False)
            except Exception:
                pass
            raise NativeProcessDenied("native_process_denied") from None
        finally:
            if proc is not None:
                try:
                    # On BaseException or incomplete termination, still kill
                    # the group even if the direct child already exited.
                    if (not completed and not terminated) or proc.poll() is None:
                        self._terminate_group(proc)
                finally:
                    if proc.stdout is not None:
                        proc.stdout.close()
                    if proc.stderr is not None:
                        proc.stderr.close()
