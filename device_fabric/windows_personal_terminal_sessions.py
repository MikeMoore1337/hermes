"""Bounded terminal sessions for a trusted personal Windows worker.

The caller must provision and verify the AppContainer and approved directory.
This class does not install, pair, grant access, or expose a network listener.
"""
from __future__ import annotations

import codecs
import os
import threading
import time
from typing import Callable

from device_fabric.windows_appcontainer_terminal import AppContainerTerminal

MAX_SESSIONS = 8
MAX_RETAINED = 32
MAX_OUTPUT = 512 * 1024
MAX_RESPONSE_CHARS = 60_000
MAX_WAIT_MS = 30_000
TOOLS = frozenset({"start_process", "read_process_output", "interact_with_process",
                   "force_terminate", "list_sessions"})


def _result(text: str, *, error: bool = False) -> dict:
    return {"content": [{"type": "text", "text": text}], "isError": error}


def _integer(value, minimum: int, maximum: int) -> bool:
    return type(value) is int and minimum <= value <= maximum


class _Session:
    def __init__(self, terminal, encoding: str):
        self.terminal = terminal
        self.data = ""
        self.bytes_seen = 0
        self.decoder = codecs.getincrementaldecoder(encoding)(errors="replace")
        self.finalized = False
        self.cursor = 0
        self.overflow = False
        self.failed = False
        self.lock = threading.RLock()
        self.stop = threading.Event()


class PersonalTerminalSessions:
    """Dispatch a narrow BRC terminal subset to separately job-owned shells."""

    def __init__(self, sid: int, root: str, *, factory: Callable = AppContainerTerminal,
                 clock: Callable = time.monotonic, pause: Callable = time.sleep,
                 encoding: str | None = None):
        if (type(sid) is not int or sid <= 0 or type(root) is not str or not root
            or not all(callable(value) for value in (factory, clock, pause))):
            raise ValueError("personal_terminal_denied")
        if encoding is not None and (type(encoding) is not str or not 1 <= len(encoding) <= 40):
            raise ValueError("personal_terminal_denied")
        try:
            self._encoding = codecs.lookup(encoding or ("oem" if os.name == "nt" else "utf-8")).name
        except LookupError:
            raise ValueError("personal_terminal_denied") from None
        self._sid, self._root, self._factory = sid, root, factory
        self._clock, self._pause = clock, pause
        self._sessions: dict[int, _Session] = {}
        self._closed = False

    def _collect(self, session: _Session) -> None:
        for _ in range(8):
            chunk = session.terminal.read()
            if not chunk:
                return
            if type(chunk) is not bytes or session.bytes_seen + len(chunk) > MAX_OUTPUT:
                session.overflow = True
                session.terminal.close()
                raise ValueError()
            session.bytes_seen += len(chunk)
            session.data += session.decoder.decode(chunk, final=False)

    def _drain(self, session: _Session) -> None:
        """Drain bounded output even when the client is not polling."""
        while not session.stop.is_set():
            try:
                with session.lock:
                    if session.stop.is_set() or session.overflow:
                        return
                    self._collect(session)
                    if session.terminal.poll() is not None:
                        self._collect(session)
                        if not session.finalized:
                            session.data += session.decoder.decode(b"", final=True)
                            session.finalized = True
                        return
            except Exception:
                with session.lock:
                    session.failed = True
                    session.terminal.close()
                return
            session.stop.wait(0.05)

    def _wait(self, session: _Session, timeout_ms: int) -> int | None:
        deadline = self._clock() + timeout_ms / 1000
        with session.lock:
            previous = len(session.data)
            quiet_until = self._clock() + 0.2 if session.cursor < previous else None
        while True:
            with session.lock:
                if session.failed:
                    raise ValueError()
                self._collect(session)
                status = session.terminal.poll()
                if status is not None:
                    self._collect(session)
                    if not session.finalized:
                        session.data += session.decoder.decode(b"", final=True)
                        session.finalized = True
                    return status
                now = self._clock()
                if len(session.data) > previous:
                    quiet_until = now + 0.2
                    previous = len(session.data)
            if now >= deadline or (quiet_until is not None and now >= quiet_until):
                return None
            self._pause(min(0.05, max(0.0, deadline - now)))

    def _session(self, value) -> tuple[int, _Session]:
        if not _integer(value, 1, 2_147_483_647) or value not in self._sessions:
            raise ValueError()
        return value, self._sessions[value]

    def _output(self, session: _Session, offset: int, length: int) -> str:
        with session.lock:
            if offset == 0:
                pending = session.data[session.cursor:]
                lines = pending.splitlines(keepends=True)
                # JSON ASCII encoding can expand an astral character to 12 bytes;
                # bound each reply independently of the larger retained buffer.
                selected = "".join(lines[:length])[:MAX_RESPONSE_CHARS]
                session.cursor += len(selected)
                return selected
            lines = session.data.splitlines(keepends=True)
            start = max(0, len(lines) + offset) if offset < 0 else offset
            return "".join(lines[start:start + length])[:MAX_RESPONSE_CHARS]

    def dispatch(self, name: str, args: dict) -> dict:
        try:
            if self._closed or name not in TOOLS or type(args) is not dict:
                raise ValueError()
            if name == "list_sessions":
                if args:
                    raise ValueError()
                active = []
                for pid, session in self._sessions.items():
                    with session.lock:
                        if not session.overflow and not session.failed and session.terminal.poll() is None:
                            active.append(str(pid))
                return _result("Active sessions: " + ", ".join(active) if active else "No active sessions")
            if name == "start_process":
                if set(args) - {"command", "timeout_ms", "shell", "origin", "verbose_timing"}:
                    raise ValueError()
                command, timeout = args.get("command"), args.get("timeout_ms")
                if (type(command) is not str or not 0 < len(command) <= 4096 or "\x00" in command
                    or not _integer(timeout, 0, MAX_WAIT_MS)
                    or args.get("shell") not in (None, "cmd", "cmd.exe")):
                    raise ValueError()
                active_count = 0
                for item in self._sessions.values():
                    with item.lock:
                        active_count += int(not item.overflow and not item.failed and item.terminal.poll() is None)
                if active_count >= MAX_SESSIONS:
                    raise ValueError()
                if len(self._sessions) >= MAX_RETAINED:
                    for old_pid, old in self._sessions.items():
                        with old.lock:
                            if old.overflow or old.failed or old.terminal.poll() is not None:
                                old.stop.set()
                                old.terminal.close()
                                del self._sessions[old_pid]
                                break
                    else:
                        raise ValueError()
                terminal = self._factory(self._sid, self._root, command=command)
                pid = getattr(terminal, "pid", None)
                if not _integer(pid, 1, 2_147_483_647) or pid in self._sessions:
                    terminal.close()
                    raise ValueError()
                session = _Session(terminal, self._encoding)
                self._sessions[pid] = session
                threading.Thread(target=self._drain, args=(session,), daemon=True).start()
                try:
                    status = self._wait(session, timeout)
                    output = self._output(session, 0, 1000)
                except Exception:
                    del self._sessions[pid]
                    session.stop.set()
                    terminal.close()
                    raise
                state = "running" if status is None else "exited with code " + str(status)
                return _result(f"Process {pid} {state}\n{output}", error=status is not None and status != 0)
            pid, session = self._session(args.get("pid"))
            if name == "force_terminate":
                if set(args) != {"pid"}:
                    raise ValueError()
                session.stop.set()
                with session.lock:
                    session.terminal.close()
                del self._sessions[pid]
                return _result(f"Terminated session {pid}")
            if session.overflow or session.failed:
                raise ValueError()
            if name == "interact_with_process":
                if set(args) - {"pid", "input", "timeout_ms", "wait_for_prompt", "verbose_timing"}:
                    raise ValueError()
                value, timeout = args.get("input"), args.get("timeout_ms", 8000)
                wait = args.get("wait_for_prompt", True)
                if (type(value) is not str or "\x00" in value or type(wait) is not bool
                    or not _integer(timeout, 0, MAX_WAIT_MS) or session.terminal.poll() is not None):
                    raise ValueError()
                payload = (value if value.endswith("\n") else value + "\n").encode(self._encoding)
                if not 0 < len(payload) <= 4096:
                    raise ValueError()
                session.terminal.write(payload)
                status = self._wait(session, timeout if wait else 0)
                output = self._output(session, 0, 1000)
                return _result(output or ("Process is running" if status is None else f"Exited with code {status}"),
                               error=status is not None and status != 0)
            if name == "read_process_output":
                if set(args) - {"pid", "timeout_ms", "offset", "length", "verbose_timing"}:
                    raise ValueError()
                timeout, offset, length = args.get("timeout_ms", 5000), args.get("offset", 0), args.get("length", 1000)
                if (not _integer(timeout, 0, MAX_WAIT_MS) or not _integer(offset, -MAX_OUTPUT, MAX_OUTPUT)
                    or not _integer(length, 1, 2000)):
                    raise ValueError()
                wait = timeout if offset == 0 and session.cursor >= len(session.data) else 0
                status = self._wait(session, wait)
                output = self._output(session, offset, length)
                return _result(output or ("Process is running" if status is None else f"Exited with code {status}"),
                               error=status is not None and status != 0)
            raise ValueError()
        except Exception:
            return _result("H454_PERSONAL_TERMINAL_DENIED", error=True)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            for session in self._sessions.values():
                try:
                    session.stop.set()
                    with session.lock:
                        session.terminal.close()
                except Exception:
                    pass
        finally:
            self._sessions.clear()
