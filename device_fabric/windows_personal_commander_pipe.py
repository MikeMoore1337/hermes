"""Bounded local stdio channel to the personal Commander dispatcher.

The trusted worker starts the child inside its Windows job and supplies only
owner-configured roots. No bearer is sent to the child. A failed channel is
terminal for the worker so its job closes and outstanding children are reaped.
"""
from __future__ import annotations

import json
import queue
import subprocess
import threading
import uuid
from typing import Any

from device_fabric.windows_personal_commander_transport import MAX_FRAME, ADAPTER_TOOLS as TOOLS, _unique
from device_fabric.windows_personal_project_limits import MAX_PROJECT_ROOTS


class PersonalPipeDenied(ValueError):
    """Constant denial without commands, file contents or child diagnostics."""


class PersonalCommanderPipe:
    def __init__(self, process: subprocess.Popen, roots: list[str], *, timeout: float = 15.0):
        if (not isinstance(process, subprocess.Popen) or process.stdin is None or process.stdout is None
            or type(roots) is not list or not 1 <= len(roots) <= MAX_PROJECT_ROOTS
            or any(type(root) is not str or not 1 <= len(root) <= 2048 for root in roots)
            or type(timeout) not in (int, float) or not 1 <= timeout <= 120):
            raise PersonalPipeDenied("personal_pipe_denied")
        self._process = process
        self._timeout = float(timeout)
        self._lock = threading.Lock()
        self._messages: queue.Queue[bytes | None] = queue.Queue(maxsize=2)
        self._closed = False
        self.tools: list[dict[str, Any]] = []
        threading.Thread(target=self._reader, daemon=True).start()
        try:
            self._write({"type": "initialize", "roots": roots})
            ready = self._read()
            if (set(ready) != {"type", "tools"} or ready["type"] != "ready"
                or type(ready["tools"]) is not list or len(ready["tools"]) != len(TOOLS)
                or any(type(tool) is not dict or type(tool.get("name")) is not str for tool in ready["tools"])
                or {tool["name"] for tool in ready["tools"]} != TOOLS):
                raise ValueError()
            self.tools = ready["tools"]
        except Exception:
            self.close()
            raise PersonalPipeDenied("personal_pipe_denied") from None

    def _reader(self) -> None:
        try:
            while True:
                line = self._process.stdout.readline(MAX_FRAME + 2)
                if not line or len(line) > MAX_FRAME + 1 or not line.endswith(b"\n"):
                    self._messages.put(None, timeout=1)
                    return
                self._messages.put(line, timeout=1)
        except Exception:
            try:
                self._messages.put_nowait(None)
            except queue.Full:
                pass

    def _write(self, frame: dict[str, Any]) -> None:
        raw = json.dumps(frame, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n"
        if len(raw) > MAX_FRAME or self._closed:
            raise PersonalPipeDenied("personal_pipe_denied")
        result: queue.Queue[bool] = queue.Queue(maxsize=1)
        def write():
            try:
                if self._process.stdin.write(raw) != len(raw):
                    raise ValueError()
                self._process.stdin.flush()
                result.put(True)
            except Exception:
                result.put(False)
        threading.Thread(target=write, daemon=True).start()
        try:
            if result.get(timeout=self._timeout) is not True:
                raise ValueError()
        except Exception:
            try:
                self._process.kill()
            except Exception:
                pass
            raise PersonalPipeDenied("personal_pipe_denied") from None

    def _read(self, *, timeout: float | None = None) -> dict[str, Any]:
        try:
            raw = self._messages.get(timeout=self._timeout if timeout is None else timeout)
            if type(raw) is not bytes:
                raise ValueError()
            frame = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique,
                               parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
            if type(frame) is not dict:
                raise ValueError()
            return frame
        except Exception:
            self.close()
            raise PersonalPipeDenied("personal_pipe_denied") from None

    def dispatch(self, name: str, args: dict) -> dict:
        """One serialized request; never retry an ambiguous completed effect."""
        try:
            if type(name) is not str or name not in TOOLS or type(args) is not dict:
                raise ValueError()
            with self._lock:
                if self._closed:
                    raise ValueError()
                ident = uuid.uuid4().hex
                wait = self._timeout
                if name in {"start_process", "read_process_output", "interact_with_process"}:
                    requested = args.get("timeout_ms")
                    if type(requested) is int and 0 <= requested <= 120_000:
                        wait = min(125.0, max(wait, requested / 1000 + 5))
                self._write({"type": "call", "id": ident, "name": name, "args": args})
                result = self._read(timeout=wait)
                if (set(result) != {"type", "id", "result"} or result["type"] != "result"
                    or result["id"] != ident or type(result["result"]) is not dict
                    or type(result["result"].get("content")) is not list):
                    raise ValueError()
                return result["result"]
        except Exception:
            self.close()
            raise PersonalPipeDenied("personal_pipe_denied") from None

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            if self._process.stdin:
                self._process.stdin.close()
            self._process.wait(timeout=5)
        except Exception:
            try:
                self._process.kill()
                self._process.wait(timeout=5)
            except Exception:
                pass
        finally:
            if self._process.stdout:
                self._process.stdout.close()
