"""Bounded stdio protocol for an already isolated personal file adapter.

The trusted caller provisions the AppContainer, verifies the bundle and
starts its job-owned process. This channel never receives a relay bearer.
"""
from __future__ import annotations

import json
import threading
import time
import uuid
from typing import Any

from device_fabric.windows_appcontainer_terminal import AppContainerTerminal, MAX_WRITE
from device_fabric.windows_personal_commander_transport import MAX_FRAME, TOOLS, _unique
from device_fabric.windows_personal_commander_pipe import PersonalPipeDenied


class PersonalAppContainerPipe:
    """One serialized request at a time; ambiguous effects are never retried."""

    def __init__(self, process: AppContainerTerminal, roots: list[str], *, timeout: float = 15.0):
        if (not isinstance(process, AppContainerTerminal)
            or type(roots) is not list or not 1 <= len(roots) <= 5
            or any(type(root) is not str or not 1 <= len(root) <= 2048 for root in roots)
            or type(timeout) not in (int, float) or not 1 <= timeout <= 120):
            raise PersonalPipeDenied("personal_pipe_denied")
        self._process = process
        self._timeout = float(timeout)
        self._lock = threading.Lock()
        self._buffer = bytearray()
        self._closed = False
        self.tools: list[dict[str, Any]] = []
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

    def _write(self, frame: dict[str, Any]) -> None:
        raw = json.dumps(frame, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n"
        if len(raw) > MAX_FRAME or self._closed:
            raise PersonalPipeDenied("personal_pipe_denied")
        deadline = time.monotonic() + self._timeout
        for offset in range(0, len(raw), MAX_WRITE):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise PersonalPipeDenied("personal_pipe_denied")
            self._process.write(raw[offset:offset + MAX_WRITE], timeout=min(remaining, 10.0))

    def _read(self) -> dict[str, Any]:
        deadline = time.monotonic() + self._timeout
        while True:
            marker = self._buffer.find(b"\n")
            if marker >= 0:
                if marker > MAX_FRAME:
                    raise PersonalPipeDenied("personal_pipe_denied")
                raw = bytes(self._buffer[:marker])
                del self._buffer[:marker + 1]
                try:
                    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique,
                        parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
                    if type(value) is not dict:
                        raise ValueError()
                    return value
                except Exception:
                    raise PersonalPipeDenied("personal_pipe_denied") from None
            if len(self._buffer) > MAX_FRAME:
                raise PersonalPipeDenied("personal_pipe_denied")
            chunk = self._process.read()
            if type(chunk) is not bytes:
                raise PersonalPipeDenied("personal_pipe_denied")
            self._buffer.extend(chunk)
            if chunk:
                continue
            if self._process.poll() is not None or time.monotonic() >= deadline:
                raise PersonalPipeDenied("personal_pipe_denied")
            time.sleep(min(0.02, max(0.0, deadline - time.monotonic())))

    def dispatch(self, name: str, args: dict) -> dict:
        try:
            if type(name) is not str or name not in TOOLS or type(args) is not dict:
                raise ValueError()
            with self._lock:
                if self._closed:
                    raise ValueError()
                ident = uuid.uuid4().hex
                self._write({"type": "call", "id": ident, "name": name, "args": args})
                response = self._read()
                if (set(response) != {"type", "id", "result"} or response["type"] != "result"
                    or response["id"] != ident or type(response["result"]) is not dict
                    or type(response["result"].get("content")) is not list):
                    raise ValueError()
                return response["result"]
        except Exception:
            self.close()
            raise PersonalPipeDenied("personal_pipe_denied") from None

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._process.close()
