"""Dormant local read dispatcher for ORIGINAL Linux projects (Hermes #454).

This library composes reviewed LinuxNativeFiles/LinuxNativeSearch capabilities
with an exact, bounded tool-call contract. It does NOT register a Hermes MCP
tool, start an agent, pair a device, issue an authorization, open a network
listener, write to host files, or execute any subprocess.

The existing authenticated Hermes MCP relay must independently authenticate
owner/device and route only to an owner-approved native host identity.
The dispatcher root map and revocation callback are trusted LOCAL inputs.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import threading
from typing import Callable

from device_fabric.linux_native_files import (
    LinuxNativeFiles, NativeLinuxDenied, MAX_READ_BYTES,
    MAX_LIST_ENTRIES, READ_EXTENSIONS, _relative,
)
from device_fabric.linux_native_search import (
    LinuxNativeSearch, MAX_ENTRIES, MAX_MATCHES, MAX_CONTENT_BYTES,
)
from device_fabric.native_effect_grants import DEVICE

MAX_FRAME_BYTES = 4096
MAX_SESSION_CALLS = 64
MAX_SESSION_READS = 16
MAX_SESSION_SEARCHES = 4
CALL_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
STAT = "native_file_stat"
READ = "native_file_read"
LIST = "native_file_list"
SEARCH = "native_file_search"
TOOLS = frozenset({STAT, READ, LIST, SEARCH})


class NativeLinuxReadDenied(ValueError):
    """Generic denial; never echo original roots, source data or secrets."""


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise NativeLinuxReadDenied("native_linux_read_denied")
        result[name] = value
    return result


def parse_call(frame: bytes) -> tuple[str, str, dict[str, str]]:
    """Validate exact in-memory call data; never decide owner permissions."""
    if type(frame) is not bytes or not 0 < len(frame) <= MAX_FRAME_BYTES:
        raise NativeLinuxReadDenied("native_linux_read_denied")
    try:
        data = json.loads(frame.decode("utf-8"), object_pairs_hook=_unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if (type(data) is not dict
            or set(data) != {"type", "id", "tool", "args"}
            or data["type"] != "call"
            or type(data["id"]) is not str
            or CALL_ID.fullmatch(data["id"]) is None
            or type(data["tool"]) is not str or data["tool"] not in TOOLS
            or type(data["args"]) is not dict):
            raise NativeLinuxReadDenied("native_linux_read_denied")
        args = data["args"]
        if data["tool"] in {STAT, READ, LIST}:
            expected = {"project", "relative"}
        else:
            expected = {"project", "query", "mode", "relative_root"}
        if set(args) != expected or any(type(v) is not str for v in args.values()):
            raise NativeLinuxReadDenied("native_linux_read_denied")
        if type(args["project"]) is not str:
            raise NativeLinuxReadDenied("native_linux_read_denied")
        if data["tool"] in {STAT, READ, LIST}:
            _relative(args["relative"], allow_root=data["tool"] != READ)
    except (NativeLinuxReadDenied, NativeLinuxDenied, ValueError, TypeError,
            UnicodeError, RecursionError, KeyError, OverflowError):
        raise NativeLinuxReadDenied("native_linux_read_denied") from None
    return data["id"], data["tool"], args


def _check_result(out: object, *, project: str,
                  tool: str, args: dict[str, str]) -> dict[str, object]:
    """Verify native adapter output and restrict all advertised fields."""
    if type(out) is not dict or out.get("status") != "ok" or out.get("project") != project:
        raise NativeLinuxReadDenied("native_linux_read_denied")
    if tool == STAT:
        if (set(out) != {"status", "project", "relative", "action",
                         "kind", "size_bytes"}
            or out["action"] != "stat"
            or out["relative"] != args["relative"]
            or out["kind"] not in {"file", "directory"}):
            raise NativeLinuxReadDenied("native_linux_read_denied")
        size = out["size_bytes"]
        if (out["kind"] == "file" and
            (type(size) is not int or not 0 <= size <= 2**53 - 1)):
            raise NativeLinuxReadDenied("native_linux_read_denied")
        if out["kind"] == "directory" and size is not None:
            raise NativeLinuxReadDenied("native_linux_read_denied")
    elif tool == READ:
        if (set(out) != {"status", "project", "relative", "action",
                         "kind", "size_bytes", "encoding", "sha256", "data"}
            or out["action"] != "read" or out["kind"] != "file"
            or out["relative"] != args["relative"]
            or out["encoding"] != "base64"
            or type(out["size_bytes"]) is not int
            or not 0 <= out["size_bytes"] <= MAX_READ_BYTES
            or type(out["data"]) is not str
            or len(out["data"]) > 4 * ((MAX_READ_BYTES + 2) // 3)
            or type(out["sha256"]) is not str
            or re.fullmatch(r"[0-9a-f]{64}", out["sha256"]) is None):
            raise NativeLinuxReadDenied("native_linux_read_denied")
        try:
            data = base64.b64decode(out["data"], validate=True)
        except (binascii.Error, ValueError):
            raise NativeLinuxReadDenied("native_linux_read_denied") from None
        if (len(data) != out["size_bytes"]
            or hashlib.sha256(data).hexdigest() != out["sha256"]):
            raise NativeLinuxReadDenied("native_linux_read_denied")
    elif tool == LIST:
        if (set(out) != {"status", "project", "relative", "action",
                         "kind", "entries", "truncated"}
            or out["action"] != "list" or out["kind"] != "directory"
            or out["relative"] != args["relative"]
            or type(out["truncated"]) is not bool
            or type(out["entries"]) is not list
            or len(out["entries"]) > MAX_LIST_ENTRIES):
            raise NativeLinuxReadDenied("native_linux_read_denied")
        names: set[str] = set()
        for entry in out["entries"]:
            if (type(entry) is not dict or set(entry) != {"name", "kind"}
                or type(entry["name"]) is not str
                or entry["kind"] not in {"directory", "file"}
                or entry["name"] in names):
                raise NativeLinuxReadDenied("native_linux_read_denied")
            full = args["relative"] + "/" + entry["name"] if args["relative"] else entry["name"]
            try:
                _relative(full)
            except NativeLinuxDenied:
                raise NativeLinuxReadDenied("native_linux_read_denied") from None
            if entry["kind"] == "file":
                from pathlib import PurePosixPath
                if PurePosixPath(entry["name"]).suffix.lower() not in READ_EXTENSIONS:
                    raise NativeLinuxReadDenied("native_linux_read_denied")
            # Linux source filesystems are case sensitive. README.md and
            # readme.md are two legitimate distinct entries.
            names.add(entry["name"])
    else:
        if (set(out) != {"status", "project", "relative_root", "mode",
                         "matches", "truncated", "entries_scanned",
                         "bytes_scanned"}
            or out["relative_root"] != args["relative_root"]
            or out["mode"] != args["mode"]
            or type(out["truncated"]) is not bool
            or type(out["entries_scanned"]) is not int
            or not 0 <= out["entries_scanned"] <= MAX_ENTRIES
            or type(out["bytes_scanned"]) is not int
            or not 0 <= out["bytes_scanned"] <= MAX_CONTENT_BYTES
            or type(out["matches"]) is not list
            or len(out["matches"]) > MAX_MATCHES):
            raise NativeLinuxReadDenied("native_linux_read_denied")
        for match in out["matches"]:
            if (type(match) is not dict or type(match.get("path")) is not str):
                raise NativeLinuxReadDenied("native_linux_read_denied")
            try:
                _relative(match["path"])
            except NativeLinuxDenied:
                raise NativeLinuxReadDenied("native_linux_read_denied") from None
            if args["relative_root"] and not match["path"].startswith(args["relative_root"] + "/"):
                raise NativeLinuxReadDenied("native_linux_read_denied")
            if out["mode"] == "names":
                if set(match) != {"path", "kind"} or match["kind"] not in {"file", "directory"}:
                    raise NativeLinuxReadDenied("native_linux_read_denied")
            else:
                if (set(match) != {"path", "line"} or type(match["line"]) is not int
                    or match["line"] < 1):
                    raise NativeLinuxReadDenied("native_linux_read_denied")
    return out


class LinuxOriginalReadDispatcher:
    """One short-lived authenticated transport session, no host authority."""

    def __init__(self, *, device_id: str,
                 local_roots: dict[str, LinuxNativeFiles],
                 is_device_revoked: Callable[[], bool]):
        if (type(device_id) is not str or DEVICE.fullmatch(device_id) is None
            or type(local_roots) is not dict or not 1 <= len(local_roots) <= 5
            or not callable(is_device_revoked)):
            raise NativeLinuxReadDenied("native_linux_read_denied")
        roots: dict[str, LinuxNativeFiles] = {}
        for project, files in local_roots.items():
            if (type(project) is not str or type(files) is not LinuxNativeFiles
                or files.project != project or files._root_fd < 0):
                raise NativeLinuxReadDenied("native_linux_read_denied")
            roots[project] = files
        self.device_id = device_id
        self._roots = roots
        self._revoked = is_device_revoked
        self._seen: set[str] = set()
        self._calls = 0
        self._reads = 0
        self._searches = 0
        self._lock = threading.Lock()

    def _active(self) -> None:
        try:
            value = self._revoked()
        except Exception:
            raise NativeLinuxReadDenied("native_linux_read_denied") from None
        if type(value) is not bool or value:
            raise NativeLinuxReadDenied("native_linux_read_denied")

    def call(self, frame: bytes) -> dict[str, object]:
        """Validate, rate-limit, execute one READ, then check revocation."""
        identity, tool, args = parse_call(frame)
        with self._lock:
            if identity in self._seen or self._calls >= MAX_SESSION_CALLS:
                raise NativeLinuxReadDenied("native_linux_read_denied")
            self._seen.add(identity)
            self._calls += 1
            if tool == READ:
                self._reads += 1
                if self._reads > MAX_SESSION_READS:
                    raise NativeLinuxReadDenied("native_linux_read_denied")
            if tool == SEARCH:
                self._searches += 1
                if self._searches > MAX_SESSION_SEARCHES:
                    raise NativeLinuxReadDenied("native_linux_read_denied")
        self._active()
        files = self._roots.get(args["project"])
        if files is None:
            raise NativeLinuxReadDenied("native_linux_read_denied")
        try:
            if tool == STAT:
                result = files.stat_file(args["relative"])
            elif tool == READ:
                result = files.read_file(args["relative"])
            elif tool == LIST:
                result = files.list_directory(args["relative"])
            else:
                result = LinuxNativeSearch(files).search(
                    args["query"], mode=args["mode"],
                    relative_root=args["relative_root"])
            safe = _check_result(result, project=args["project"],
                                 tool=tool, args=args)
            self._active()
            return {"status": "ok", "tool": tool, "id": identity,
                    "result": safe}
        except (NativeLinuxDenied, NativeLinuxReadDenied, OSError, UnicodeError,
                ValueError, TypeError):
            raise NativeLinuxReadDenied("native_linux_read_denied") from None
