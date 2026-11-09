"""Dormant bounded Linux original-file search for Hermes Commander Stage 2A.

This is read-only and NOT registered as an MCP tool. Project roots are
supplied by a trusted local LinuxNativeFiles adapter, never remote input.
Every stat/read/descend reuses kernel openat2 no-follow path confinement.
Search results contain only relative paths and line numbers, NEVER file
contents, credentials, absolute host paths, subprocesses or terminal output.
"""
from __future__ import annotations

import base64
import binascii
from collections import deque
import itertools
from pathlib import PurePosixPath
import os
import stat
import unicodedata

from device_fabric.linux_native_files import (
    LinuxNativeFiles, NativeLinuxDenied, READ_EXTENSIONS, MAX_READ_BYTES,
    _relative,
)

MAX_PATTERN_BYTES = 96
MAX_ENTRIES = 512
MAX_DEPTH = 4
MAX_MATCHES = 64
MAX_CONTENT_BYTES = 2 * 1024 * 1024


class LinuxNativeSearch:
    """Read-only path and content discovery in exactly one pinned Linux root."""

    def __init__(self, files: LinuxNativeFiles):
        if type(files) is not LinuxNativeFiles:
            raise NativeLinuxDenied("native_linux_denied")
        self._files = files

    def search(self, query: str, *, mode: str = "names",
               relative_root: str = "") -> dict[str, object]:
        """Sanitize all source-filesystem errors before returning to MCP."""
        try:
            return self._search(query, mode=mode, relative_root=relative_root)
        except (OSError, UnicodeError, ValueError, binascii.Error):
            raise NativeLinuxDenied("native_linux_denied") from None

    def _search(self, query: str, *, mode: str,
                relative_root: str) -> dict[str, object]:
        """Search bounded literal text, case-insensitive, no regex or snippets.

        names: returns only safe file/directory names containing the query.
        content: returns relative file path + line number, no matching text.
        Truncated is true for depth/entry/byte/result budgets.
        """
        if (type(query) is not str or type(mode) is not str
            or mode not in ("names", "content")
            or unicodedata.normalize("NFC", query) != query
            or not query.strip()
            or any(unicodedata.category(char).startswith("C") for char in query)):
            raise NativeLinuxDenied("native_linux_denied")
        try:
            if len(query.encode("utf-8")) > MAX_PATTERN_BYTES:
                raise NativeLinuxDenied("native_linux_denied")
        except (UnicodeError, ValueError):
            raise NativeLinuxDenied("native_linux_denied") from None
        if relative_root:
            _relative(relative_root)
        elif relative_root != "":
            raise NativeLinuxDenied("native_linux_denied")

        wanted = query.casefold()
        found: list[dict[str, object]] = []
        entries_scanned = 0
        bytes_scanned = 0
        truncated = False
        queue: deque[tuple[str, int]] = deque([(relative_root, 0)])
        while queue and not truncated:
            directory, depth = queue.popleft()
            # Verify the subdirectory is really under the locally pinned root.
            fd = self._files._open(directory, directory=True)
            try:
                if not stat.S_ISDIR(os.fstat(fd).st_mode):
                    raise NativeLinuxDenied("native_linux_denied")
                names: list[str] = []
                with os.scandir(fd) as iterator:
                    for entry in itertools.islice(iterator, MAX_ENTRIES - entries_scanned + 1):
                        entries_scanned += 1
                        if entries_scanned > MAX_ENTRIES:
                            truncated = True
                            break
                        names.append(entry.name)
            finally:
                os.close(fd)
            names.sort(key=lambda name: (name.casefold(), name))
            for name in names:
                relative = directory + "/" + name if directory else name
                try:
                    _relative(relative)
                    meta = self._files.stat_file(relative)
                except (NativeLinuxDenied, OSError, ValueError):
                    # Secret names, symlinks, reparse-style paths, devices,
                    # hardlinks and inaccessible entries are not disclosed.
                    continue
                kind = meta["kind"]
                if kind == "directory":
                    if mode == "names" and wanted in name.casefold():
                        found.append({"path": relative, "kind": "directory"})
                    if depth < MAX_DEPTH:
                        queue.append((relative, depth + 1))
                    else:
                        truncated = True
                elif kind == "file" and PurePosixPath(name).suffix.lower() in READ_EXTENSIONS:
                    if mode == "names":
                        if wanted in name.casefold():
                            found.append({"path": relative, "kind": "file"})
                    else:
                        size = meta["size_bytes"]
                        if (type(size) is not int or size < 0 or size > MAX_READ_BYTES
                            or bytes_scanned + size > MAX_CONTENT_BYTES):
                            truncated = True
                            continue
                        try:
                            # A prior path stat can become stale. The reader
                            # enforces remaining bytes on the OPEN file fd.
                            remaining = MAX_CONTENT_BYTES - bytes_scanned
                            payload = self._files.read_file(
                                relative, max_bytes=min(MAX_READ_BYTES, remaining))
                            data = base64.b64decode(payload["data"], validate=True)
                            if len(data) > remaining:
                                raise NativeLinuxDenied("native_linux_denied")
                        except (NativeLinuxDenied, UnicodeError, ValueError, binascii.Error):
                            # A read can have occurred before a concurrent
                            # growth/IO error. Stop rather than repeatedly
                            # reading unaccounted bytes from unstable files.
                            truncated = True
                            break
                        # EVERY successful read counts, including binary and
                        # invalid UTF-8 that will not produce a match.
                        bytes_scanned += len(data)
                        if b"\x00" in data:
                            continue
                        try:
                            text = data.decode("utf-8")
                        except UnicodeError:
                            continue
                        for line_number, line in enumerate(text.splitlines(), 1):
                            if wanted in line.casefold():
                                found.append({"path": relative, "line": line_number})
                                if len(found) > MAX_MATCHES:
                                    truncated = True
                                    break
                if len(found) > MAX_MATCHES:
                    truncated = True
                    break
            # A scan that hits the cap may show only the first MAX_MATCHES.
        return {
            "status": "ok", "project": self._files.project,
            "relative_root": relative_root, "mode": mode,
            "matches": found[:MAX_MATCHES], "truncated": truncated,
            "entries_scanned": min(entries_scanned, MAX_ENTRIES),
            "bytes_scanned": bytes_scanned,
        }
