"""Bounded read-only Windows project search using the existing Win32 broker."""
from __future__ import annotations

import base64
from collections import deque
from contextlib import contextmanager
import ntpath
import os
import unicodedata

from scripts import h15_native_windows_read as native

MAX_QUERY_BYTES = 96
MAX_ENTRIES = 512
MAX_DEPTH = 4
MAX_MATCHES = 64
MAX_CONTENT_BYTES = 2 * 1024 * 1024


@contextmanager
def _locked_directory(project: str, relative: str):
    """Keep every ancestor open against rename through directory enumeration."""
    root, _ = native.build_request(project, "", "stat")
    parts = relative.split("\\") if relative else []
    if len(parts) > 64:
        raise native.NativeReadRefused("search_path_denied")
    api = native._winapi()
    handles = []
    try:
        expected_root = ntpath.normcase(ntpath.normpath(root))
        path = root
        for index in range(len(parts) + 1):
            if index:
                _, path = native.build_request(project, "\\".join(parts[:index]), "stat")
            handle = native._opened(api, path, content=False, lock_rename=True)
            handles.append(handle)
            info = native._metadata(api, handle)
            final = native._final_path(api, handle)
            expected = ntpath.normcase(ntpath.normpath(path))
            if (not info.dwFileAttributes & native.FILE_ATTRIBUTE_DIRECTORY
                or final != expected
                or (index == 0 and final != expected_root)
                or (index and not final.startswith(expected_root + "\\"))):
                raise native.NativeReadRefused("search_path_denied")
        yield api, path, expected_root
    finally:
        for handle in reversed(handles):
            api.CloseHandle(handle)


def search(project: str, query: str, *, mode: str, relative_root: str) -> dict:
    try:
        if (type(query) is not str or type(mode) is not str or type(relative_root) is not str
            or mode not in ("names", "content") or not query.strip()
            or unicodedata.normalize("NFC", query) != query
            or len(query.encode("utf-8")) > MAX_QUERY_BYTES
            or any(unicodedata.category(char).startswith("C") for char in query)):
            raise native.NativeReadRefused("search_input_denied")
        native.build_request(project, relative_root, "stat")
        wanted = query.casefold()
        queue = deque([(relative_root, 0)])
        matches = []
        entries_scanned = bytes_scanned = 0
        truncated = False
        while queue and not truncated:
            directory, depth = queue.popleft()
            with _locked_directory(project, directory) as (api, path, root):
                names = []
                with os.scandir(path) as iterator:
                    for entry in iterator:
                        if entries_scanned >= MAX_ENTRIES:
                            truncated = True
                            break
                        entries_scanned += 1
                        names.append(entry.name)
                for name in sorted(names, key=lambda value: (value.casefold(), value)):
                    relative = directory + "\\" + name if directory else name
                    try:
                        _, child_path = native.build_request(project, relative, "stat")
                        child = native._opened(api, child_path, content=False, lock_rename=True)
                        try:
                            info = native._metadata(api, child)
                            expected = ntpath.normcase(ntpath.normpath(child_path))
                            if native._final_path(api, child) != expected or not expected.startswith(root + "\\"):
                                continue
                            is_dir = bool(info.dwFileAttributes & native.FILE_ATTRIBUTE_DIRECTORY)
                            if not is_dir and (info.nNumberOfLinks != 1 or
                                ntpath.splitext(name)[1].lower() not in native.ALLOWED_EXTENSIONS):
                                continue
                            if is_dir:
                                if mode == "names" and wanted in name.casefold():
                                    matches.append({"path": relative, "kind": "directory"})
                                if depth < MAX_DEPTH:
                                    queue.append((relative, depth + 1))
                                else:
                                    truncated = True
                            elif mode == "names":
                                if wanted in name.casefold():
                                    matches.append({"path": relative, "kind": "file"})
                            else:
                                size = (info.nFileSizeHigh << 32) | info.nFileSizeLow
                                remaining = MAX_CONTENT_BYTES - bytes_scanned
                                if size > native.MAX_FILE_BYTES or remaining < native.MAX_FILE_BYTES + 1:
                                    truncated = True
                                    continue
                                try:
                                    result = native.handle_native_request(project, relative, "read")
                                    data = base64.b64decode(result["data"], validate=True)
                                except (native.NativeReadRefused, OSError, ValueError):
                                    # A failed read may already have consumed bytes; stop the search.
                                    truncated = True
                                    break
                                bytes_scanned += len(data)
                                if b"\x00" not in data:
                                    try:
                                        text = data.decode("utf-8")
                                    except UnicodeError:
                                        text = ""
                                    for number, line in enumerate(text.splitlines(), 1):
                                        if wanted in line.casefold():
                                            matches.append({"path": relative, "line": number})
                                            if len(matches) > MAX_MATCHES:
                                                truncated = True
                                                break
                        finally:
                            api.CloseHandle(child)
                    except (native.NativeReadRefused, OSError, ValueError, UnicodeError):
                        continue
                    if len(matches) > MAX_MATCHES:
                        truncated = True
                        break
        return {"status": "ok", "project": project, "relative_root": relative_root,
                "mode": mode, "matches": matches[:MAX_MATCHES], "truncated": truncated,
                "entries_scanned": entries_scanned, "bytes_scanned": bytes_scanned}
    except (native.NativeReadRefused, OSError, ValueError, TypeError, UnicodeError):
        raise native.NativeReadRefused("native_search_denied") from None
