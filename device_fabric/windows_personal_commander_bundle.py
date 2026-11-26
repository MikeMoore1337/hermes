"""Deterministic local bundle manifest for a personal Windows Commander.

Only an already selected bundle directory is inspected. This module never
downloads, extracts, executes, installs, or reads a project or credential.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat

SCHEMA = "h454-personal-commander-bundle-v1"
MAX_ENTRIES = 200_000
MAX_BYTES = 2 * 1024 * 1024 * 1024
MAX_FILE = 128 * 1024 * 1024
MAX_MANIFEST = 32 * 1024 * 1024
REPARSE = 0x400


class PersonalBundleDenied(ValueError):
    """Constant denial without file names or local installation paths."""


def _reparse(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & REPARSE)


def _within(root: Path, item: Path) -> bool:
    try:
        base = os.path.normcase(str(root))
        target = os.path.normcase(str(item))
        return os.path.commonpath((base, target)) == base
    except (ValueError, OSError):
        return False


def _internal_target(root: Path, link: Path) -> Path:
    """Resolve links one component at a time without probing outside root."""
    remaining = list(link.relative_to(root).parts)
    current = root
    followed = 0
    while remaining:
        candidate = current / remaining.pop(0)
        info = candidate.lstat()
        if _reparse(info):
            followed += 1
            if followed > 40:
                raise ValueError()
            raw = os.readlink(candidate)
            if os.name == "nt" and raw.startswith("\\\\?\\"):
                if raw.startswith("\\\\?\\UNC\\"):
                    raise ValueError()
                raw = raw[4:]
            target = Path(raw)
            if not target.is_absolute():
                target = candidate.parent / target
            target = Path(os.path.abspath(target))
            if not _within(root, target):
                raise ValueError()
            remaining = list(target.relative_to(root).parts) + remaining
            current = root
        else:
            current = candidate
    return current


def manifest(root: Path) -> bytes:
    """Hash files and internal link targets without traversing links.

    Exact file/size/hash and root-relative resolved link targets are included;
    unexpected additions, missing files and link escape change verification.
    """
    try:
        if not isinstance(root, Path) or not root.is_absolute():
            raise ValueError()
        info = root.lstat()
        if _reparse(info) or not stat.S_ISDIR(info.st_mode):
            raise ValueError()
        canonical = root.resolve(strict=True)
        if os.path.normcase(str(canonical)) != os.path.normcase(str(root)):
            raise ValueError()
        entries = []
        total = 0
        stack = [root]
        while stack:
            directory = stack.pop()
            with os.scandir(directory) as iterator:
                children = sorted(iterator, key=lambda item: item.name)
            for item in children:
                if len(entries) >= MAX_ENTRIES or item.name in ("", ".", ".."):
                    raise ValueError()
                path = Path(item.path)
                relative = path.relative_to(root).as_posix()
                if len(relative.encode("utf-8")) > 4096:
                    raise ValueError()
                entry = path.lstat()
                if _reparse(entry):
                    target = _internal_target(canonical, path)
                    entries.append({"path": relative, "kind": "link",
                                    "target": target.relative_to(canonical).as_posix()})
                elif stat.S_ISDIR(entry.st_mode):
                    entries.append({"path": relative, "kind": "directory"})
                    stack.append(path)
                elif stat.S_ISREG(entry.st_mode) and 0 <= entry.st_size <= MAX_FILE:
                    total += entry.st_size
                    if total > MAX_BYTES:
                        raise ValueError()
                    digest = hashlib.sha256()
                    with path.open("rb") as stream:
                        before = os.fstat(stream.fileno())
                        while block := stream.read(1024 * 1024):
                            digest.update(block)
                        after = os.fstat(stream.fileno())
                    # Windows path stat and handle stat may report different
                    # synthetic execute bits for the same regular file.
                    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns")
                    if (not stat.S_ISREG(before.st_mode) or not stat.S_ISREG(after.st_mode)
                        or before.st_mode != after.st_mode
                        or any(getattr(entry, key) != getattr(before, key) or
                               getattr(before, key) != getattr(after, key) for key in fields)):
                        raise ValueError()
                    entries.append({"path": relative, "kind": "file", "size": entry.st_size,
                                    "sha256": digest.hexdigest()})
                else:
                    raise ValueError()
        entries.sort(key=lambda item: item["path"])
        raw = json.dumps({"schema": SCHEMA, "entries": entries}, sort_keys=True,
                         separators=(",", ":"), ensure_ascii=True).encode("ascii")
        if not entries or len(raw) > MAX_MANIFEST:
            raise ValueError()
        return raw
    except Exception:
        raise PersonalBundleDenied("personal_bundle_denied") from None


def verify(root: Path, expected_manifest: bytes, expected_sha256: str) -> str:
    """Return the pinned manifest digest only if current bundle bytes match."""
    try:
        if (type(expected_manifest) is not bytes or not 0 < len(expected_manifest) <= MAX_MANIFEST
            or type(expected_sha256) is not str or len(expected_sha256) != 64
            or any(char not in "0123456789abcdef" for char in expected_sha256)
            or hashlib.sha256(expected_manifest).hexdigest() != expected_sha256
            or manifest(root) != expected_manifest):
            raise ValueError()
        return expected_sha256
    except Exception:
        raise PersonalBundleDenied("personal_bundle_denied") from None
