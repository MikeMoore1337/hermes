#!/usr/bin/env python3
"""Offline safety check: pinned read-only Hermes external writing reference.

Git text worktrees can be checked out as CRLF on Windows. Allow this one
explicitly marked textual representation only when it normalizes to the
exact same pinned Git blob. Any mixed/newline-manipulated or changed
content is rejected.
"""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "docs/operations/external-skill-sources.json"


def blob_sha(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest()


def matches_pinned_blob(data: bytes, expected: str, policy: str = "exact") -> bool:
    if type(data) is not bytes or type(expected) is not str:
        return False
    if policy not in ("exact", "consistent_crlf_text"):
        return False
    if blob_sha(data) == expected:
        return True
    if policy != "consistent_crlf_text":
        return False
    # Only a *fully CRLF* text checkout is an allowed equivalent.
    # Mixed LF/CRLF, stray CR, NUL and changes to actual words fail closed.
    if (not data or b"\x00" in data or b"\r\n" not in data
            or data.count(b"\r\n") != data.count(b"\n")):
        return False
    normalized = data.replace(b"\r\n", b"\n")
    return b"\r" not in normalized and blob_sha(normalized) == expected


def main() -> None:
    manifest = json.loads(LOCK.read_text(encoding="utf-8"))
    assert manifest["schema_version"] == 1
    for entry in manifest["files"]:
        path = (ROOT / entry["local"]).resolve()
        if ROOT not in path.parents or not path.is_file():
            raise ValueError(f"Unsafe/missing path: {entry['local']}")
        if manifest["upstream_references"][entry["source"]] != entry["commit"]:
            raise ValueError(f"Source is not pinned: {entry['local']}")
        data = path.read_bytes()
        if not matches_pinned_blob(data, entry["git_blob_sha"],
                                   entry.get("newline_policy", "exact")):
            raise ValueError(f"Unexpected source content: {entry['local']}")
    print(f"Verified {len(manifest['files'])} external doc reference(s).")


if __name__ == "__main__":
    main()
