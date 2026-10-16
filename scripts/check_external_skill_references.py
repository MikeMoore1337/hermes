#!/usr/bin/env python3
"""Offline safety check: pinned read-only Hermes external writing reference."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "docs/operations/external-skill-sources.json"


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
        actual = hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest()
        if actual != entry["git_blob_sha"]:
            raise ValueError(f"Unexpected source content: {entry['local']}")
    print(f"Verified {len(manifest['files'])} external doc reference(s).")


if __name__ == "__main__":
    main()
