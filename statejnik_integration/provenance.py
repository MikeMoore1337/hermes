"""Hermes H-12: exact file inventory of the owner's licensed statejnik copy.

This never runs the imported agent/skill or accesses the network. The manifest
records the fixed upstream source commit and per-file hashes. It is a checksum
inventory, not a signature or proof of the private licensing agreement.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

UPSTREAM_URL = "https://github.com/artemiimillier/statejnik"
UPSTREAM_COMMIT = "4de2944a31eaffdba4463cdbea115191cb551300"
ROOT = Path(__file__).resolve().parents[1] / "third_party" / "statejnik"
MANIFEST = ROOT / "HERMES_SOURCE_MANIFEST.json"
SCHEMA = "hermes-h12-statejnik-source-manifest-v1"
MAX_FILES = 150
MAX_FILE_BYTES = 1_000_000
MAX_TOTAL_BYTES = 4_000_000


class ProvenanceDenied(ValueError):
    """No raw external bytes are echoed on provenance verification failure."""


def inventory(root: Path = ROOT) -> dict[str, str]:
    if not root.is_dir() or root.is_symlink():
        raise ProvenanceDenied("source_directory_invalid")
    entries: dict[str, str] = {}
    total = 0
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ProvenanceDenied("source_symlink_denied")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ProvenanceDenied("source_special_file_denied")
        rel = path.relative_to(root).as_posix()
        if rel == MANIFEST.name:
            continue
        if rel.startswith(".git/") or "__pycache__" in path.parts:
            raise ProvenanceDenied("source_untracked_or_generated")
        data = path.read_bytes()
        if len(data) > MAX_FILE_BYTES:
            raise ProvenanceDenied("source_file_oversize")
        total += len(data)
        if total > MAX_TOTAL_BYTES or len(entries) >= MAX_FILES:
            raise ProvenanceDenied("source_inventory_oversize")
        entries[rel] = hashlib.sha256(data).hexdigest()
    if not entries or "LICENSE" not in entries or "skills/statejnik/SKILL.md" not in entries:
        raise ProvenanceDenied("source_incomplete")
    return entries


def metadata(root: Path = ROOT) -> dict[str, object]:
    return {
        "schema": SCHEMA,
        "upstream_repository": UPSTREAM_URL,
        "upstream_commit": UPSTREAM_COMMIT,
        "author": "Artemii Millier (artemiimillier)",
        "rights_basis": "owner_attested_full_private_license_2026-10-16",
        "rights_document_independently_verified": False,
        "upstream_signature_verified": False,
        "runtime_execution_authorized": False,
        "external_providers_authorized": False,
        "automatic_publication_authorized": False,
        "files_sha256": inventory(root),
    }


def verify(root: Path = ROOT) -> dict[str, object]:
    path = root / MANIFEST.name
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 32_768:
        raise ProvenanceDenied("manifest_invalid")
    try:
        recorded = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeError, OSError):
        raise ProvenanceDenied("manifest_invalid") from None
    expected = metadata(root)
    if type(recorded) is not dict or recorded != expected:
        raise ProvenanceDenied("vendor_source_mismatch")
    return {"status": "VENDORED_BYTES_MATCH_MANIFEST", "file_count": len(expected["files_sha256"]),
            "upstream_commit": UPSTREAM_COMMIT, "signature_verified": False,
            "resident_agent_allowed": False}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="statejnik vendored source manifest")
    parser.add_argument("--write-manifest", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.write_manifest:
            if MANIFEST.exists() or MANIFEST.is_symlink():
                raise ProvenanceDenied("manifest_already_exists")
            MANIFEST.write_text(json.dumps(metadata(), ensure_ascii=False, indent=2,
                                           sort_keys=True) + "\n", encoding="utf-8")
            result = verify()
        else:
            result = verify()
    except ProvenanceDenied as exc:
        print(json.dumps({"status": "REJECTED", "reason": str(exc),
                          "resident_agent_allowed": False}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
