"""H-22: local, read-only prerequisites for a *separate* OSV offline pilot.

This never executes OSV, opens a network connection, or establishes DB freshness.
All public output is sanitized; only explicitly selected local files are read.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import tomllib
import zipfile
from pathlib import Path, PurePosixPath

VERSION = "2.7.0"
# SHA256 and asset size from official GitHub v2.7.0 release metadata (Linux amd64).
BINARY_SHA256 = "160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b"
BINARY_SIZE = 57_725_088
LOCKFILE_LIMIT = 8_000_000
DB_ARCHIVE_LIMIT = 300_000_000
DB_EXPANDED_LIMIT = 3_000_000_000
DB_MEMBER_LIMIT = 32_000_000
DB_MEMBERS_LIMIT = 200_000
ECOSYSTEMS = {"uv.lock": "PyPI", "package-lock.json": "npm"}


class Denied(ValueError):
    """Only fixed error codes may reach output."""


def _file(path: Path, limit: int) -> int:
    if path.is_symlink() or not path.is_file():
        raise Denied("missing_or_symlink_input")
    size = path.stat().st_size
    if size <= 0 or size > limit:
        raise Denied("oversized_or_empty_input")
    return size


def _digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _binary(path: Path) -> None:
    if _file(path, BINARY_SIZE) != BINARY_SIZE:
        raise Denied("binary_size_mismatch")
    with path.open("rb") as source:
        header = source.read(20)
    # ELF64, little-endian, x86-64. Header alone is not executable provenance.
    if header[:6] != b"\x7fELF\x02\x01" or header[18:20] != b"\x3e\x00":
        raise Denied("unexpected_binary_architecture")
    if _digest(path) != BINARY_SHA256:
        raise Denied("binary_digest_mismatch")


def _lockfile(path: Path) -> tuple[str, int, str]:
    kind = path.name
    if kind not in ECOSYSTEMS:
        raise Denied("unsupported_lockfile")
    _file(path, LOCKFILE_LIMIT)
    raw = path.read_bytes()
    try:
        if kind == "uv.lock":
            parsed = tomllib.loads(raw.decode("utf-8"))
            items = parsed["package"]
            if not isinstance(items, list):
                raise ValueError()
            packages = [p for p in items if isinstance(p, dict)
                        and isinstance(p.get("name"), str)
                        and isinstance(p.get("version"), str)]
            if len(packages) != len(items):
                raise ValueError()
        else:
            parsed = json.loads(raw)
            if (not isinstance(parsed, dict)
                    or parsed.get("lockfileVersion") not in (2, 3)
                    or not isinstance(parsed.get("packages"), dict)):
                raise ValueError()
            packages = [p for name, p in parsed["packages"].items()
                        if name.startswith("node_modules/")]
            if any(not isinstance(p, dict) or not isinstance(p.get("version"), str)
                   for p in packages):
                raise ValueError()
    except (UnicodeError, KeyError, ValueError, TypeError, tomllib.TOMLDecodeError):
        raise Denied("invalid_lockfile") from None
    return ECOSYSTEMS[kind], len(packages), hashlib.sha256(raw).hexdigest()


def _database(path: Path) -> tuple[int, str]:
    _file(path, DB_ARCHIVE_LIMIT)
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if not 0 < len(infos) <= DB_MEMBERS_LIMIT:
                raise Denied("invalid_db_index")
            total = 0
            json_files = []
            for member in infos:
                part = PurePosixPath(member.filename)
                if (member.is_dir() or member.filename.startswith("/")
                        or ".." in part.parts or "\\" in member.filename
                        or member.flag_bits & 1 or member.file_size > DB_MEMBER_LIMIT):
                    raise Denied("unsafe_db_archive")
                total += member.file_size
                if total > DB_EXPANDED_LIMIT:
                    raise Denied("expanded_db_too_large")
                if member.filename.endswith(".json"):
                    json_files.append(member)
            if not json_files:
                raise Denied("no_advisory_json")
            # Parse one entry and verify its CRC, not the entire DB inventory.
            sample = json_files[0]
            with archive.open(sample) as entry:
                advisory = json.loads(entry.read(DB_MEMBER_LIMIT + 1))
            if not isinstance(advisory, dict) or not isinstance(advisory.get("id"), str):
                raise Denied("invalid_advisory_sample")
    except (zipfile.BadZipFile, EOFError, UnicodeError, ValueError,
            RuntimeError, OSError, json.JSONDecodeError):
        raise Denied("invalid_db_archive") from None
    return len(json_files), _digest(path)


def assess(binary: Path, db_root: Path, lockfile: Path) -> dict:
    ecosystem, packages, lock_sha = _lockfile(lockfile)
    _binary(binary)
    db = db_root / "osv-scanner" / ecosystem / "all.zip"
    entries, db_sha = _database(db)
    return {
        "status": "INCONCLUSIVE",
        "reason": "inputs_prepared_scanner_not_executed",
        "scanner_version_pinned": VERSION,
        "binary_hash_matches_release_metadata": True,
        "publisher_provenance_verified": False,
        "db_archive_structurally_checked": True,
        "db_member_count": entries,
        "db_sha256": db_sha,
        "db_snapshot_utc": None,
        "db_freshness_verified": False,
        "db_completeness_verified": False,
        "lockfile_sha256": lock_sha,
        "lockfile_ecosystem": ecosystem,
        "lockfile_packages_parsed": packages,
        "scanner_executed": False,
        "scanner_extraction_verified": False,
        "offline_network_boundary_verified": False,
        "pilot_inputs_ready": True,
        "resident_agent_allowed": False,
        "auto_upgrade_allowed": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="H-22 read-only OSV offline pilot preflight")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--db-root", type=Path)
    parser.add_argument("--lockfile", type=Path)
    args = parser.parse_args(argv)
    if not args.check:
        print(json.dumps({"status": "NOT_EXECUTED", "scanner_executed": False}))
        return 0
    try:
        if args.binary is None or args.db_root is None or args.lockfile is None:
            raise Denied("missing_inputs")
        output = assess(args.binary, args.db_root, args.lockfile)
    except (Denied, OSError, RecursionError):
        output = {"status": "INCONCLUSIVE", "reason": "preflight_unavailable_or_invalid",
                  "pilot_inputs_ready": False, "scanner_executed": False,
                  "resident_agent_allowed": False, "auto_upgrade_allowed": False}
    print(json.dumps(output, sort_keys=True))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
