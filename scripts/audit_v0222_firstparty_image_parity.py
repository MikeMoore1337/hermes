"""Opt-in offline comparison of extracted v0.22.2 first-party Python vs exact Git.

Only reads two explicitly supplied directory trees. Does not run upstream code,
Docker, model, shell command (except Git read-only metadata), or network.
Even perfect parity is NOT supply-chain attestation, CVE clearance or runtime GO.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath

from scripts.audit_v0222_python_surface import (
    UPSTREAM_COMMIT, SourceAuditDenied, _verified_git_filenames,
)

ROOTS = ("agent", "hermes_cli", "gateway", "cron", "plugins", "tools", "acp_adapter", "pm")
VENDOR_PREFIXES = {
    "python-3.14.7": "tools/python-3.14.7+20260901-linux-x64/",
    "node-26.7.0": "tools/node-26.7.0-linux-x64/",
    "npm-12.0.2": "tools/npm-12.0.2-linux-x64/",
}
IMAGE = ("nousresearch/hermes-agent@sha256:"
         "a11574b7fe8e1631d7d88d556677dac693bc058abf558cdeb899155688c1bf05")
MAX_FILES = 10_000
MAX_FILE_BYTES = 2_000_000
MAX_TOTAL_BYTES = 150_000_000


class ParityDenied(ValueError):
    """Fixed diagnostics, never include file content or arbitrary private paths."""


def _is_safe_name(name: str) -> bool:
    rel = PurePosixPath(name)
    return (type(name) is str and bool(rel.parts)
            and not rel.is_absolute() and ".." not in rel.parts
            and chr(92) not in name and name.endswith(".py")
            and rel.parts[0] in ROOTS)


def _read_file(root: Path, name: str) -> bytes:
    if not _is_safe_name(name):
        raise ParityDenied("unsafe_file_name")
    p = root.joinpath(*PurePosixPath(name).parts)
    if root.is_symlink() or any(part.is_symlink() for part in (p, *p.parents)
                                if part != root.parent):
        raise ParityDenied("symlink_denied")
    if not p.is_file() or p.stat().st_size > MAX_FILE_BYTES:
        raise ParityDenied("missing_or_oversized_file")
    with p.open("rb") as stream:
        raw = stream.read(MAX_FILE_BYTES + 1)
    if len(raw) > MAX_FILE_BYTES:
        raise ParityDenied("oversized_file")
    return raw


def _image_names(image: Path) -> list[str]:
    names: list[str] = []
    if image.is_symlink() or not image.is_dir():
        raise ParityDenied("invalid_image_snapshot")
    for root_name in ROOTS:
        directory = image / root_name
        if directory.is_symlink() or not directory.is_dir():
            raise ParityDenied("missing_image_scope")
        for base, subdirs, files in os.walk(directory, followlinks=False):
            if any((Path(base) / name).is_symlink() for name in subdirs):
                raise ParityDenied("symlinked_subdirectory")
            subdirs[:] = sorted(name for name in subdirs
                                if name not in ("__pycache__", ".git"))
            for file_name in sorted(files):
                if not file_name.endswith(".py"):
                    # Executable/tool distributions contain legitimate non-Python
                    # symlink files. They are not read or traversed here.
                    continue
                p = Path(base) / file_name
                if p.is_symlink():
                    raise ParityDenied("symlinked_python_file")
                rel = p.relative_to(image).as_posix()
                if not _is_safe_name(rel):
                    raise ParityDenied("unexpected_image_filename")
                names.append(rel)
                if len(names) > MAX_FILES:
                    raise ParityDenied("image_file_count_limit")
    return sorted(names)


def _fingerprint(stream: list[tuple[str, bytes]]) -> str:
    digest = hashlib.sha256()
    for name, raw in sorted(stream):
        digest.update(name.encode("utf-8") + b"\0" + hashlib.sha256(raw).digest())
    return digest.hexdigest()


def compare_trees(image: Path, upstream: Path, tracked: list[str]) -> dict:
    """Compare exact Python bytes and partition the embedded Python distribution."""
    if (image.is_symlink() or upstream.is_symlink()
            or not image.is_dir() or not upstream.is_dir()):
        raise ParityDenied("invalid_source_directories")
    relevant = [name for name in tracked if _is_safe_name(name)]
    if not relevant or len(tracked) != len(set(tracked)) or len(relevant) > MAX_FILES:
        raise ParityDenied("unbounded_or_duplicate_git_paths")
    if any(not isinstance(name, str) or not name.endswith(".py")
           or name.startswith(tuple(root + "/" for root in ROOTS))
           and not _is_safe_name(name) for name in tracked):
        raise ParityDenied("unsafe_tracked_git_paths")
    git_names = set(relevant)
    image_names = _image_names(image)
    image_set = set(image_names)
    unknown_extra = sorted(name for name in image_set - git_names
                           if not any(name.startswith(prefix) for prefix in VENDOR_PREFIXES.values()))
    absent = sorted(git_names - image_set)
    if unknown_extra or absent:
        raise ParityDenied("unexpected_or_missing_first_party_files")

    group_data: dict[str, dict] = {
        root: {"source_count": 0, "matching_count": 0} for root in ROOTS
    }
    matched = []
    vendor = []
    vendor_by_component = {key: 0 for key in VENDOR_PREFIXES}
    differing = 0
    total = 0
    for name in image_names:
        blob = _read_file(image, name)
        total += len(blob)
        if total > MAX_TOTAL_BYTES:
            raise ParityDenied("excessive_image_bytes")
        if name in git_names:
            source_blob = _read_file(upstream, name)
            total += len(source_blob)
            if total > MAX_TOTAL_BYTES:
                raise ParityDenied("excessive_source_bytes")
            root_name = PurePosixPath(name).parts[0]
            group_data[root_name]["source_count"] += 1
            if hashlib.sha256(blob).digest() == hashlib.sha256(source_blob).digest():
                group_data[root_name]["matching_count"] += 1
            else:
                differing += 1
            matched.append((name, blob))
        else:
            vendor.append((name, blob))
            for component, prefix in VENDOR_PREFIXES.items():
                if name.startswith(prefix):
                    vendor_by_component[component] += 1
                    break
    first_party = len(matched)
    report = {
        "schema": "hermes-h18-v0222-firstparty-byte-parity-v1",
        "status": "FIRST_PARTY_SUBSET_PARITY_NO_GO" if differing == 0 else "FIRST_PARTY_SOURCE_DRIFT",
        "upstream_commit_claim": UPSTREAM_COMMIT,
        "immutable_image_claim": IMAGE,
        "first_party_roots": list(ROOTS),
        "per_root_counts": group_data,
        "image_python_files_scanned": len(image_names),
        "tracked_first_party_python_files": first_party,
        "first_party_matching": first_party - differing,
        "first_party_differing": differing,
        "embedded_runtime_python_files_unattested": len(vendor),
        "embedded_vendor_python_file_counts": vendor_by_component,
        "embedded_vendor_prefixes": VENDOR_PREFIXES,
        "first_party_image_fingerprint": _fingerprint(matched),
        "vendor_source_fingerprint_unattested": _fingerprint(vendor),
        "complete_oci_filesystem_checked": False,
        "compiled_native_files_verified": False,
        "embedded_python_runtime_provenance_verified": False,
        "source_to_build_to_image_attestation_verified": False,
        "all_cve_fixed": False,
        "resident_agent_allowed": False,
    }
    return report


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="v0.22.2 extracted image vs pinned public source")
    ap.add_argument("--execute", action="store_true")
    ap.add_argument("--image-tree", type=Path)
    ap.add_argument("--source-tree", type=Path)
    args = ap.parse_args(argv)
    if not args.execute:
        print(json.dumps({"status": "NOT_EXECUTED", "resident_agent_allowed": False}))
        return 0
    try:
        if args.image_tree is None or args.source_tree is None:
            raise ParityDenied("missing_required_trees")
        # Checking HEAD and the tracked Git working tree is mandatory, not optional.
        tracked = _verified_git_filenames(args.source_tree)
        report = compare_trees(args.image_tree, args.source_tree, tracked)
    except (SourceAuditDenied, ParityDenied, OSError, ValueError, RecursionError):
        report = {"status": "INCONCLUSIVE", "resident_agent_allowed": False,
                  "error_code": "source_or_image_evidence_invalid"}
    print(json.dumps(report, sort_keys=True, ensure_ascii=True))
    # Parity is evidence only. Never exit 0 or authorize resident runtime.
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
