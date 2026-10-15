"""Compare three official pinned vendor archives to the offline v0.22.1 image.

No downloads, archive extraction, execution of vendor tools or production writes.
Archive SHA256 is the exact lock value from upstream commit 297552a9.
This is byte evidence for selected files, NOT signed source-to-image provenance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tarfile
from pathlib import Path
from typing import Any, Callable

from .bounded_subprocess import BoundedProcessError, run_bounded
from . import verify_v0221_core_python as core
from .verify_v0221_local_image import IMAGE

ARCHIVES = {
    "python": (
        "0ab3305457051cd3e7c031857e005f1bda17c218a1990567dacaaac6dd1d14f0",
        {
            "python/bin/python3.14": "python_binary",
            "python/lib/python3.14/LICENSE.txt": "python_license",
        },
    ),
    "node": (
        "982aa24dd8be4c889c6a8ab337ddff3b0896645b20f4239356e80552c16277ee",
        {
            "node-v26.7.0-linux-x64/bin/node": "node_binary",
            "node-v26.7.0-linux-x64/LICENSE": "node_license",
        },
    ),
    "npm": (
        "5dbb86c71d07a1957f2e90734092dd6a58bdcd9ebc2d8d41ca1c6e6a21d364e1",
        {
            "package/bin/npm-cli.js": "npm_bin",
            "package/package.json": "npm_manifest",
            "package/LICENSE": "npm_license",
        },
    ),
}
IMAGE_FILES = {
    "python_binary": "/opt/hermes/tools/python-3.14.7+20260901-linux-x64/bin/python3.14",
    "python_license": "/opt/hermes/tools/python-3.14.7+20260901-linux-x64/lib/python3.14/LICENSE.txt",
    "node_binary": "/opt/hermes/tools/node-26.7.0-linux-x64/bin/node",
    "node_license": "/opt/hermes/tools/node-26.7.0-linux-x64/LICENSE",
    "npm_bin": "/opt/hermes/tools/npm-12.0.2-linux-x64/lib/node_modules/npm/bin/npm-cli.js",
    "npm_manifest": "/opt/hermes/tools/npm-12.0.2-linux-x64/lib/node_modules/npm/package.json",
    "npm_license": "/opt/hermes/tools/npm-12.0.2-linux-x64/lib/node_modules/npm/LICENSE",
}
INSPECTOR = r"""
import hashlib
import json
from pathlib import Path

paths = {
    "python_binary": "/opt/hermes/tools/python-3.14.7+20260901-linux-x64/bin/python3.14",
    "python_license": "/opt/hermes/tools/python-3.14.7+20260901-linux-x64/lib/python3.14/LICENSE.txt",
    "node_binary": "/opt/hermes/tools/node-26.7.0-linux-x64/bin/node",
    "node_license": "/opt/hermes/tools/node-26.7.0-linux-x64/LICENSE",
    "npm_bin": "/opt/hermes/tools/npm-12.0.2-linux-x64/lib/node_modules/npm/bin/npm-cli.js",
    "npm_manifest": "/opt/hermes/tools/npm-12.0.2-linux-x64/lib/node_modules/npm/package.json",
    "npm_license": "/opt/hermes/tools/npm-12.0.2-linux-x64/lib/node_modules/npm/LICENSE",
}
rows = {}
for name, raw in paths.items():
    file = Path(raw)
    if not file.is_file() or file.is_symlink() or not 0 < file.stat().st_size < 200_000_000:
        raise SystemExit(4)
    digest = hashlib.sha256()
    with file.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    rows[name] = {"size": file.stat().st_size, "sha256": digest.hexdigest()}
print(json.dumps({"schema": "hermes-v0221-vendor-selected-files-v1", "files": rows},
                 sort_keys=True, separators=(",", ":")))
"""


class SupplierEvidenceDenied(ValueError):
    """Only sanitized failure codes, never expose untrusted file contents."""


def archive_evidence(directory: Path) -> dict[str, dict[str, object]]:
    """Hash pinned archive and selected archive members without extracting."""
    seen: dict[str, dict[str, object]] = {}
    for package, (expected_digest, members) in ARCHIVES.items():
        path = directory / (package + ".tar")
        if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 160_000_000:
            raise SupplierEvidenceDenied("archive_unavailable")
        sha = hashlib.sha256()
        with path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                sha.update(chunk)
        if sha.hexdigest() != expected_digest:
            raise SupplierEvidenceDenied("archive_digest_mismatch")
        try:
            with tarfile.open(path, mode="r:*") as archive:
                matched = set()
                for member in archive:
                    if member.name not in members:
                        continue
                    if member.name in matched or not member.isfile() or not 0 < member.size < 200_000_000:
                        raise SupplierEvidenceDenied("archive_member_invalid")
                    matched.add(member.name)
                    file = archive.extractfile(member)
                    if file is None:
                        raise SupplierEvidenceDenied("archive_member_unavailable")
                    digest = hashlib.sha256()
                    while chunk := file.read(1024 * 1024):
                        digest.update(chunk)
                    seen[members[member.name]] = {
                        "size": member.size, "sha256": digest.hexdigest(),
                    }
                if matched != set(members):
                    raise SupplierEvidenceDenied("archive_member_missing")
        except (OSError, tarfile.TarError, EOFError):
            raise SupplierEvidenceDenied("invalid_archive") from None
    return seen


def commands() -> tuple[list[str], list[str]]:
    inspect, run = core.commands()
    return inspect, [*run[:-1], INSPECTOR]


def evaluate(archive: dict[str, dict[str, object]], data: bytes) -> dict[str, Any]:
    if type(archive) is not dict or set(archive) != set(IMAGE_FILES):
        raise SupplierEvidenceDenied("incomplete_official_archive_scope")
    try:
        packet = core._json(data, limit=8192)
    except core.ParityDenied:
        raise SupplierEvidenceDenied("invalid_inspector_json") from None
    if (type(packet) is not dict or set(packet) != {"schema", "files"}
            or packet["schema"] != "hermes-v0221-vendor-selected-files-v1"
            or type(packet["files"]) is not dict
            or set(packet["files"]) != set(IMAGE_FILES)):
        raise SupplierEvidenceDenied("invalid_inspector_schema")
    for item in packet["files"].values():
        if (type(item) is not dict or set(item) != {"size", "sha256"}
                or type(item["size"]) is not int
                or not 0 < item["size"] < 200_000_000
                or type(item["sha256"]) is not str
                or re.fullmatch(r"[a-f0-9]{64}", item["sha256"]) is None):
            raise SupplierEvidenceDenied("invalid_file_fingerprint")
    failed = sorted(name for name, item in archive.items() if packet["files"][name] != item)
    return {
        "status": "SELECTED_VENDOR_RELEASE_BYTES_MATCH" if not failed
                  else "SELECTED_VENDOR_RELEASE_BYTES_MISMATCH",
        "immutable_image": IMAGE,
        "archive_checks": len(ARCHIVES),
        "selected_files": len(IMAGE_FILES),
        "matched_files": len(IMAGE_FILES) - len(failed),
        "mismatched_files": failed,
        "signed_supplier_attestation_verified": False,
        "complete_sbom_verified": False,
        "resident_agent_allowed": False,
    }


def observe(directory: Path, runner: Callable[..., subprocess.CompletedProcess] = run_bounded
            ) -> dict[str, Any]:
    release = archive_evidence(directory)
    first, second = commands()
    try:
        inspected = runner(first, capture_output=True, timeout=10,
                           stdout_limit=8192, stderr_limit=16384)
        core.image_identity(inspected.stdout)
        answer = runner(second, capture_output=True, timeout=90,
                        stdout_limit=8192, stderr_limit=16384)
        return evaluate(release, answer.stdout)
    except (OSError, subprocess.TimeoutExpired, BoundedProcessError, core.ParityDenied):
        raise SupplierEvidenceDenied("offline_image_inspection_unavailable") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline selected vendor archive parity")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--archives-dir", type=Path)
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"status": "NOT_EXECUTED", "resident_agent_allowed": False}))
        return 0
    if args.archives_dir is None:
        print(json.dumps({"status": "NO_DATA", "resident_agent_allowed": False}))
        return 2
    try:
        result = observe(args.archives_dir)
    except (SupplierEvidenceDenied, OSError):
        print(json.dumps({"status": "NO_DATA", "reason": "supplier_files_unverified",
                          "resident_agent_allowed": False}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
