"""Measure (not attest) bundled vendor Python source files in immutable v0.22.1.

The no-network, non-root pinned image inspector emits paths, sizes and SHA256
only. The snapshot is NOT supplier attestation, a security scan or runtime GO.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any, Callable

from . import verify_v0221_core_python as core
from .bounded_subprocess import BoundedProcessError, run_bounded
from .verify_v0221_local_image import IMAGE, SOURCE_SHA

VENDOR_COUNTS = {
    "node-26.7.0-linux-x64": 59,
    "npm-12.0.2-linux-x64": 58,
    "python-3.14.7+20260901-linux-x64": 1059,
}
EXPECTED = sum(VENDOR_COUNTS.values())
PATH = re.compile(r"[A-Za-z0-9_.+-]+(?:/[A-Za-z0-9_.+-]+)*[.]py\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
MAX_REPLY = 400_000
INSPECTOR = r"""
import hashlib
import json
from pathlib import Path

root = Path("/opt/hermes/tools")
names = ("node-26.7.0-linux-x64", "npm-12.0.2-linux-x64",
         "python-3.14.7+20260901-linux-x64")
stamp = Path("/opt/hermes/install-stamp.json")
if not stamp.is_file() or stamp.is_symlink() or stamp.stat().st_size > 4096:
    raise SystemExit(4)
identity = json.loads(stamp.read_text(encoding="utf-8"))
rows = []
total_bytes = 0
for name in names:
    directory = root / name
    if not directory.is_dir() or directory.is_symlink():
        raise SystemExit(5)
    for file in directory.rglob("*.py"):
        if not file.is_file() or file.is_symlink():
            raise SystemExit(6)
        size = file.stat().st_size
        if size > 5_000_000:
            raise SystemExit(7)
        content = file.read_bytes()
        if len(content) != size:
            raise SystemExit(8)
        total_bytes += size
        if total_bytes > 128_000_000:
            raise SystemExit(9)
        rows.append({
            "path": file.relative_to(root).as_posix(),
            "size": size,
            "sha256": hashlib.sha256(content).hexdigest(),
        })
print(json.dumps({
    "schema": "hermes-v0221-vendor-python-fingerprints-v1",
    "embedded_commit": identity.get("commit"),
    "embedded_version": identity.get("baseVersion"),
    "files": sorted(rows, key=lambda row: row["path"]),
}, separators=(",", ":")))
"""


class FingerprintDenied(ValueError):
    """Only fixed failure codes; never return raw stderr or file contents."""


def validate(raw: bytes) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        packet = core._json(raw, limit=MAX_REPLY)
    except core.ParityDenied:
        raise FingerprintDenied("invalid_image_payload") from None
    if (type(packet) is not dict
            or set(packet) != {"schema", "embedded_commit", "embedded_version", "files"}
            or packet["schema"] != "hermes-v0221-vendor-python-fingerprints-v1"
            or packet["embedded_commit"] != SOURCE_SHA
            or packet["embedded_version"] != "0.22.1"):
        raise FingerprintDenied("vendor_stamp_invalid")
    entries = packet["files"]
    if type(entries) is not list or len(entries) != EXPECTED:
        raise FingerprintDenied("vendor_file_count_invalid")
    files = {}
    counts = Counter()
    total_bytes = 0
    for record in entries:
        if type(record) is not dict or set(record) != {"path", "size", "sha256"}:
            raise FingerprintDenied("vendor_file_record_invalid")
        path, size, checksum = record["path"], record["size"], record["sha256"]
        if (type(path) is not str or len(path) > 300 or PATH.fullmatch(path) is None
                or path.split("/")[0] not in VENDOR_COUNTS
                or any(part in (".", "..") for part in path.split("/"))
                or type(size) is not int or not 0 <= size <= 5_000_000
                or type(checksum) is not str or SHA256.fullmatch(checksum) is None
                or path in files):
            raise FingerprintDenied("vendor_file_identity_invalid")
        files[path] = {"path": path, "size": size, "sha256": checksum}
        counts[path.split("/")[0]] += 1
        total_bytes += size
    if dict(counts) != VENDOR_COUNTS or total_bytes > 128_000_000:
        raise FingerprintDenied("vendor_file_layout_invalid")
    artifact = {
        "schema": "hermes-v0221-vendor-python-fingerprints-v1",
        "immutable_image": IMAGE,
        "embedded_commit": SOURCE_SHA,
        "files": [files[name] for name in sorted(files)],
    }
    raw_artifact = json.dumps(artifact, sort_keys=True, indent=2) + "\n"
    summary = {
        "status": "VENDOR_PYTHON_FINGERPRINTS_RECORDED_UNATTESTED",
        "python_file_count": EXPECTED,
        "counts": VENDOR_COUNTS,
        "python_total_bytes": total_bytes,
        "artifact_sha256": hashlib.sha256(raw_artifact.encode()).hexdigest(),
        "supplier_source_verified": False,
        "runtime_binaries_verified": False,
        "licensing_verified": False,
        "vulnerabilities_scanned": False,
        "complete_sbom_verified": False,
        "resident_agent_allowed": False,
        "model_executed": False,
    }
    return artifact, summary


def commands() -> tuple[list[str], list[str]]:
    inspect, run = core.commands()
    return inspect, [*run[:-1], INSPECTOR]


def collect(runner: Callable[..., subprocess.CompletedProcess] = run_bounded
            ) -> tuple[dict[str, Any], dict[str, Any]]:
    inspect, run = commands()
    try:
        first = runner(inspect, check=False, capture_output=True, timeout=10,
                       stdout_limit=8192, stderr_limit=16384)
        if first.returncode:
            raise FingerprintDenied("pinned_image_unavailable")
        core.image_identity(first.stdout)
        second = runner(run, check=False, capture_output=True, timeout=90,
                        stdout_limit=MAX_REPLY, stderr_limit=16384)
        if second.returncode:
            raise FingerprintDenied("vendor_inspector_unavailable")
        return validate(second.stdout)
    except (OSError, subprocess.TimeoutExpired, core.ParityDenied,
            BoundedProcessError):
        raise FingerprintDenied("offline_docker_unavailable") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Unattested vendor Python fingerprints")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"status": "NOT_EXECUTED", "resident_agent_allowed": False}))
        return 0
    if args.output is None:
        print(json.dumps({"status": "NOT_RUN", "reason": "output_required",
                          "resident_agent_allowed": False}))
        return 2
    try:
        artifact, summary = collect()
        with args.output.open("x", encoding="utf-8", newline="\n") as out:
            json.dump(artifact, out, sort_keys=True, indent=2)
            out.write("\n")
    except (FingerprintDenied, OSError):
        print(json.dumps({"status": "NO_DATA", "reason": "vendor_evidence_unavailable",
                          "resident_agent_allowed": False}))
        return 2
    print(json.dumps(summary, sort_keys=True))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
