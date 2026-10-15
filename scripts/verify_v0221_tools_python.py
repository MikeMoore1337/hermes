"""H-01 bounded offline source parity for built-in tools (NOT vendor runtimes).

Reuses pinned non-root Docker restrictions from the 1410-file core verifier.
The three bundled language runtimes are counted but NOT source-attested.
No network, mounts, model, credentials, downloads or production interaction.
"""
from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Callable

from . import verify_v0221_core_python as core
from .bounded_subprocess import BoundedProcessError, run_bounded
from .verify_v0221_local_image import IMAGE, SOURCE_SHA

MANIFEST = Path(__file__).with_name("v0221_tools_python_manifest.json")
EXPECTED_FILES = 353
VENDOR_COUNTS = {
    "node-26.7.0-linux-x64": 59,
    "npm-12.0.2-linux-x64": 58,
    "python-3.14.7+20260901-linux-x64": 1059,
}
MAX_RESPONSE = 100_000
INSPECTOR = r"""
import hashlib
import json
from pathlib import Path

base = Path("/opt/hermes/tools")
vendor = {
    "node-26.7.0-linux-x64": 0,
    "npm-12.0.2-linux-x64": 0,
    "python-3.14.7+20260901-linux-x64": 0,
}
if base.is_symlink() or not base.is_dir():
    raise SystemExit(4)
rows = []
for file in base.rglob("*.py"):
    if file.is_symlink() or not file.is_file() or file.stat().st_size > 1024 * 1024:
        raise SystemExit(5)
    relative = file.relative_to(base)
    if len(relative.parts) > 1 and relative.parts[0] in vendor:
        vendor[relative.parts[0]] += 1
        continue
    content = file.read_bytes()
    rows.append({
        "path": "tools/" + relative.as_posix(),
        "git_blob_sha1": hashlib.sha1(
            b"blob " + str(len(content)).encode("ascii") + b"\0" + content
        ).hexdigest(),
        "size": len(content),
    })
print(json.dumps({
    "schema": "hermes-v0221-tools-image-sample-v1",
    "files": sorted(rows, key=lambda x: x["path"]),
    "vendor_python_file_counts": vendor,
}, separators=(",", ":")))
"""


def _files(data: object, *, max_count: int) -> dict[str, tuple[str, int]]:
    if type(data) is not list or len(data) > max_count:
        raise core.ParityDenied("tools_file_count_invalid")
    result = {}
    for entry in data:
        if type(entry) is not dict or set(entry) != {"path", "git_blob_sha1", "size"}:
            raise core.ParityDenied("tools_file_record_invalid")
        path, checksum, size = entry["path"], entry["git_blob_sha1"], entry["size"]
        if (type(path) is not str or len(path) > 250
                or core.PATH.fullmatch(path) is None
                or not path.startswith("tools/")
                or type(checksum) is not str
                or core.SHA1.fullmatch(checksum) is None
                or type(size) is not int or not 0 <= size <= 1024 * 1024
                or path in result):
            raise core.ParityDenied("tools_file_identity_invalid")
        result[path] = checksum, size
    return result


def manifest(path: Path = MANIFEST) -> dict[str, tuple[str, int]]:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 90_000:
            raise core.ParityDenied("tools_manifest_invalid")
        payload = core._json(path.read_bytes(), limit=90_000)
    except OSError:
        raise core.ParityDenied("tools_manifest_unavailable") from None
    if (type(payload) is not dict
            or set(payload) != {"schema", "source_repo", "source_commit", "files"}
            or payload["schema"] != "hermes-v0221-tools-python-tree-v1"
            or payload["source_repo"] != "NousResearch/hermes-agent"
            or payload["source_commit"] != SOURCE_SHA):
        raise core.ParityDenied("tools_manifest_origin_invalid")
    files = _files(payload["files"], max_count=EXPECTED_FILES)
    if len(files) != EXPECTED_FILES:
        raise core.ParityDenied("tools_manifest_scope_invalid")
    return files


def parse(expected: dict[str, tuple[str, int]], raw: bytes) -> dict[str, Any]:
    packet = core._json(raw, limit=MAX_RESPONSE)
    if (type(packet) is not dict
            or set(packet) != {"schema", "files", "vendor_python_file_counts"}
            or packet["schema"] != "hermes-v0221-tools-image-sample-v1"):
        raise core.ParityDenied("tools_image_schema_invalid")
    received = _files(packet["files"], max_count=4000)
    vendor = packet["vendor_python_file_counts"]
    if (type(vendor) is not dict or set(vendor) != set(VENDOR_COUNTS)
            or any(type(x) is not int or not 0 <= x <= 10_000
                   for x in vendor.values())):
        raise core.ParityDenied("vendor_count_schema_invalid")
    wanted, found = set(expected), set(received)
    missing = len(wanted - found)
    extra = len(found - wanted)
    different = sum(expected[name] != received[name] for name in wanted & found)
    vendor_count_changed = vendor != VENDOR_COUNTS
    matched = not (missing or extra or different or vendor_count_changed)
    return {
        "status": "TOOLS_PYTHON_BLOBS_MATCH_UNATTESTED" if matched
                  else "TOOLS_PYTHON_BLOBS_MISMATCH",
        "source_commit": SOURCE_SHA,
        "image": IMAGE,
        "expected_tools_source_files": EXPECTED_FILES,
        "observed_tools_source_files": len(received),
        "missing_count": missing, "extra_count": extra, "different_count": different,
        "vendor_python_file_counts": vendor,
        "vendor_file_count_drift": vendor_count_changed,
        "tools_scope_matches": matched,
        "vendor_runtime_content_verified": False,
        "full_source_to_image_parity_verified": False,
        "supplier_attestation_verified": False,
        "complete_sbom_verified": False,
        "model_executed": False,
        "resident_agent_allowed": False,
    }


def commands() -> tuple[list[str], list[str]]:
    inspect, run = core.commands()
    return inspect, [*run[:-1], INSPECTOR]


def observe(runner: Callable[..., subprocess.CompletedProcess] = run_bounded,
            path: Path = MANIFEST) -> dict[str, Any]:
    wanted = manifest(path)
    inspect, run = commands()
    try:
        metadata = runner(inspect, check=False, capture_output=True, timeout=10,
                          stdout_limit=8192, stderr_limit=16384)
        if metadata.returncode:
            raise core.ParityDenied("image_not_loaded")
        core.image_identity(metadata.stdout)
        result = runner(run, check=False, capture_output=True, timeout=90,
                        stdout_limit=MAX_RESPONSE, stderr_limit=16384)
        if result.returncode:
            raise core.ParityDenied("tools_inspector_unavailable")
    except (OSError, subprocess.TimeoutExpired, BoundedProcessError):
        raise core.ParityDenied("local_docker_unavailable") from None
    return parse(wanted, result.stdout)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Pinned v0.22.1 tools Python parity")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"status": "NOT_EXECUTED"}))
        return 0
    try:
        result = observe()
    except core.ParityDenied:
        print(json.dumps({"status": "UNKNOWN",
                          "reason": "tools_parity_evidence_unavailable",
                          "resident_agent_allowed": False}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
