"""H-01: offline exact Git-blob comparison of v0.22.1 core Python files.

Compares the pinned public upstream source tree manifest against a pinned,
locally available AMD64 image. No network in container, mount, model, secrets,
download, model call or production action. Not a build attestation or SBOM.
"""
from __future__ import annotations

import argparse
import json
import re
import stat
import subprocess
from pathlib import Path
from typing import Any, Callable

from .verify_v0221_local_image import IMAGE, SOURCE_SHA

ROOTS = ("agent", "gateway", "hermes_cli", "hermes_platform", "providers")
COUNTS = {"agent": 362, "gateway": 302, "hermes_cli": 729,
          "hermes_platform": 15, "providers": 2}
TOTAL = sum(COUNTS.values())
MANIFEST = Path(__file__).with_name("v0221_core_python_manifest.json")
MAX_MANIFEST = 240_000
MAX_REPLY = 320_000
SHA1 = re.compile(r"[0-9a-f]{40}\Z")
PATH = re.compile(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\.py\Z")

INSPECTOR = r"""
import hashlib
import json
from pathlib import Path

roots = ("agent", "gateway", "hermes_cli", "hermes_platform", "providers")
base = Path("/opt/hermes")
rows = []
for name in roots:
    directory = base / name
    if directory.is_symlink() or not directory.is_dir():
        raise SystemExit(4)
    for file in directory.rglob("*.py"):
        if file.is_symlink() or not file.is_file() or file.stat().st_size > 1024 * 1024:
            raise SystemExit(5)
        raw = file.read_bytes()
        blob = hashlib.sha1(
            b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw
        ).hexdigest()
        rows.append({
            "path": file.relative_to(base).as_posix(),
            "git_blob_sha1": blob,
            "size": len(raw),
        })
print(json.dumps({
    "schema": "hermes-v0221-image-python-tree-v1",
    "files": sorted(rows, key=lambda row: row["path"]),
}, separators=(",", ":")))
"""


class ParityDenied(ValueError):
    """Only fixed error codes, no remote stdout or file contents."""


def strict_pairs(items: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in items:
        if name in result:
            raise ParityDenied("duplicate_json_key")
        result[name] = value
    return result


def _json(raw: bytes, *, limit: int) -> Any:
    if type(raw) is not bytes or not 1 <= len(raw) <= limit:
        raise ParityDenied("invalid_payload_size")
    try:
        return json.loads(raw, object_pairs_hook=strict_pairs)
    except ParityDenied:
        raise
    except (ValueError, UnicodeError):
        raise ParityDenied("invalid_json") from None


def _files(raw: object, *, max_files: int) -> dict[str, tuple[str, int]]:
    if type(raw) is not list or len(raw) > max_files:
        raise ParityDenied("invalid_file_count")
    files: dict[str, tuple[str, int]] = {}
    for entry in raw:
        if type(entry) is not dict or set(entry) != {"path", "git_blob_sha1", "size"}:
            raise ParityDenied("invalid_file_record")
        name, checksum, size = entry["path"], entry["git_blob_sha1"], entry["size"]
        if (type(name) is not str or len(name) > 250
                or PATH.fullmatch(name) is None
                or name.split("/", 1)[0] not in ROOTS
                or type(checksum) is not str or SHA1.fullmatch(checksum) is None
                or type(size) is not int or not 0 <= size <= 1024 * 1024
                or name in files):
            raise ParityDenied("invalid_file_identity")
        files[name] = checksum, size
    return files


def load_manifest(path: Path = MANIFEST) -> dict[str, tuple[str, int]]:
    try:
        if path.is_symlink() or not path.is_file():
            raise ParityDenied("manifest_missing_or_symlink")
        info = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_MANIFEST:
            raise ParityDenied("manifest_invalid")
        document = _json(path.read_bytes(), limit=MAX_MANIFEST)
    except OSError:
        raise ParityDenied("manifest_unavailable") from None
    if (type(document) is not dict
            or set(document) != {"schema", "source_repo", "source_commit", "roots", "files"}
            or document["schema"] != "hermes-v0221-source-python-tree-v1"
            or document["source_repo"] != "NousResearch/hermes-agent"
            or document["source_commit"] != SOURCE_SHA
            or document["roots"] != list(ROOTS)):
        raise ParityDenied("manifest_identity_invalid")
    files = _files(document["files"], max_files=TOTAL)
    if len(files) != TOTAL or {
        root: sum(p.startswith(root + "/") for p in files)
        for root in ROOTS
    } != COUNTS:
        raise ParityDenied("manifest_scope_invalid")
    return files


def image_identity(raw: bytes) -> None:
    if type(raw) is not bytes or len(raw) > 8192:
        raise ParityDenied("image_metadata_invalid")
    try:
        digests_raw, arch = raw.decode("utf-8").strip().split("|")
        digests = json.loads(digests_raw, object_pairs_hook=strict_pairs)
    except (UnicodeError, ValueError):
        raise ParityDenied("image_metadata_invalid") from None
    if type(digests) is not list or IMAGE not in digests or arch != "amd64":
        raise ParityDenied("image_identity_mismatch")


def compare(manifest: dict[str, tuple[str, int]], raw: bytes) -> dict[str, Any]:
    evidence = _json(raw, limit=MAX_REPLY)
    if (type(evidence) is not dict
            or set(evidence) != {"schema", "files"}
            or evidence["schema"] != "hermes-v0221-image-python-tree-v1"):
        raise ParityDenied("image_evidence_schema_invalid")
    actual = _files(evidence["files"], max_files=3000)
    expected_names, actual_names = set(manifest), set(actual)
    different = sum(actual[name] != manifest[name] for name in
                    expected_names & actual_names)
    missing = len(expected_names - actual_names)
    extras = len(actual_names - expected_names)
    matches = not (different or missing or extras)
    return {
        "status": ("CORE_PYTHON_BLOBS_MATCH_UNATTESTED" if matches
                   else "CORE_PYTHON_BLOBS_MISMATCH"),
        "source_commit": SOURCE_SHA,
        "image": IMAGE,
        "expected_files": TOTAL,
        "inspected_files": len(actual),
        "different_count": different,
        "missing_count": missing,
        "extra_count": extras,
        "sampled_scope_matches": matches,
        "full_source_to_image_parity_verified": False,
        "supplier_attestation_verified": False,
        "complete_sbom_verified": False,
        "model_executed": False,
        "resident_agent_allowed": False,
    }


def commands() -> tuple[list[str], list[str]]:
    inspect = ["docker", "image", "inspect", IMAGE,
               "--format", "{{json .RepoDigests}}|{{.Architecture}}"]
    run = [
        "docker", "run", "--rm", "--pull=never", "--platform", "linux/amd64",
        "--network", "none", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--user", "65534:65534",
        "--cpus", "0.25", "--memory", "256m", "--memory-swap", "256m",
        "--pids-limit", "25", "--tmpfs", "/tmp:rw,nosuid,nodev,size=8m",
        "--entrypoint", "/opt/hermes/.venv/bin/python",
        IMAGE, "-B", "-c", INSPECTOR,
    ]
    return inspect, run


def observe(runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
            manifest_path: Path = MANIFEST) -> dict[str, Any]:
    expected = load_manifest(manifest_path)
    inspect, run = commands()
    try:
        meta = runner(inspect, check=False, capture_output=True, timeout=10)
        if meta.returncode:
            raise ParityDenied("image_not_loaded")
        image_identity(meta.stdout)
        container = runner(run, check=False, capture_output=True, timeout=90)
        if container.returncode:
            raise ParityDenied("image_inspector_failed")
    except (OSError, subprocess.TimeoutExpired):
        raise ParityDenied("local_docker_unavailable") from None
    return compare(expected, container.stdout)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Pinned v0.22.1 core Python parity")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"status": "NOT_EXECUTED"}))
        return 0
    try:
        outcome = observe()
    except ParityDenied:
        print(json.dumps({"status": "UNKNOWN", "reason": "source_parity_evidence_unavailable",
                          "resident_agent_allowed": False}))
        return 2
    print(json.dumps(outcome, sort_keys=True))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
