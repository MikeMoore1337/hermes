"""Offline, non-root inventory of exactly one pinned v0.22.1 Docker image.

Works with Docker Desktop or a separate Linux Docker engine. Only local
image inspect + isolated non-root container. No model calls, network, mounts,
secrets, repo writes, image pull or publication. Not a complete signed SBOM.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from collections import Counter
from typing import Any, Callable

IMAGE = (
    "nousresearch/hermes-agent@sha256:"
    "cd9cb455576d27c9b6311de1104494ad7e221b6e68dc77e9ac2a8af661a4dc21"
)
SOURCE_SHA = "297552a9d646119871391d202509822cd86330df"
MAX_BYTES = 150_000
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+:~-]{0,120}\Z")
VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+~:!%-]{0,180}\Z")
INSPECTOR = r"""
import importlib.metadata as metadata
import json
import pathlib
import subprocess

stamp_path = pathlib.Path("/opt/hermes/install-stamp.json")
if not stamp_path.is_file() or stamp_path.stat().st_size > 4096:
    raise SystemExit(4)
stamp = json.loads(stamp_path.read_text(encoding="utf-8"))
response = subprocess.run(
    ["/usr/bin/dpkg-query", "-W"],
    capture_output=True, text=True, timeout=8, check=True,
)
os_packages = []
for row in response.stdout.splitlines():
    fields = row.split("\t")
    if len(fields) != 2:
        raise SystemExit(5)
    os_packages.append({"name":fields[0],"version":fields[1]})
python_packages = [
    {"name": dist.metadata.get("Name"), "version": dist.version}
    for dist in metadata.distributions()
]
print(json.dumps({
    "schema": "hermes-v0221-offline-inspector-v1",
    "embedded_commit": stamp.get("commit"),
    "embedded_version": stamp.get("baseVersion"),
    "embedded_distribution": stamp.get("distribution"),
    "os_packages": os_packages,
    "python_packages": python_packages,
}, separators=(",", ":")))
"""


class ImageEvidenceDenied(ValueError):
    """Fixed errors only; never reveal image/env/script raw stdout."""


def commands() -> tuple[list[str], list[str]]:
    inspect = [
        "docker", "image", "inspect", IMAGE,
        "--format", "{{json .RepoDigests}}|{{.Architecture}}",
    ]
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


def _package_rows(raw: object, ecosystem: str) -> list[dict[str, str]]:
    if type(raw) is not list or not 1 <= len(raw) <= 3000:
        raise ImageEvidenceDenied("package_list_invalid")
    result: list[dict[str, str]] = []
    for item in raw:
        if type(item) is not dict or set(item) != {"name", "version"}:
            raise ImageEvidenceDenied("package_row_invalid")
        name, version = item["name"], item["version"]
        if (type(name) is not str or NAME.fullmatch(name) is None
                or type(version) is not str or VERSION.fullmatch(version) is None):
            raise ImageEvidenceDenied("package_value_invalid")
        result.append({"ecosystem": ecosystem, "name": name, "version": version})
    return result


def parse(image_metadata: bytes, inspector_raw: bytes) -> dict[str, Any]:
    if (type(image_metadata) is not bytes
            or len(image_metadata) > 8192
            or type(inspector_raw) is not bytes
            or not 1 <= len(inspector_raw) <= MAX_BYTES):
        raise ImageEvidenceDenied("image_evidence_response_invalid")
    try:
        inspect, architecture = image_metadata.decode("utf-8").strip().split("|")
        digests = json.loads(inspect)
    except (ValueError, UnicodeError):
        raise ImageEvidenceDenied("image_metadata_invalid") from None
    if (type(digests) is not list or IMAGE not in digests
            or architecture != "amd64"):
        raise ImageEvidenceDenied("unexpected_image_identity")

    def strict(fields: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in fields:
            if key in result:
                raise ImageEvidenceDenied("duplicate_image_json_key")
            result[key] = value
        return result

    try:
        payload = json.loads(inspector_raw, object_pairs_hook=strict)
    except ImageEvidenceDenied:
        raise
    except (ValueError, UnicodeError):
        raise ImageEvidenceDenied("invalid_image_json") from None
    if (type(payload) is not dict or set(payload) != {
            "schema", "embedded_commit", "embedded_version",
            "embedded_distribution", "os_packages", "python_packages",
        } or payload["schema"] != "hermes-v0221-offline-inspector-v1"):
        raise ImageEvidenceDenied("invalid_image_schema")
    os_packages = _package_rows(payload["os_packages"], "dpkg")
    python_packages = _package_rows(payload["python_packages"], "python-venv")
    components = sorted(
        os_packages + python_packages,
        key=lambda x: (x["ecosystem"], x["name"].casefold(), x["version"]),
    )
    counts = Counter(
        row["ecosystem"] + ":" + row["name"].lower().replace("_", "-")
        for row in components
    )
    repeat_names = sorted(name for name, count in counts.items() if count > 1)
    serialized = json.dumps(
        components, sort_keys=True, separators=(",", ":"),
    ).encode("ascii")
    match = (
        payload["embedded_commit"] == SOURCE_SHA
        and payload["embedded_version"] == "0.22.1"
        and payload["embedded_distribution"] == "docker"
    )
    return {
        "status": (
            "EMBEDDED_STAMP_MATCH_IMAGE_UNATTESTED" if match
            else "EMBEDDED_STAMP_MISMATCH"
        ),
        "immutable_image": IMAGE,
        "embedded_stamp_matches_release_commit": match,
        "os_package_entries": len(os_packages),
        "python_package_entries": len(python_packages),
        "duplicate_canonical_package_names": repeat_names,
        "component_inventory_sha256": hashlib.sha256(serialized).hexdigest(),
        "source_to_image_parity_verified": False,
        "complete_sbom_verified": False,
        "supplier_signature_verified": False,
        "model_executed": False,
        "resident_agent_allowed": False,
    }


def observe(runner: Callable[..., subprocess.CompletedProcess] = subprocess.run) -> dict[str, Any]:
    inspect, container = commands()
    try:
        first = runner(inspect, check=False, capture_output=True, timeout=10)
        if first.returncode != 0:
            raise ImageEvidenceDenied("pinned_image_not_loaded_locally")
        second = runner(container, check=False, capture_output=True, timeout=30)
        if second.returncode != 0:
            raise ImageEvidenceDenied("offline_inspector_failed")
    except (OSError, subprocess.TimeoutExpired):
        raise ImageEvidenceDenied("local_docker_unavailable") from None
    return parse(first.stdout, second.stdout)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="One pinned local Docker image evidence check")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"status": "NOT_EXECUTED"}))
        return 0
    try:
        result = observe()
    except ImageEvidenceDenied:
        print(json.dumps({
            "status": "UNKNOWN", "reason": "offline_image_evidence_unavailable",
            "resident_agent_allowed": False,
        }))
        return 2
    print(json.dumps(result, sort_keys=True))
    # Local stamp and package inventory alone never authorize resident AI.
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
