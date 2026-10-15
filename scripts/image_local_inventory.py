"""No-network OS and Python package inventory for one pinned official image.

This is not a signed supplier SBOM or source-build provenance. It neither
pulls an image nor launches Hermes/model/tools, nor reads host secrets.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable

IMAGE = "nousresearch/hermes-agent@sha256:32d095e84190ae7266afbb361579e6921f2c633e899f5eacfb88111b9c851a22"
DIGEST = IMAGE.rsplit(":", 1)[-1]
OUT_DIR = Path("/var/lib/hermes-image-audit")
REPORT = "local-components.json"
SCHEMA = "hermes-local-image-components-v1"
MAX_OUTPUT = 131_072
MAX_PACKAGES = 3000
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+:~-]{0,110}\Z")
VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+~:!%-]{0,160}\Z")
INSPECTOR = r"""
import importlib.metadata as m
import json
import subprocess
p = subprocess.run(["dpkg-query", "-W"], capture_output=True, text=True,
                   timeout=8, check=True)
os_items = []
for line in p.stdout.splitlines():
    pieces = line.split("\t")
    if len(pieces) != 2:
        raise RuntimeError("invalid_dpkg_inventory")
    os_items.append({"name": pieces[0], "version": pieces[1]})
py_items = [{"name": d.metadata.get("Name"), "version": d.version}
            for d in m.distributions()]
print(json.dumps({"schema":"hermes-pinned-image-inspector-v1",
                  "os_packages": os_items, "python_venv_packages":py_items}))
"""

class InventoryDenied(ValueError):
    """Fixed diagnostic codes, never package contents or stderr."""


def commands() -> tuple[list[str], list[str]]:
    inspect = ["docker", "image", "inspect", IMAGE, "--format", "{{.Id}} {{.Architecture}}"]
    run = ["docker", "run", "--rm", "--pull=never", "--platform", "linux/amd64",
           "--network", "none", "--read-only", "--cap-drop", "ALL",
           "--security-opt", "no-new-privileges", "--cpus", "0.25",
           "--memory", "256m", "--memory-swap", "256m", "--pids-limit", "25",
           "--tmpfs", "/tmp:rw,nosuid,nodev,size=8m",
           "--entrypoint", "/opt/hermes/.venv/bin/python", IMAGE, "-c", INSPECTOR]
    return inspect, run


def _packages(raw: object, kind: str) -> tuple[list[dict[str, str]], list[str]]:
    if type(raw) is not list or not 1 <= len(raw) <= MAX_PACKAGES:
        raise InventoryDenied("package_list_invalid")
    seen: set[str] = set()
    ambiguous: set[str] = set()
    result: list[dict[str, str]] = []
    for row in raw:
        if type(row) is not dict or set(row) != {"name", "version"}:
            raise InventoryDenied("package_schema_invalid")
        name, version = row["name"], row["version"]
        if (type(name) is not str or type(version) is not str or
                NAME.fullmatch(name) is None or VERSION.fullmatch(version) is None):
            raise InventoryDenied("package_value_invalid")
        key = name.casefold().replace("_", "-")
        if key in seen:
            # Multiple package installations under the same canonical name
            # are important audit evidence. Preserve both, do not hide either.
            ambiguous.add(kind + ":" + key)
        seen.add(key)
        result.append({"ecosystem": kind, "name": name, "version": version})
    return (sorted(result, key=lambda x: (x["name"].casefold(), x["version"])),
            sorted(ambiguous))


def parse(raw: bytes, *, inspected_image_id: str) -> dict[str, Any]:
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_OUTPUT:
        raise InventoryDenied("image_response_invalid")
    if inspected_image_id != "sha256:" + DIGEST + " amd64":
        raise InventoryDenied("image_id_mismatch")
    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise InventoryDenied("duplicate_json_key")
            result[key] = value
        return result
    try:
        root = json.loads(raw, object_pairs_hook=unique)
    except InventoryDenied:
        raise
    except (UnicodeError, ValueError):
        raise InventoryDenied("image_json_invalid") from None
    if (type(root) is not dict or set(root) != {
            "schema", "os_packages", "python_venv_packages"
        } or root["schema"] != "hermes-pinned-image-inspector-v1"):
        raise InventoryDenied("image_schema_invalid")
    os_items, os_ambiguous = _packages(root["os_packages"], "dpkg")
    py_items, py_ambiguous = _packages(root["python_venv_packages"], "python-venv")
    components = sorted(os_items + py_items,
                        key=lambda x: (x["ecosystem"], x["name"].casefold(), x["version"]))
    canonical = json.dumps(components, separators=(",", ":"), sort_keys=True,
                           ensure_ascii=True).encode()
    return {
        "schema": SCHEMA, "image": IMAGE, "image_id": "sha256:" + DIGEST,
        "architecture": "amd64",
        "inventory_sha256": hashlib.sha256(canonical).hexdigest(),
        "os_packages_count": len(os_items),
        "python_venv_packages_count": len(py_items),
        "components": components,
        "ambiguous_package_names": os_ambiguous + py_ambiguous,
        "ambiguous_package_count": len(os_ambiguous) + len(py_ambiguous),
        "supplier_sbom_verified": False,
        "source_release_parity_verified": False,
        "signature_verified": False,
        "vulnerability_scan_complete": False,
        "transitive_dependency_completeness_verified": False,
        "usage": "local_inventory_only",
    }


def record_to_directory(report: dict[str, Any], directory: Path = OUT_DIR) -> None:
    if (type(report) is not dict or report.get("schema") != SCHEMA
            or report.get("image") != IMAGE
            or report.get("supplier_sbom_verified") is not False
            or report.get("source_release_parity_verified") is not False):
        raise InventoryDenied("document_invalid")
    if directory.is_symlink():
        raise InventoryDenied("directory_unsafe")
    directory.mkdir(mode=0o700, exist_ok=True)
    info = directory.stat()
    if not directory.is_dir() or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise InventoryDenied("directory_unsafe")
    destination = directory / REPORT
    if destination.is_symlink():
        raise InventoryDenied("file_unsafe")
    if destination.exists():
        previous = destination.stat()
        if (not stat.S_ISREG(previous.st_mode) or previous.st_uid != os.geteuid()
                or stat.S_IMODE(previous.st_mode) != 0o600 or previous.st_nlink != 1):
            raise InventoryDenied("file_unsafe")
    data = json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
    if len(data) > 512_000:
        raise InventoryDenied("output_oversize")
    fd, name = tempfile.mkstemp(prefix=".inventory-", dir=directory)
    temporary = Path(name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as target:
            target.write(data)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, destination)
        df = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(df)
        finally:
            os.close(df)
    finally:
        temporary.unlink(missing_ok=True)


def observe(runner: Callable[..., subprocess.CompletedProcess] = subprocess.run) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise InventoryDenied("root_required")
    inspect, run = commands()
    try:
        first = runner(inspect, check=False, capture_output=True, timeout=12)
        if first.returncode != 0 or len(first.stdout) > 256:
            raise InventoryDenied("image_inspect_failed")
        second = runner(run, check=False, capture_output=True, timeout=28)
        if second.returncode != 0:
            raise InventoryDenied("image_inventory_failed")
    except (OSError, subprocess.TimeoutExpired):
        raise InventoryDenied("local_command_failed") from None
    try:
        image_id = first.stdout.decode("ascii").strip()
    except (UnicodeError, AttributeError):
        raise InventoryDenied("image_id_invalid") from None
    return parse(second.stdout, inspected_image_id=image_id)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Local image inventory, not signed SBOM")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"status": "NOT_EXECUTED"}))
        return 0
    try:
        report = observe()
        record_to_directory(report)
    except (InventoryDenied, OSError):
        print(json.dumps({"status": "UNKNOWN", "reason": "image_inventory_unavailable"}))
        return 2
    print(json.dumps({
        "status": "INVENTORY_REQUIRES_REVIEW" if report["ambiguous_package_count"] else "LOCAL_INVENTORY_ONLY",
        "ambiguous_package_count": report["ambiguous_package_count"],
        "os_packages": report["os_packages_count"],
        "python_venv_packages": report["python_venv_packages_count"],
        "aggregate_sha256": report["inventory_sha256"],
        "supplier_sbom_verified": False,
        "source_release_parity_verified": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
