#!/usr/bin/env python3
"""H-15: deterministic observed Debian image package SBOM, not a CVE scan.

Read only dpkg-query results taken from the ACTUAL built OCI image and
an independently generated docker image inspect. No network, subprocess,
Docker socket, host package database or deployment permission.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import quote

UPSTREAM_SHA = "cbe511702dd0147650353c29ac6ab1decd8afda1"
IMAGE_ID_RE = re.compile(r"sha256:[a-f0-9]{64}\Z")
PACKAGE_RE = re.compile(r"[a-z0-9][a-z0-9+.-]{0,127}\Z")
ARCH_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,31}\Z")
MAX_INPUT_SIZE = 2 * 1024 * 1024
MAX_PACKAGES = 1500


class OsInventoryDenied(ValueError):
    pass


def inventory(raw: bytes, inspect_raw: bytes) -> dict:
    if not 0 < len(raw) <= MAX_INPUT_SIZE:
        raise OsInventoryDenied("invalid_dpkg_input_size")
    try:
        info = json.loads(inspect_raw)
        image = info[0] if isinstance(info, list) and len(info) == 1 else None
        if not isinstance(image, dict):
            raise OsInventoryDenied("invalid_docker_inspect")
        image_id = image["Id"]
        if not isinstance(image_id, str) or not IMAGE_ID_RE.fullmatch(image_id):
            raise OsInventoryDenied("invalid_image_id")
        cfg = image["Config"]
        if (image.get("Os") != "linux" or image.get("Architecture") != "amd64"
                or cfg["User"] != "65534:65534"
                or cfg["Labels"]["org.opencontainers.image.revision"] != UPSTREAM_SHA):
            raise OsInventoryDenied("unexpected_image_identity")
        rows = raw.decode("utf-8").splitlines()
    except (UnicodeDecodeError, KeyError, TypeError, IndexError) as exc:
        raise OsInventoryDenied("invalid_input") from exc
    if not 30 <= len(rows) <= MAX_PACKAGES:
        raise OsInventoryDenied("unexpected_package_count")
    packages = []
    seen = set()
    for line in rows:
        parts = line.split("\t")
        if len(parts) != 3:
            raise OsInventoryDenied("malformed_package_record")
        name, version, arch = parts
        if (not PACKAGE_RE.fullmatch(name)
                or not ARCH_RE.fullmatch(arch)
                or not version or len(version) > 255
                or any(ord(c) < 33 or ord(c) > 126 for c in version)):
            raise OsInventoryDenied("invalid_package_field")
        if (name, arch) in seen:
            raise OsInventoryDenied("duplicate_package")
        seen.add((name, arch))
        purl = (
            "pkg:deb/debian/" + quote(name, safe="")
            + "@" + quote(version, safe="")
            + "?arch=" + quote(arch, safe="")
        )
        packages.append({
            "type": "library",
            "bom-ref": purl,
            "name": name,
            "version": version,
            "purl": purl,
            "properties": [{"name": "deb:architecture", "value": arch}],
        })
    packages.sort(key=lambda item: item["bom-ref"])
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "container",
                "name": "hermes-brc-relay-evaluation",
                "version": image_id,
            }
        },
        "components": packages,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dpkg-list", type=Path, required=True)
    parser.add_argument("--docker-inspect", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.output.exists() or args.output.is_symlink():
            raise OsInventoryDenied("no_overwrite")
        raw = args.dpkg_list.read_bytes()
        inspect = args.docker_inspect.read_bytes()
        if len(inspect) > MAX_INPUT_SIZE:
            raise OsInventoryDenied("docker_inspect_too_large")
        report = inventory(raw, inspect)
        payload = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
        with args.output.open("xb") as dst:
            dst.write(payload)
    except (OsInventoryDenied, ValueError, OSError) as exc:
        print("H15_OS_INVENTORY=REJECTED_" + type(exc).__name__)
        return 2
    print("H15_OS_INVENTORY=PASS")
    print("H15_OS_PACKAGE_COUNT=" + str(len(report["components"])))
    print("H15_OS_INVENTORY_SHA256=" + hashlib.sha256(payload).hexdigest())
    print("H15_OS_VULNERABILITY_SCAN=NOT_PERFORMED")
    print("H15_OS_RELEASE_APPROVED=NO")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
