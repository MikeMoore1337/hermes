#!/usr/bin/env python3
"""H-15 #371: create/verify strict offline BRC Docker image transfer receipt.

Verification requires archive SHA256 + image ID + Hermes Git SHA supplied
independently from a trusted exact-head GitHub Actions run. Files inside
the downloaded artifact are *not* an authenticity root by themselves.
Never contacts the network, loads Docker images or executes source.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
from pathlib import Path

UPSTREAM_SHA = "cbe511702dd0147650353c29ac6ab1decd8afda1"
ARCHIVE = "brc-relay.docker.tar.zst"
RECEIPT = "OCI_RECEIPT.json"
SBOM = "sbom.cdx.json"
OS_SBOM = "os-packages.cdx.json"
MANIFEST = "IMAGE_BUNDLE.json"
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
MAX_ARCHIVE_BYTES = 1_500_000_000


class BundleDenied(ValueError):
    pass


def regular_file(directory: Path, name: str, max_bytes: int) -> Path:
    if directory.is_symlink() or not directory.is_dir():
        raise BundleDenied("unsafe_bundle_directory")
    p = directory / name
    if p.is_symlink() or not p.is_file():
        raise BundleDenied("unsafe_bundle_file")
    info = p.stat()
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= max_bytes:
        raise BundleDenied("unexpected_bundle_size")
    return p


def digest_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fd:
        for chunk in iter(lambda: fd.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read_json(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise BundleDenied("invalid_receipt_object")
    return data


def validate_source_receipt(oci: dict) -> None:
    if (oci.get("status") != "CI_IMAGE_VERIFIED_NOT_DEPLOYABLE"
        or oci.get("production_deployment") != "NOT_AUTHORIZED"
        or oci.get("owner_device_execution") != "NOT_ENABLED"
        or oci.get("upstream_sha") != UPSTREAM_SHA
        or not COMMIT_RE.fullmatch(str(oci.get("hermes_commit", "")))
        or not DIGEST_RE.fullmatch(str(oci.get("image_id", "")))
        or oci.get("image_user") != "65534:65534"
        or oci.get("application_license") != "MIT"
        or oci.get("sbom_format") != "CycloneDX"
        or not isinstance(oci.get("sbom_component_count"), int)
        or oci["sbom_component_count"] < 10):
        raise BundleDenied("unapproved_oci_source_receipt")


def validate_os_sbom(os_sbom: dict, image_id: str) -> int:
    if (os_sbom.get("bomFormat") != "CycloneDX"
        or os_sbom.get("specVersion") != "1.5"
        or not isinstance(os_sbom.get("components"), list)
        or not 30 <= len(os_sbom["components"]) <= 1500
        or ((os_sbom.get("metadata") or {}).get("component") or {}).get("version") != image_id):
        raise BundleDenied("unverified_os_package_inventory")
    refs = set()
    for component in os_sbom["components"]:
        if not isinstance(component, dict):
            raise BundleDenied("invalid_os_package_record")
        ref = component.get("bom-ref")
        if (not isinstance(ref, str) or not ref.startswith("pkg:deb/debian/")
            or ref in refs or ref != component.get("purl")
            or component.get("type") != "library"):
            raise BundleDenied("invalid_os_package_record")
        refs.add(ref)
    return len(refs)


def build(*, directory: Path, inspect: Path) -> dict:
    archive = regular_file(directory, ARCHIVE, MAX_ARCHIVE_BYTES)
    oci = read_json(regular_file(directory, RECEIPT, 200_000))
    validate_source_receipt(oci)
    sbom = regular_file(directory, SBOM, 50_000_000)
    if digest_file(sbom) != oci["cyclonedx_sha256"]:
        raise BundleDenied("oci_sbom_digest_mismatch")
    os_path = regular_file(directory, OS_SBOM, 20_000_000)
    os_count = validate_os_sbom(read_json(os_path), oci["image_id"])
    inspect_data = json.loads(inspect.read_text(encoding="utf-8"))
    if not isinstance(inspect_data, list) or len(inspect_data) != 1:
        raise BundleDenied("unexpected_image_inspection")
    image = inspect_data[0]
    if (image.get("Id") != oci["image_id"]
        or image.get("Os") != "linux"
        or image.get("Architecture") != "amd64"
        or (image.get("Config") or {}).get("User") != "65534:65534"):
        raise BundleDenied("incorrect_linux_amd64_image")
    body = {
        "schema": 2,
        "status": "OFFLINE_IMAGE_EXPORT_NOT_DEPLOYED",
        "image_id": oci["image_id"],
        "image_platform": "linux/amd64",
        "upstream_sha": UPSTREAM_SHA,
        "hermes_commit": oci["hermes_commit"],
        "archive_file": ARCHIVE,
        "archive_bytes": archive.stat().st_size,
        "archive_sha256": digest_file(archive),
        "oci_receipt_sha256": digest_file(directory / RECEIPT),
        "sbom_sha256": digest_file(sbom),
        "os_sbom_sha256": digest_file(os_path),
        "os_package_count": os_count,
        "owner_agents_paired": False,
        "production_mcp_enabled": False,
    }
    (directory / MANIFEST).write_text(
        json.dumps(body, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return body


def verify(*, directory: Path, expected_archive_sha: str,
           expected_image_id: str, expected_hermes_sha: str) -> dict:
    if (not SHA_RE.fullmatch(expected_archive_sha)
        or not DIGEST_RE.fullmatch(expected_image_id)
        or not COMMIT_RE.fullmatch(expected_hermes_sha)):
        raise BundleDenied("independent_pin_invalid")
    path = regular_file(directory, MANIFEST, 50_000)
    doc = read_json(path)
    base_fields = {
        "schema", "status", "image_id", "image_platform", "upstream_sha",
        "hermes_commit", "archive_file", "archive_bytes", "archive_sha256",
        "oci_receipt_sha256", "sbom_sha256", "owner_agents_paired",
        "production_mcp_enabled",
    }
    # Legacy schema 1 artifacts remain independently verifiable for
    # offline evaluation; only new schema 2 includes OS-layer evidence.
    if doc.get("schema") == 1:
        fields = base_fields
    elif doc.get("schema") == 2:
        fields = base_fields | {"os_sbom_sha256", "os_package_count"}
    else:
        raise BundleDenied("unsupported_manifest_schema")
    if set(doc) != fields:
        raise BundleDenied("unexpected_manifest_schema")
    if (doc["status"] != "OFFLINE_IMAGE_EXPORT_NOT_DEPLOYED"
        or doc["image_id"] != expected_image_id
        or doc["image_platform"] != "linux/amd64"
        or doc["hermes_commit"] != expected_hermes_sha
        or doc["upstream_sha"] != UPSTREAM_SHA
        or doc["archive_file"] != ARCHIVE
        or doc["archive_sha256"] != expected_archive_sha
        or doc["owner_agents_paired"] is not False
        or doc["production_mcp_enabled"] is not False):
        raise BundleDenied("manifest_independent_pin_mismatch")
    archive = regular_file(directory, ARCHIVE, MAX_ARCHIVE_BYTES)
    receipt = read_json(regular_file(directory, RECEIPT, 200_000))
    sbom = regular_file(directory, SBOM, 50_000_000)
    os_path = regular_file(directory, OS_SBOM, 20_000_000) if doc["schema"] == 2 else None
    os_count = validate_os_sbom(read_json(os_path), expected_image_id) if os_path else None
    validate_source_receipt(receipt)
    if (doc["archive_bytes"] != archive.stat().st_size
        or digest_file(archive) != expected_archive_sha
        or digest_file(directory / RECEIPT) != doc["oci_receipt_sha256"]
        or digest_file(sbom) != doc["sbom_sha256"]
        or (os_path is not None and (digest_file(os_path) != doc["os_sbom_sha256"]
                                     or doc["os_package_count"] != os_count))
        or receipt["image_id"] != expected_image_id
        or receipt["hermes_commit"] != expected_hermes_sha
        or receipt["cyclonedx_sha256"] != doc["sbom_sha256"]):
        raise BundleDenied("bundle_payload_digest_mismatch")
    return doc


def main() -> int:
    parser = argparse.ArgumentParser()
    modes = parser.add_subparsers(dest="mode", required=True)
    b = modes.add_parser("build")
    b.add_argument("--directory", type=Path, required=True)
    b.add_argument("--inspect", type=Path, required=True)
    v = modes.add_parser("verify")
    v.add_argument("--directory", type=Path, required=True)
    v.add_argument("--expected-archive-sha", required=True)
    v.add_argument("--expected-image-id", required=True)
    v.add_argument("--expected-hermes-sha", required=True)
    args = parser.parse_args()
    try:
        if args.mode == "build":
            res = build(directory=args.directory, inspect=args.inspect)
        else:
            res = verify(directory=args.directory,
                         expected_archive_sha=args.expected_archive_sha,
                         expected_image_id=args.expected_image_id,
                         expected_hermes_sha=args.expected_hermes_sha)
    except (BundleDenied, OSError, ValueError, TypeError, KeyError) as exc:
        print("H15_OFFLINE_BUNDLE_REJECTED=" + type(exc).__name__)
        return 2
    print("H15_OFFLINE_BUNDLE_" + args.mode.upper() + "=PASS")
    print("H15_OFFLINE_BUNDLE_IMAGE_ID=" + res["image_id"])
    print("H15_OFFLINE_BUNDLE_ARCHIVE_SHA256=" + res["archive_sha256"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
