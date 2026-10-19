#!/usr/bin/env python3
"""Check the identity of an imported H-15 OCI image on classic and containerd Docker.

The independent archive, config-image-ID and source-commit pins are validated
by h15_brc_offline_image_bundle.py BEFORE this verifier is invoked. This verifier
binds the imported image to the pinned archive's OCI index, manifest, config and
rootfs. It never launches containers or accesses the network.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tarfile
from typing import BinaryIO

CONFIG_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
BLOB_NAME = re.compile(r"blobs/sha256/([0-9a-f]{64})\Z")
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
MAX_METADATA_BYTES = 2_000_000
UPSTREAM_SHA = "cbe511702dd0147650353c29ac6ab1decd8afda1"


class LoadedImageDenied(ValueError):
    pass


def _json_object(data: bytes) -> dict:
    value = json.loads(data)
    if not isinstance(value, dict):
        raise LoadedImageDenied("non_object_oci_metadata")
    return value


def verify_loaded_tar(
    archive: BinaryIO, inspect: dict, expected_config_id: str, expected_tag: str
) -> tuple[str, str]:
    """Read an OCI docker-save tar stream without extracting its members.

    Returns (runtime image ID, docker identity style). The archive SHA256 and
    expected config ID are separately pinned and verified by the caller.
    """
    if not CONFIG_ID.fullmatch(expected_config_id):
        raise LoadedImageDenied("invalid_expected_config_id")
    if not re.fullmatch(r"hermes-brc-relay-eval:[a-f0-9]{12}", expected_tag):
        raise LoadedImageDenied("invalid_expected_tag")
    saved: dict[str, bytes] = {}
    with tarfile.open(fileobj=archive, mode="r|") as stream:
        for entry in stream:
            name = entry.name
            is_metadata = name in ("index.json", "manifest.json")
            match = BLOB_NAME.fullmatch(name)
            if not (is_metadata or match):
                continue
            if not entry.isfile() or entry.size > MAX_METADATA_BYTES:
                if is_metadata:
                    raise LoadedImageDenied("invalid_oci_metadata_entry")
                continue  # Large layer tar blobs are not read into memory.
            payload_stream = stream.extractfile(entry)
            if payload_stream is None:
                raise LoadedImageDenied("unreadable_oci_metadata")
            raw = payload_stream.read(MAX_METADATA_BYTES + 1)
            if len(raw) != entry.size or name in saved:
                raise LoadedImageDenied("duplicate_or_oversize_oci_metadata")
            if match and hashlib.sha256(raw).hexdigest() != match.group(1):
                raise LoadedImageDenied("oci_blob_digest_mismatch")
            saved[name] = raw

    index = _json_object(saved["index.json"])
    docker_manifest = json.loads(saved["manifest.json"])
    if (not isinstance(docker_manifest, list) or len(docker_manifest) != 1
        or docker_manifest[0].get("RepoTags") != [expected_tag]):
        raise LoadedImageDenied("unexpected_archive_tag")
    descriptors = index.get("manifests")
    if not isinstance(descriptors, list) or len(descriptors) != 1:
        raise LoadedImageDenied("unexpected_oci_index")
    descriptor = descriptors[0]
    manifest_id = descriptor.get("digest")
    if (descriptor.get("mediaType") != OCI_MANIFEST
        or not isinstance(manifest_id, str)
        or not CONFIG_ID.fullmatch(manifest_id)):
        raise LoadedImageDenied("unexpected_oci_manifest_descriptor")
    manifest = _json_object(saved["blobs/sha256/" + manifest_id[7:]])
    image_config_ref = manifest.get("config")
    if (not isinstance(image_config_ref, dict)
        or image_config_ref.get("digest") != expected_config_id):
        raise LoadedImageDenied("unexpected_oci_config_reference")
    image_config = _json_object(saved["blobs/sha256/" + expected_config_id[7:]])
    if (image_config.get("os") != "linux"
        or image_config.get("architecture") != "amd64"):
        raise LoadedImageDenied("wrong_archive_platform")

    if not isinstance(inspect, dict):
        raise LoadedImageDenied("invalid_docker_inspect")
    actual_id = inspect.get("Id")
    if actual_id not in (expected_config_id, manifest_id):
        raise LoadedImageDenied("unrecognized_imported_image_id")
    runtime_descriptor = inspect.get("Descriptor") or {}
    if actual_id == manifest_id:
        if (runtime_descriptor.get("digest") != manifest_id
            or runtime_descriptor.get("mediaType") != OCI_MANIFEST):
            raise LoadedImageDenied("containerd_descriptor_mismatch")
        style = "containerd_manifest"
    else:
        if runtime_descriptor and runtime_descriptor.get("digest") not in (
            manifest_id, expected_config_id
        ):
            raise LoadedImageDenied("classic_descriptor_mismatch")
        style = "classic_config"

    if inspect.get("Os") != "linux" or inspect.get("Architecture") != "amd64":
        raise LoadedImageDenied("wrong_imported_platform")
    if inspect.get("RepoTags") != [expected_tag]:
        raise LoadedImageDenied("wrong_imported_tag")
    config = inspect.get("Config") or {}
    original = image_config.get("config") or {}
    for key in (
        "User", "Cmd", "Entrypoint", "WorkingDir", "Env", "Labels", "Healthcheck"
    ):
        if original.get(key) != config.get(key):
            raise LoadedImageDenied("imported_config_mismatch_" + key)
    if (config.get("User") != "65534:65534"
        or (config.get("Labels") or {}).get(
            "org.opencontainers.image.revision"
        ) != UPSTREAM_SHA
        or (config.get("Labels") or {}).get(
            "org.opencontainers.image.licenses"
        ) != "MIT"):
        raise LoadedImageDenied("unsafe_imported_identity")
    original_layers = (image_config.get("rootfs") or {}).get("diff_ids")
    runtime_layers = (inspect.get("RootFS") or {}).get("Layers")
    if (not isinstance(original_layers, list) or not original_layers
        or original_layers != runtime_layers):
        raise LoadedImageDenied("imported_rootfs_layers_mismatch")
    return actual_id, style


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True)
    parser.add_argument("--expected-config-id", required=True)
    parser.add_argument("--expected-tag", required=True)
    args = parser.parse_args()
    try:
        response = json.load(sys.stdin)
        if not isinstance(response, list) or len(response) != 1:
            raise LoadedImageDenied("invalid_docker_inspect")
        with subprocess.Popen(
            ["zstd", "-dc", args.archive], stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        ) as proc:
            assert proc.stdout is not None
            runtime_id, style = verify_loaded_tar(
                proc.stdout, response[0], args.expected_config_id,
                args.expected_tag,
            )
            if proc.wait() != 0:
                raise LoadedImageDenied("zstd_stream_failure")
    except (LoadedImageDenied, KeyError, OSError, ValueError, tarfile.TarError) as exc:
        print("H15_LOADED_IMAGE_REJECTED=" + type(exc).__name__, file=sys.stderr)
        return 2
    print("H15_LOADED_IMAGE_VERIFY=PASS")
    print("H15_LOADED_IMAGE_ID_STYLE=" + style)
    print("H15_LOADED_IMAGE_RUNTIME_ID=" + runtime_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
