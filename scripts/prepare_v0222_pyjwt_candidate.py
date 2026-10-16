"""Prepare an opt-in THREE-FILE offline build context for the PyJWT fix pilot.

Never downloads, builds, executes Docker, accesses credentials or copies source trees.
Always NO-GO: preparing an image candidate does not attest or secure a runtime.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile

WHEEL = "pyjwt-2.15.1-py3-none-any.whl"
WHEEL_SHA256 = "42d59d631f7768a1028a64c7ff581a9bf7519804daf91fc5b6c56e30eec5e193"
PATCH = "hermes-v0.22.1-native-tool-policy.patch"
PATCH_SHA256 = "e7157fd4831b32670d418a5eec675a8cab8318a49e5c1df94e33da7e9d3a2016"
IMAGE = ("nousresearch/hermes-agent@sha256:"
         "a11574b7fe8e1631d7d88d556677dac693bc058abf558cdeb899155688c1bf05")
ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "docker/v0222-pyjwt-fixed-candidate/Dockerfile"
PATCHFILE = ROOT / "patches/upstream" / PATCH
MAX_WHEEL = 80_000
MAX_DOCKERFILE = 8_192
MAX_PATCH = 20_000


class ContextDenied(ValueError):
    """Sanitized rejection; never expose private absolute paths."""


def _verified_bytes(path: Path, *, maximum: int, digest: str | None = None) -> bytes:
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= maximum:
        raise ContextDenied("missing_or_invalid_input")
    blob = path.read_bytes()
    if not 0 < len(blob) <= maximum:
        raise ContextDenied("input_size_denied")
    if digest and hashlib.sha256(blob).hexdigest() != digest:
        raise ContextDenied("input_sha256_mismatch")
    return blob


def prepare(wheel: Path, output: Path) -> dict:
    if wheel.name != WHEEL:
        raise ContextDenied("unexpected_wheel_filename")
    source_wheel = _verified_bytes(wheel, maximum=MAX_WHEEL, digest=WHEEL_SHA256)
    patch = _verified_bytes(PATCHFILE, maximum=MAX_PATCH, digest=PATCH_SHA256)
    dockerfile = _verified_bytes(DOCKERFILE, maximum=MAX_DOCKERFILE)
    if (b"FROM " + IMAGE.encode()) not in dockerfile or WHEEL_SHA256.encode() not in dockerfile:
        raise ContextDenied("unrecognized_immutable_build_recipe")
    if output.exists() or output.is_symlink() or not output.parent.is_dir():
        raise ContextDenied("output_must_not_exist")
    destination = output.resolve(strict=False)
    if (destination == ROOT or destination.is_relative_to(ROOT)
            or destination == Path(destination.anchor)):
        raise ContextDenied("unsafe_output_directory")
    if output.parent.is_symlink() or output.parent.resolve() != output.parent.absolute():
        raise ContextDenied("untrusted_output_parent")
    temp = Path(tempfile.mkdtemp(prefix="hermes-h18-stage-", dir=output.parent))
    try:
        for name, data in (("Dockerfile", dockerfile), (PATCH, patch), (WHEEL, source_wheel)):
            with (temp / name).open("xb") as stream:
                stream.write(data)
        os.replace(temp, output)
    except Exception:
        shutil.rmtree(temp, ignore_errors=True)
        raise ContextDenied("stage_failed") from None
    return {
        "schema": "hermes-h18-pyjwt-214-stage-v1",
        "status": "OFFLINE_CONTEXT_PREPARED_NO_GO",
        "files_staged": 3,
        "base_immutable_image": IMAGE,
        "pyjwt_wheel_sha256_matches_pypi": True,
        "native_guard_patch_sha256_verified": True,
        "build_executed": False,
        "upstream_security_attestation": False,
        "resident_agent_allowed": False,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Prepare locked PyJWT 2.14 offline build context")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--wheel", type=Path)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"status": "NOT_EXECUTED", "resident_agent_allowed": False}))
        return 0
    try:
        if args.wheel is None or args.output_dir is None:
            raise ContextDenied("missing_inputs")
        report = prepare(args.wheel, args.output_dir)
    except (ContextDenied, OSError):
        report = {"status": "INCONCLUSIVE", "resident_agent_allowed": False,
                  "error_code": "unverified_wheel_or_build_context"}
    print(json.dumps(report, sort_keys=True))
    # Staging is NOT equivalent to signed image or CVE clearance.
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
