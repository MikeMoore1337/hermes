"""H454 client for restricted SSH staging: bounded frame and report, CI only.

No SSH key input, no host command, no host installation. GitHub Actions
owns transport/known_hosts. This module reads only private exact-SHA archive
bytes from a verified build directory and emits a framed stdin payload.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

from scripts.h454_native_readonly_bundle import (
    ARCHIVE_NAME, RECEIPT_NAME, MAX_ARCHIVE_SIZE, MAX_RECEIPT_SIZE,
    _read_private_artifact, verify_bytes,
)
from scripts.h454_native_linux_ssh_stage import (
    encode, verify_report, StageDenied, TARGETS,
)


def _candidate(folder: Path, target: str, sha: str) -> tuple[bytes, bytes, str]:
    try:
        if type(folder) is not Path or not folder.is_absolute():
            raise StageDenied("native_stage_client_denied")
        source = folder.lstat()
        if (not stat.S_ISDIR(source.st_mode) or
            stat.S_IMODE(source.st_mode) != 0o700 or
            source.st_uid != os.geteuid() or
            stat.S_ISLNK(source.st_mode)):
            raise StageDenied("native_stage_client_denied")
        if {item.name for item in folder.iterdir()} != {ARCHIVE_NAME, RECEIPT_NAME}:
            raise StageDenied("native_stage_client_denied")
        archive = _read_private_artifact(folder / ARCHIVE_NAME, MAX_ARCHIVE_SIZE)
        receipt = _read_private_artifact(folder / RECEIPT_NAME, MAX_RECEIPT_SIZE)
        proof = verify_bytes(archive, receipt, target=target, release_sha=sha)
        return archive, receipt, proof["bundle_sha256"]
    except Exception:
        raise StageDenied("native_stage_client_denied") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="H454 stage source-only CI pipe")
    parser.add_argument("action", choices=("encode", "verify"))
    parser.add_argument("--target", choices=sorted(TARGETS), required=True)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--bundle-dir", type=Path, required=True)
    parser.add_argument("--mode", choices=("stage", "cleanup"), required=True)
    args = parser.parse_args(argv)
    try:
        archive, receipt, digest = _candidate(
            args.bundle_dir, args.target, args.release_sha)
        if args.action == "encode":
            frame = encode(target=args.target, release_sha=args.release_sha,
                           archive=archive, receipt=receipt)
            sys.stdout.buffer.write(frame)
        else:
            report = verify_report(
                sys.stdin.buffer.read(2049),
                expected_target=args.target,
                release_sha=args.release_sha,
                bundle_sha256=digest, action=args.mode,
            )
            print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        return 0
    except Exception:
        print("H454_NATIVE_SSH_STAGE_CLIENT=HOLD", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
