#!/usr/bin/env python3
"""Hermes #454: local, READ-ONLY candidate installation preflight.

NO installer command, no systemctl/sc.exe, no service registration, no
account/ACL modification, no SSH, no network, no device pairing, no key
creation or output of original workspace paths. All output is sanitized.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys

from device_fabric.native_install_preview import (
    InstallPlanDenied, MAX_MANIFEST_BYTES, TARGETS, parse_candidate,
    preview, inspect_linux_roots,
)


def _private_manifest(path: Path) -> bytes:
    """Pin one regular private manifest inode to avoid symlink redirects."""
    fd: int | None = None
    try:
        if not path.is_absolute():
            raise InstallPlanDenied("native_install_plan_denied")
        before = path.lstat()
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or not 0 < before.st_size <= MAX_MANIFEST_BYTES
            or (os.name == "posix" and before.st_mode & 0o077)):
            raise InstallPlanDenied("native_install_plan_denied")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags)
        opened = os.fstat(fd)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            or opened.st_size != before.st_size
            or opened.st_ctime_ns != before.st_ctime_ns
            or (os.name == "posix"
                and (opened.st_mode & 0o077
                     or opened.st_uid != os.geteuid()))):
            raise InstallPlanDenied("native_install_plan_denied")
        data = os.read(fd, MAX_MANIFEST_BYTES + 1)
        after = os.fstat(fd)
        if (not data or len(data) > MAX_MANIFEST_BYTES
            or len(data) != before.st_size
            or (opened.st_dev, opened.st_ino, opened.st_mtime_ns,
                opened.st_ctime_ns, opened.st_mode) !=
               (after.st_dev, after.st_ino, after.st_mtime_ns,
                after.st_ctime_ns, after.st_mode)
            or (os.name == "posix" and after.st_mode & 0o077)):
            raise InstallPlanDenied("native_install_plan_denied")
        return data
    except (OSError, ValueError, TypeError):
        raise InstallPlanDenied("native_install_plan_denied") from None
    finally:
        if fd is not None:
            os.close(fd)


def execute(*, manifest: Path, target: str, release_sha: str,
            verify_local_roots: bool) -> dict[str, object]:
    """No writes. A passing preview is never a host installer GO."""
    try:
        parsed = parse_candidate(
            _private_manifest(manifest),
            expected_release=release_sha, expected_target=target)
        result = preview(parsed)
        if verify_local_roots:
            result["local_roots"] = inspect_linux_roots(parsed)
        else:
            result["local_roots"] = "NOT_CHECKED"
        return result
    except (InstallPlanDenied, OSError, ValueError, TypeError):
        return {
            "schema": "h454-native-install-candidate-v1",
            "status": "HOLD",
            "reason": "NATIVE_INSTALL_PREFLIGHT_DENIED",
            "target": target if target in TARGETS else "UNRECOGNIZED",
            "install_authorized": False,
            "changes_applied": False,
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Source-only, read-only Hermes native installation preflight")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--target", choices=sorted(TARGETS), required=True)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--verify-local-roots", action="store_true")
    args = parser.parse_args(argv)
    report = execute(
        manifest=args.manifest, target=args.target,
        release_sha=args.release_sha,
        verify_local_roots=args.verify_local_roots)
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["status"] == "CANDIDATE_SYNTAX_VALID" else 1


if __name__ == "__main__":
    raise SystemExit(main())
