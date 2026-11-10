"""H454 Stage 2A - dedicated non-root Linux SSH source staging channel.

SSH forced command account h454-native-stage has NO root/sudo/production
access. It only validates a bounded exact-main source-bundle/receipt and
exclusively stages two private files. The existing root-console installer
remains a separate owner-approved action; SSH staging does not enable/start
systemd, pair a device, create an OS principal or touch original projects.
"""
from __future__ import annotations
import argparse
import base64
import binascii
import hashlib
import io
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import sys

from scripts.h454_native_readonly_bundle import (
    ARCHIVE_NAME, RECEIPT_NAME, MAX_ARCHIVE_SIZE, MAX_RECEIPT_SIZE,
    verify_bytes, SourceBundleDenied,
)

SCHEMA = "h454-native-linux-stage-v1"
REPORT_SCHEMA = "h454-native-linux-stage-report-v1"
TARGETS = frozenset({"hermes-vps", "yfc-vps"})
SHA40 = re.compile(r"[a-f0-9]{40}\Z")
SHA64 = re.compile(r"[a-f0-9]{64}\Z")
ACCOUNT = "h454-native-stage"
STAGING_ROOT = Path("/var/lib/hermes-commander-native-staging")
MAX_FRAME = 3 * 1024 * 1024
FIELDS = frozenset({
    "schema", "target", "release_sha",
    "bundle_sha256", "archive_b64", "receipt_b64",
})


class StageDenied(ValueError):
    """Constant refusal, never expose source, SSH key or host paths."""


def _deny() -> None:
    raise StageDenied("native_linux_stage_denied")


def _canonical(value: dict[str, object]) -> bytes:
    return json.dumps(
        value, sort_keys=True, ensure_ascii=True,
        separators=(",", ":"), allow_nan=False,
    ).encode("ascii")


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    output = {}
    for name, value in pairs:
        if name in output:
            _deny()
        output[name] = value
    return output


def decode(frame: bytes, *, expected_target: str) -> tuple[dict[str, object], bytes, bytes]:
    """Validate full source bundle BEFORE creating any directory on a VPS."""
    try:
        if (type(frame) is not bytes or not 0 < len(frame) <= MAX_FRAME
            or expected_target not in TARGETS):
            _deny()
        item = json.loads(
            frame.decode("ascii"), object_pairs_hook=_unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
        if (type(item) is not dict or set(item) != FIELDS
            or frame != _canonical(item)
            or item["schema"] != SCHEMA
            or item["target"] != expected_target
            or type(item["release_sha"]) is not str
            or SHA40.fullmatch(item["release_sha"]) is None
            or type(item["bundle_sha256"]) is not str
            or SHA64.fullmatch(item["bundle_sha256"]) is None
            or type(item["archive_b64"]) is not str
            or type(item["receipt_b64"]) is not str):
            _deny()
        archive = base64.b64decode(item["archive_b64"], validate=True)
        receipt = base64.b64decode(item["receipt_b64"], validate=True)
        if (not 0 < len(archive) <= MAX_ARCHIVE_SIZE
            or not 0 < len(receipt) <= MAX_RECEIPT_SIZE
            or hashlib.sha256(archive).hexdigest() != item["bundle_sha256"]):
            _deny()
        evidence = verify_bytes(
            archive, receipt, target=expected_target,
            release_sha=item["release_sha"],
        )
        if evidence["bundle_sha256"] != item["bundle_sha256"]:
            _deny()
        return item, archive, receipt
    except Exception:
        raise StageDenied("native_linux_stage_denied") from None


def encode(*, target: str, release_sha: str,
           archive: bytes, receipt: bytes) -> bytes:
    """Local exact-SHA owner-reviewed CI transport fixture, no host writes."""
    if (target not in TARGETS or type(release_sha) is not str
        or SHA40.fullmatch(release_sha) is None
        or type(archive) is not bytes or type(receipt) is not bytes):
        _deny()
    data = {
        "schema": SCHEMA,
        "target": target,
        "release_sha": release_sha,
        "bundle_sha256": hashlib.sha256(archive).hexdigest(),
        "archive_b64": base64.b64encode(archive).decode("ascii"),
        "receipt_b64": base64.b64encode(receipt).decode("ascii"),
    }
    raw = _canonical(data)
    decode(raw, expected_target=target)
    return raw


def _trusted_dir(directory: Path, *, owner: int,
                 check_ancestors: bool = True) -> None:
    if not isinstance(directory, Path) or not directory.is_absolute():
        _deny()
    checks = (directory, *directory.parents) if check_ancestors else (directory,)
    for index, current in enumerate(checks):
        try:
            info = current.lstat()
            if (not stat.S_ISDIR(info.st_mode)
                or stat.S_ISLNK(info.st_mode)
                or info.st_mode & 0o022):
                _deny()
            if index == 0:
                if info.st_uid != owner or stat.S_IMODE(info.st_mode) != 0o700:
                    _deny()
            elif info.st_uid != 0:
                _deny()
        except (OSError, ValueError):
            _deny()


def _write_file(target: Path, data: bytes) -> None:
    fd = None
    created = False
    try:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | os.O_NOFOLLOW, 0o600)
        created = True
        with os.fdopen(fd, "wb") as stream:
            fd = None
            stream.write(data)
            stream.flush()
            os.fchmod(stream.fileno(), 0o600)
            os.fsync(stream.fileno())
    except Exception:
        if created:
            try:
                target.unlink()
            except OSError:
                pass
        _deny()
    finally:
        if fd is not None:
            os.close(fd)


def _leaf(root: Path, target: str, sha: str) -> Path:
    if target not in TARGETS or SHA40.fullmatch(sha) is None:
        _deny()
    return root / (target + "-" + sha)


def stage(frame: bytes, *, target: str, root: Path,
          owner_uid: int, check_ancestors: bool = True) -> dict[str, object]:
    _trusted_dir(root, owner=owner_uid, check_ancestors=check_ancestors)
    info, archive, receipt = decode(frame, expected_target=target)
    leaf = _leaf(root, target, info["release_sha"])
    created = False
    try:
        leaf.mkdir(mode=0o700)
        created = True
        _trusted_dir(leaf, owner=owner_uid, check_ancestors=False)
        _write_file(leaf / ARCHIVE_NAME, archive)
        _write_file(leaf / RECEIPT_NAME, receipt)
        return {
            "schema": REPORT_SCHEMA, "status": "SOURCE_STAGED_NOT_INSTALLED",
            "target": target, "release_sha": info["release_sha"],
            "bundle_sha256": info["bundle_sha256"],
            "service_installed": False, "native_device_paired": False,
            "original_host_files_touched": False,
        }
    except Exception:
        if created and not leaf.is_symlink() and leaf.is_dir():
            # The staging account owns this exclusive *new* private leaf.
            shutil.rmtree(leaf)
        _deny()


def cleanup(frame: bytes, *, target: str, root: Path,
            owner_uid: int, check_ancestors: bool = True) -> dict[str, object]:
    _trusted_dir(root, owner=owner_uid, check_ancestors=check_ancestors)
    info, archive, receipt = decode(frame, expected_target=target)
    leaf = _leaf(root, target, info["release_sha"])
    _trusted_dir(leaf, owner=owner_uid, check_ancestors=False)
    try:
        if {entry.name for entry in leaf.iterdir()} != {ARCHIVE_NAME, RECEIPT_NAME}:
            _deny()
        for name, data in ((ARCHIVE_NAME, archive), (RECEIPT_NAME, receipt)):
            path = leaf / name
            st = path.lstat()
            if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1
                or st.st_uid != owner_uid or stat.S_IMODE(st.st_mode) != 0o600
                or st.st_size != len(data)
                or path.read_bytes() != data):
                _deny()
        for name in (ARCHIVE_NAME, RECEIPT_NAME):
            (leaf / name).unlink()
        leaf.rmdir()
        return {
            "schema": REPORT_SCHEMA, "status": "SOURCE_STAGING_CLEANED",
            "target": target, "release_sha": info["release_sha"],
            "bundle_sha256": info["bundle_sha256"],
            "service_installed": False, "native_device_paired": False,
            "original_host_files_touched": False,
        }
    except Exception:
        raise StageDenied("native_linux_stage_denied") from None


def verify_report(raw: bytes, *, expected_target: str,
                  release_sha: str, bundle_sha256: str,
                  action: str) -> dict[str, object]:
    """Verify SSH response after pinned host authentication. No host effect."""
    try:
        if (type(raw) is not bytes or not 0 < len(raw) <= 2048
            or expected_target not in TARGETS or action not in ("stage", "cleanup")
            or SHA40.fullmatch(release_sha) is None
            or SHA64.fullmatch(bundle_sha256) is None):
            _deny()
        data = json.loads(raw.rstrip(b"\n").decode("ascii"),
                          object_pairs_hook=_unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        expected_status = (
            "SOURCE_STAGED_NOT_INSTALLED" if action == "stage"
            else "SOURCE_STAGING_CLEANED"
        )
        expected = {
            "schema": REPORT_SCHEMA, "status": expected_status,
            "target": expected_target, "release_sha": release_sha,
            "bundle_sha256": bundle_sha256,
            "service_installed": False, "native_device_paired": False,
            "original_host_files_touched": False,
        }
        if (type(data) is not dict or data != expected
            or raw not in (_canonical(expected), _canonical(expected) + b"\n")):
            _deny()
        return expected
    except Exception:
        raise StageDenied("native_linux_stage_denied") from None


def _forced_ssh_preflight(action: str) -> None:
    if (sys.platform != "linux" or os.geteuid() == 0
        or os.getegid() == 0
        or os.environ.get("SSH_ORIGINAL_COMMAND") != action
        or not sys.stdin.buffer.readable()
        or pwd.getpwuid(os.geteuid()).pw_name != ACCOUNT):
        _deny()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="H454 restricted native SSH staging")
    parser.add_argument("action", choices=("stage", "cleanup"))
    parser.add_argument("--target", choices=sorted(TARGETS), required=True)
    args = parser.parse_args(argv)
    try:
        _forced_ssh_preflight(args.action)
        raw = sys.stdin.buffer.read(MAX_FRAME + 1)
        operator = stage if args.action == "stage" else cleanup
        result = operator(
            raw, target=args.target, root=STAGING_ROOT,
            owner_uid=os.geteuid(), check_ancestors=True,
        )
        print(_canonical(result).decode("ascii"))
        return 0
    except Exception:
        print('{"status":"HOLD","reason":"NATIVE_SSH_STAGE_DENIED"}')
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
