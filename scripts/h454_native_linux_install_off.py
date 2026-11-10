"""Hermes #454 Stage 2A: *disabled-only* original-Linux source installation.

This is a root-console operator for a future owner-approved procedure, NOT
a running native agent or an SSH forced-command implementation. It never
creates an account or device, provisions credentials, starts a service, or
changes an existing BRC/WSS component. The only installable unit is the
offline, PrivateNetwork=yes preflight oneshot with NO [Install] section.

CLI install/rollback are fail-closed unless run by root on an interactive
TTY, after the user reviews an exact SHA-scoped plan and types a fresh
confirmation string. An on-host root approval is not an authenticated
remote Control Center approval, and this does not enable future effects.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import io
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tarfile
from typing import Callable

from device_fabric.native_install_preview import parse_candidate
from scripts.h454_native_readonly_bundle import (
    _bounded_ustar, _read_private_artifact, MAX_ARCHIVE_SIZE,
    MAX_RECEIPT_SIZE, SOURCE_FILES, MANIFEST_NAME, verify_bytes,
)
from scripts.h454_native_linux_unit_candidate import (
    SERVICE_NAME, SERVICE_USER, render_preflight_unit,
)
from scripts.h454_native_install_preflight import _private_manifest

SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SHA64 = re.compile(r"[0-9a-f]{64}\Z")
SCHEMA = "h454-native-linux-disabled-install-v1"
TARGETS = frozenset({"hermes-vps", "yfc-vps"})
RELEASES = Path("/opt/hermes-commander-native/releases")
UNITS = Path("/etc/systemd/system")
RECEIPTS = Path("/opt/hermes-commander-native/receipts")
SYSTEMCTL = "/usr/bin/systemctl"
SOURCE_LIMIT = 256 * 1024


class DisabledInstallDenied(ValueError):
    """Never log source paths, OS error details, tokens or host data."""


@dataclass(frozen=True, slots=True, repr=False)
class DisabledPlan:
    target: str
    release_sha: str
    bundle_sha256: str
    manifest_sha256: str
    unit: bytes
    source: tuple[tuple[str, bytes], ...]

    def __repr__(self) -> str:
        return "DisabledPlan([REDACTED])"


@dataclass(frozen=True)
class InstallPaths:
    releases: Path = RELEASES
    units: Path = UNITS
    receipts: Path = RECEIPTS


def _deny() -> None:
    raise DisabledInstallDenied("native_linux_disabled_install_denied")


def plan_bytes(
    *, target: str, release_sha: str, bundle_sha256: str,
    manifest: bytes, bundle: bytes, receipt: bytes,
) -> DisabledPlan:
    """Validate before any host mutation. SHA must be approved externally.

    The source bundle's checksum receipt is NOT a cryptographic signature.
    Use only after separately checking the GitHub artifact origin/provenance.
    """
    try:
        if (target not in TARGETS or type(release_sha) is not str
            or SHA40.fullmatch(release_sha) is None
            or type(bundle_sha256) is not str
            or SHA64.fullmatch(bundle_sha256) is None
            or type(manifest) is not bytes
            or type(bundle) is not bytes
            or type(receipt) is not bytes
            or hashlib.sha256(bundle).hexdigest() != bundle_sha256):
            _deny()
        v = verify_bytes(bundle, receipt, target=target, release_sha=release_sha)
        candidate = parse_candidate(
            manifest, expected_release=release_sha, expected_target=target)
        if (v["bundle_sha256"] != bundle_sha256
            or candidate.artifact_sha256 != bundle_sha256):
            _deny()
        unit = render_preflight_unit(
            manifest, target=target, release_sha=release_sha,
            manifest_sha256=candidate.manifest_sha256,
        ).encode("ascii")
        # The bundle verifier has already rejected every unsafe TAR header,
        # link, extra member and compressed stream. Extract bytes *by hand*
        # from that same bounded in-memory authenticated candidate, not
        # via tar.extractall or an untrusted filename.
        raw = _bounded_ustar(bundle)
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            source = []
            for path in SOURCE_FILES:
                info = archive.getmember(path)
                file = archive.extractfile(info)
                if (file is None or info.size > SOURCE_LIMIT):
                    _deny()
                data = file.read(SOURCE_LIMIT + 1)
                if len(data) != info.size:
                    _deny()
                source.append((path, data))
        if (not source or len(source) != len(SOURCE_FILES)
            or b"[Install]\n" in unit
            or b"PrivateNetwork=yes\n" not in unit
            or b"ExecStart=/usr/bin/python3 -B -m scripts.h454_native_linux_runtime" not in unit):
            _deny()
        return DisabledPlan(
            target, release_sha, bundle_sha256,
            candidate.manifest_sha256, unit, tuple(source),
        )
    except Exception:
        raise DisabledInstallDenied("native_linux_disabled_install_denied") from None


def preview(plan: DisabledPlan) -> dict[str, object]:
    if type(plan) is not DisabledPlan:
        _deny()
    return {
        "status": "DISABLED_INSTALL_PLAN_ONLY",
        "target": plan.target,
        "release_sha": plan.release_sha,
        "bundle_sha256": plan.bundle_sha256,
        "manifest_sha256": plan.manifest_sha256,
        "source_file_count": len(plan.source),
        "service_name": SERVICE_NAME,
        "start_state": "DISABLED",
        "native_host_accepted": False,
        "owner_authenticated": False,
        "installed": False,
        "activated": False,
    }


def _directory(path: Path, *, uid: int, ancestors: bool) -> None:
    """Require root-owned nonwritable ancestors in real operator mode."""
    if not isinstance(path, Path) or not path.is_absolute():
        _deny()
    to_check = (path, *path.parents) if ancestors else (path,)
    for segment in to_check:
        try:
            info = segment.lstat()
            if (not stat.S_ISDIR(info.st_mode)
                or info.st_uid != uid
                or info.st_mode & 0o022):
                _deny()
        except (OSError, ValueError):
            _deny()


def _fixed_paths(plan: DisabledPlan, paths: InstallPaths) -> tuple[Path, Path, Path]:
    if type(plan) is not DisabledPlan or type(paths) is not InstallPaths:
        _deny()
    return (
        paths.releases / ("main-" + plan.release_sha),
        paths.units / SERVICE_NAME,
        paths.receipts / (plan.target + "-" + plan.release_sha + ".json"),
    )


def _write_new(path: Path, data: bytes, mode: int) -> None:
    fd = None
    created = False
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        created = True
        with os.fdopen(fd, "wb") as stream:
            fd = None
            stream.write(data)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
    except (OSError, ValueError):
        # A partial write is ours only if O_EXCL succeeded. Never unlink an
        # occupied path that another actor created first.
        if created:
            try:
                path.unlink()
            except OSError:
                pass
        _deny()
    finally:
        if fd is not None:
            os.close(fd)


def _source_tree(plan: DisabledPlan, release: Path) -> None:
    # The caller exclusively created the release directory before invoking
    # this writer; a losing concurrent call must never remove another tree.
    for item, content in plan.source:
        if (item not in SOURCE_FILES or item.startswith("/")
            or ".." in item.split("/")):
            _deny()
        dest = release.joinpath(*item.split("/"))
        for directory in (dest.parent, *dest.parent.parents):
            if directory == release:
                break
            if release not in directory.parents:
                _deny()
            directory.mkdir(mode=0o755, exist_ok=True)
        _write_new(dest, content, 0o444)


def _expected_receipt(plan: DisabledPlan) -> bytes:
    return json.dumps({
        "schema": SCHEMA,
        "target": plan.target,
        "release_sha": plan.release_sha,
        "bundle_sha256": plan.bundle_sha256,
        "manifest_sha256": plan.manifest_sha256,
        "unit_sha256": hashlib.sha256(plan.unit).hexdigest(),
        "source_sha256": {
            name: hashlib.sha256(data).hexdigest()
            for name, data in plan.source
        },
        "start_state": "DISABLED", "activated": False,
    }, sort_keys=True, separators=(",", ":")).encode("ascii")


def _verify_service_user() -> None:
    try:
        account = pwd.getpwnam(SERVICE_USER)
        if (account.pw_uid == 0 or account.pw_gid == 0
            or account.pw_shell not in ("/usr/sbin/nologin", "/sbin/nologin")):
            _deny()
    except Exception:
        _deny()


def _reload_daemon() -> None:
    try:
        proc = subprocess.run(
            [SYSTEMCTL, "daemon-reload"], capture_output=True,
            check=False, timeout=15,
        )
        if proc.returncode != 0:
            _deny()
    except Exception:
        _deny()


def _ensure_off(plan: DisabledPlan, paths: InstallPaths,
                *, owner_uid: int, ancestors: bool) -> None:
    if sys.platform != "linux":
        _deny()
    if type(plan) is not DisabledPlan:
        _deny()
    for path in (paths.releases, paths.units, paths.receipts):
        _directory(path, uid=owner_uid, ancestors=ancestors)
    if b"[Install]\n" in plan.unit or b"PrivateNetwork=yes\n" not in plan.unit:
        _deny()
    if len(plan.source) != len(SOURCE_FILES):
        _deny()


def _install_off(plan: DisabledPlan, *, paths: InstallPaths,
                 reload_daemon: Callable[[], None], owner_uid: int,
                 check_ancestors: bool) -> dict[str, object]:
    """Low-level exclusively creating writer, tested on temporary fixture.

    Not exposed as an unapproved CLI shortcut: callers must already be
    privileged and authenticated. The public CLI enforces root + exact TTY
    approval, but real installation still requires signed provenance.
    """
    _ensure_off(plan, paths, owner_uid=owner_uid, ancestors=check_ancestors)
    release, unit, receipt = _fixed_paths(plan, paths)
    if any(p.exists() or p.is_symlink() for p in (release, unit, receipt)):
        _deny()
    created_release = False
    created_unit = False
    created_receipt = False
    try:
        release.mkdir(mode=0o755)
        created_release = True
        _source_tree(plan, release)
        _write_new(unit, plan.unit, 0o644)
        created_unit = True
        _write_new(receipt, _expected_receipt(plan), 0o600)
        created_receipt = True
        reload_daemon()
        return {
            "status": "DISABLED_SOURCE_INSTALLED",
            "target": plan.target, "release_sha": plan.release_sha,
            "unit": SERVICE_NAME, "active": False,
            "device_paired": False, "owner_host_e2e": False,
        }
    except Exception:
        # Roll back ONLY the new artifacts this invocation created. Preserve
        # accounts, original files, credentials and existing services.
        if created_unit:
            unit.unlink(missing_ok=True)
        if created_receipt:
            receipt.unlink(missing_ok=True)
        if created_release and release.exists() and not release.is_symlink():
            shutil.rmtree(release)
        if created_unit:
            try:
                reload_daemon()
            except Exception:
                pass
        _deny()


def _validate_existing(plan: DisabledPlan, paths: InstallPaths) -> None:
    release, unit, receipt = _fixed_paths(plan, paths)
    try:
        if (_read_private_artifact(receipt, 4096) != _expected_receipt(plan)
            or unit.is_symlink() or not unit.is_file()
            or unit.read_bytes() != plan.unit
            or release.is_symlink() or not release.is_dir()):
            _deny()
        all_expected = set(SOURCE_FILES)
        actual = set()
        for file in release.rglob("*"):
            if file.is_symlink():
                _deny()
            if file.is_file():
                relative = file.relative_to(release).as_posix()
                actual.add(relative)
                if relative not in all_expected:
                    _deny()
                if file.stat().st_nlink != 1:
                    _deny()
        if actual != all_expected:
            _deny()
        for name, source in plan.source:
            target = release.joinpath(*name.split("/"))
            if (not target.is_file() or target.read_bytes() != source):
                _deny()
    except Exception:
        raise DisabledInstallDenied("native_linux_disabled_install_denied") from None


def _rollback_off(plan: DisabledPlan, *, paths: InstallPaths,
                  reload_daemon: Callable[[], None],
                  inactive: Callable[[str], bool], owner_uid: int,
                  check_ancestors: bool) -> dict[str, object]:
    _ensure_off(plan, paths, owner_uid=owner_uid, ancestors=check_ancestors)
    _validate_existing(plan, paths)
    release, unit, receipt = _fixed_paths(plan, paths)
    try:
        if inactive(SERVICE_NAME) is not True:
            _deny()
        # Safe deletion only after verifying all selected inode contents and
        # the exact inert unit. Never remove the dedicated account/state.
        unit.unlink()
        shutil.rmtree(release)
        reload_daemon()
        # Preserve a root-owned installation receipt for incident review.
        return {
            "status": "DISABLED_SOURCE_ROLLED_BACK",
            "target": plan.target, "release_sha": plan.release_sha,
            "receipt_preserved": receipt.exists(),
            "old_brc_wss_untouched": True,
        }
    except Exception:
        _deny()


def _require_interactive_root(plan: DisabledPlan, action: str) -> None:
    if (os.geteuid() != 0 or sys.platform != "linux"
        or not sys.stdin.isatty() or action not in {"INSTALL", "ROLLBACK"}):
        _deny()
    # Typed approval is an explicit local root-console decision, NOT a
    # replacement for verified artifact provenance or remote owner auth.
    challenge = (
        "H454 " + action + " OFF " + plan.target + " " +
        plan.release_sha + " " + plan.bundle_sha256
    )
    print("Confirm this exact OFFLINE action (no token):", file=sys.stderr)
    print(challenge, file=sys.stderr)
    try:
        given = input()
    except (EOFError, OSError, ValueError):
        _deny()
    if given != challenge:
        _deny()


def _is_inactive(unit: str) -> bool:
    try:
        proc = subprocess.run(
            [SYSTEMCTL, "is-active", unit],
            capture_output=True, check=False, timeout=8,
        )
        return proc.returncode == 3 and proc.stdout.strip() == b"inactive"
    except Exception:
        return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="H454 disabled Linux source install, owner-gated")
    parser.add_argument("mode", choices=("plan", "install-off", "rollback-off"))
    parser.add_argument("--target", choices=sorted(TARGETS), required=True)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--bundle-sha256", required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        planned = plan_bytes(
            target=args.target, release_sha=args.release_sha,
            bundle_sha256=args.bundle_sha256,
            manifest=_private_manifest(args.manifest),
            bundle=_read_private_artifact(args.bundle, MAX_ARCHIVE_SIZE),
            receipt=_read_private_artifact(args.receipt, MAX_RECEIPT_SIZE),
        )
        if args.mode == "plan":
            print(json.dumps(preview(planned), sort_keys=True))
            return 0
        _verify_service_user()
        _require_interactive_root(
            planned, "INSTALL" if args.mode == "install-off" else "ROLLBACK")
        if args.mode == "install-off":
            result = _install_off(
                planned, paths=InstallPaths(), reload_daemon=_reload_daemon,
                owner_uid=0, check_ancestors=True,
            )
        else:
            result = _rollback_off(
                planned, paths=InstallPaths(), reload_daemon=_reload_daemon,
                inactive=_is_inactive, owner_uid=0, check_ancestors=True,
            )
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception:
        print('{"status":"HOLD","reason":"H454_LINUX_DISABLED_INSTALL_DENIED"}')
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
