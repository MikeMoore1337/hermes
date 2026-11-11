"""H454: verified offline pure-Python websockets wheel for native Linux READ.

This is a first-time ROOT CONSOLE operator for a separately approved release.
It DOES NOT download packages or run pip, curl, shell, network, systemctl,
sudo, service start/enable, pairing or original-project file operations.
The exact universal Python wheel SHA-256 is published by PyPI on Oct 3, 2026.
An authorized owner root installer can stage it under an immutable release
path and roll it back only after verifying every staged byte.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import zipfile
from typing import NamedTuple

PACKAGE = "websockets"
VERSION = "17.2"
WHEEL = "websockets-17.2-py3-none-any.whl"
WHEEL_SHA256 = "6aa59f0ef92e796b2db6f5f26550c4713c0e4036899fadf02f55e2ed4db0b7ae"
RELEASE = re.compile(r"[a-f0-9]{40}\Z")
TARGETS = frozenset({"hermes-vps", "yfc-vps"})
ROOT = Path("/opt/hermes-commander-native/deps")
MAX_WHEEL_BYTES = 400_000
MAX_FILES = 240
MAX_UNCOMPRESSED = 3_000_000
MAX_SINGLE = 512_000
RECEIPT = ".h454-websockets-receipt.json"


class WheelDenied(ValueError):
    """Deny without leaking local paths or untrusted wheel exception text."""


class VerifiedWheel(NamedTuple):
    files: tuple[tuple[str, bytes], ...]
    sha256: str


def _deny():
    raise WheelDenied("h454_native_wheel_denied")


def verify_bytes(data: bytes) -> VerifiedWheel:
    """Full wheel fingerprint + bounded path inspection BEFORE any write."""
    try:
        if (type(data) is not bytes or not 1 <= len(data) <= MAX_WHEEL_BYTES
            or hashlib.sha256(data).hexdigest() != WHEEL_SHA256):
            _deny()
        files: dict[str, bytes] = {}
        with zipfile.ZipFile(io.BytesIO(data), mode="r") as archive:
            items = archive.infolist()
            if not 1 <= len(items) <= MAX_FILES:
                _deny()
            total = 0
            seen: set[str] = set()
            for info in items:
                name = info.filename
                if (type(name) is not str or not name or len(name) > 255
                    or name.startswith("/") or "\\" in name or "\x00" in name
                    or name in seen or any(part in ("", ".", "..")
                       for part in name.rstrip("/").split("/"))
                    or not (name.startswith("websockets/")
                            or name.startswith("websockets-17.2.dist-info/"))
                    or info.flag_bits & 0x01
                    or info.compress_type not in
                       (zipfile.ZIP_DEFLATED, zipfile.ZIP_STORED)):
                    _deny()
                seen.add(name)
                mode = (info.external_attr >> 16) & 0o170000
                if mode not in (0, stat.S_IFDIR, stat.S_IFREG):
                    _deny()
                if info.is_dir():
                    if info.file_size != 0: _deny()
                    continue
                if (info.file_size < 0 or info.file_size > MAX_SINGLE
                    or any(name.lower().endswith(ext) for ext in
                      (".pth", ".pyc", ".so", ".pyd", ".dll", ".exe", ".sh"))):
                    _deny()
                total += info.file_size
                if total > MAX_UNCOMPRESSED:
                    _deny()
                content = archive.read(info)
                if len(content) != info.file_size:
                    _deny()
                files[name] = content
        for required in (
            "websockets/__init__.py",
            "websockets/sync/client.py",
            "websockets-17.2.dist-info/METADATA",
            "websockets-17.2.dist-info/WHEEL",
            "websockets-17.2.dist-info/RECORD",
        ):
            if required not in files:
                _deny()
        metadata = files["websockets-17.2.dist-info/METADATA"]
        wheel_info = files["websockets-17.2.dist-info/WHEEL"]
        if (b"Name: websockets\n" not in metadata
            or b"Version: 17.2\n" not in metadata
            or b"Root-Is-Purelib: true\n" not in wheel_info
            or b"Tag: py3-none-any\n" not in wheel_info):
            _deny()
        return VerifiedWheel(tuple(sorted(files.items())), WHEEL_SHA256)
    except Exception:
        raise WheelDenied("h454_native_wheel_denied") from None


def _dir(path: Path, *, owner_uid: int, ancestors: bool) -> None:
    if not isinstance(path, Path) or not path.is_absolute():
        _deny()
    for idx, item in enumerate((path, *path.parents) if ancestors else (path,)):
        try:
            info = item.lstat()
            if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_mode & 0o022
                or info.st_uid != (owner_uid if idx == 0 else 0)):
                _deny()
        except OSError:
            _deny()


def _target(root: Path, release_sha: str) -> Path:
    if type(release_sha) is not str or RELEASE.fullmatch(release_sha) is None:
        _deny()
    return root / ("main-" + release_sha)


def _receipt(target: str, release_sha: str, wheel: VerifiedWheel) -> bytes:
    return json.dumps({
        "schema": "h454-native-python-wheel-v1",
        "target": target,
        "release_sha": release_sha,
        "name": PACKAGE,
        "version": VERSION,
        "wheel_sha256": wheel.sha256,
        "files_sha256": {
            name: hashlib.sha256(data).hexdigest()
            for name, data in wheel.files
        },
        "native_started": False,
    }, sort_keys=True, separators=(",", ":")).encode("ascii")


def _create_only(path: Path, content: bytes, mode: int = 0o444) -> None:
    fd = None
    created = False
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        created = True
        with os.fdopen(fd, "wb") as stream:
            fd = None
            stream.write(content)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
    except Exception:
        if created:
            try: path.unlink()
            except OSError: pass
        _deny()
    finally:
        if fd is not None:
            os.close(fd)


def _new_tree(root: Path, leaf: Path, wheel: VerifiedWheel,
              receipt: bytes) -> None:
    if leaf.exists() or leaf.is_symlink():
        _deny()
    created = False
    try:
        leaf.mkdir(mode=0o755)
        created = True
        for name, contents in wheel.files:
            dest = leaf.joinpath(*name.split("/"))
            relative_dirs = dest.parent.relative_to(leaf).parts
            folder = leaf
            for component in relative_dirs:
                folder = folder / component
                if not folder.exists():
                    folder.mkdir(mode=0o755)
                _dir(folder, owner_uid=os.geteuid(), ancestors=False)
            _create_only(dest, contents)
        _create_only(leaf / RECEIPT, receipt, mode=0o444)
    except Exception:
        if created and leaf.is_dir() and not leaf.is_symlink():
            shutil.rmtree(leaf)
        _deny()


def stage_wheel(
    data: bytes, *, target: str, release_sha: str,
    root: Path = ROOT, owner_uid: int = 0,
    check_ancestors: bool = True,
) -> dict[str, object]:
    if target not in TARGETS:
        _deny()
    wheel = verify_bytes(data)
    _dir(root, owner_uid=owner_uid, ancestors=check_ancestors)
    dest = _target(root, release_sha)
    _new_tree(root, dest, wheel, _receipt(target, release_sha, wheel))
    return {
        "status": "PINNED_WHEEL_STAGED_ONLY",
        "target": target, "release_sha": release_sha,
        "wheel_sha256": wheel.sha256,
        "files": len(wheel.files),
        "system_python_unmodified": True,
        "native_service_started": False,
    }


def rollback_wheel(
    data: bytes, *, target: str, release_sha: str,
    root: Path = ROOT, owner_uid: int = 0,
    check_ancestors: bool = True,
) -> dict[str, object]:
    if target not in TARGETS:
        _deny()
    wheel = verify_bytes(data)
    _dir(root, owner_uid=owner_uid, ancestors=check_ancestors)
    leaf = _target(root, release_sha)
    try:
        _dir(leaf, owner_uid=owner_uid, ancestors=False)
        expected = {name:data for name,data in wheel.files}
        expected[RECEIPT] = _receipt(target, release_sha, wheel)
        actual: set[str] = set()
        for path in leaf.rglob("*"):
            st = path.lstat()
            if st.st_uid != owner_uid or stat.S_ISLNK(st.st_mode):
                _deny()
            if stat.S_ISDIR(st.st_mode):
                if st.st_mode & 0o022:
                    _deny()
                continue
            if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1
                or stat.S_IMODE(st.st_mode) != 0o444):
                _deny()
            relative = path.relative_to(leaf).as_posix()
            if relative not in expected or path.read_bytes() != expected[relative]:
                _deny()
            actual.add(relative)
        if actual != set(expected):
            _deny()
        # Only the exact new immutable wheel/receipt subtree is removed.
        shutil.rmtree(leaf)
        return {
            "status": "PINNED_WHEEL_ROLLED_BACK",
            "target": target, "release_sha": release_sha,
            "wheel_sha256": wheel.sha256,
            "other_releases_preserved": True,
            "native_service_started": False,
        }
    except Exception:
        raise WheelDenied("h454_native_wheel_denied") from None


def _read_source(path: Path) -> bytes:
    fd = None
    try:
        st = path.lstat()
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1
            or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o600
            or st.st_size > MAX_WHEEL_BYTES):
            _deny()
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream:
            fd = None
            content = stream.read(MAX_WHEEL_BYTES + 1)
            if len(content) != st.st_size: _deny()
            return content
    except Exception:
        raise WheelDenied("h454_native_wheel_denied") from None
    finally:
        if fd is not None:
            os.close(fd)


def main(argv: list[str] | None = None) -> int:
    """No unattended root operation; owner reviews exact fingerprint."""
    parser = argparse.ArgumentParser(description="H454 immutable Python wheel staging")
    parser.add_argument("action", choices=("install-offline", "rollback-offline"))
    parser.add_argument("--target", choices=sorted(TARGETS), required=True)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--wheel", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if (sys.platform != "linux" or os.geteuid() != 0
            or not sys.stdin.isatty() or not sys.stdout.isatty()):
            _deny()
        payload = _read_source(args.wheel)
        verify_bytes(payload)
        phrase = "H454 " + args.action.upper() + " WHEEL " + args.target + \
                 " " + args.release_sha + " " + WHEEL_SHA256
        print(phrase, flush=True)
        if input("Confirm exact action: ") != phrase:
            _deny()
        fn = stage_wheel if args.action == "install-offline" else rollback_wheel
        result = fn(payload, target=args.target, release_sha=args.release_sha)
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception:
        print('{"status":"HOLD","reason":"H454_WHEEL_INSTALL_DENIED"}')
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
