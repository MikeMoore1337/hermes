"""Hermes #454: reproducible, source-only original-Linux READ candidate archive.

Never installs or starts any service, copies a host key, executes an agent,
connects to a VPS, or deploys anything. Only an isolated checkout at the
verified exact Git commit may produce this strictly selected source archive.
The target-scoped artifact is NOT an owner approval, OS sandbox, signed
provenance, runtime installer, or proof of real native host access.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tarfile
from typing import Final

SCHEMA: Final = "h454-native-linux-read-bundle-v1"
RECEIPT_SCHEMA: Final = "h454-native-linux-read-receipt-v1"
RELEASE_PATTERN = re.compile(r"[0-9a-f]{40}\Z")
BLOB_PATTERN = re.compile(r"[0-9a-f]{40}\Z")
TARGETS = frozenset({"hermes-vps", "yfc-vps"})
ARCHIVE_NAME: Final = "h454-native-linux-readonly.tar.gz"
RECEIPT_NAME: Final = "h454-native-bundle-receipt.json"
MANIFEST_NAME: Final = "h454-native-bundle-manifest.json"
MAX_FILE_SIZE = 256 * 1024
MAX_TOTAL_FILE_SIZE = 2 * 1024 * 1024
MAX_ARCHIVE_SIZE = 2 * 1024 * 1024
MAX_RECEIPT_SIZE = 4096
SOURCE_FILES: Final = tuple(sorted((
    "device_fabric/__init__.py",
    "device_fabric/linux_native_files.py",
    "device_fabric/linux_native_outbound.py",
    "device_fabric/linux_native_read_dispatch.py",
    "device_fabric/linux_native_search.py",
    "device_fabric/native_effect_grants.py",
    "device_fabric/native_install_preview.py",
    "scripts/h454_native_install_preflight.py",
    "scripts/h454_native_linux_runtime.py",
    "scripts/h454_native_linux_unit_candidate.py",
)))


class SourceBundleDenied(ValueError):
    """Never include a host original path, Git config, token or subprocess stderr."""


def _deny() -> None:
    raise SourceBundleDenied("native_source_bundle_denied")


def _json(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False,
    ).encode("ascii")


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for name, item in pairs:
        if name in value:
            _deny()
        value[name] = item
    return value


def _decode(raw: bytes) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_RECEIPT_SIZE + MAX_TOTAL_FILE_SIZE:
        _deny()
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, TypeError, RecursionError, OverflowError):
        _deny()
    if type(value) is not dict or raw != _json(value):
        _deny()
    return value


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _validate_ids(target: str, release_sha: str) -> None:
    if (type(target) is not str or target not in TARGETS
        or type(release_sha) is not str
        or RELEASE_PATTERN.fullmatch(release_sha) is None
        or release_sha == "0" * 40):
        _deny()


def _git(repository: Path, *argv: str) -> bytes:
    """Source-only fixed argv for the isolated CI checkout, never shell."""
    try:
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "LC_ALL": "C", "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0",
            "GIT_NO_LAZY_FETCH": "1",
        }
        run = subprocess.run(
            ["git", "-C", str(repository), *argv],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=10,
            env=env, check=True,
        )
    except (OSError, ValueError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired):
        _deny()
    return run.stdout


def _git_blob(repository: Path, sha: str, filename: str) -> bytes:
    """Read an exact regular Git blob, not modified working-tree files."""
    listing = _git(repository, "ls-tree", "-z", sha, "--", filename)
    parts = listing.split(b"\x00")
    if len(parts) != 2 or parts[1] != b"":
        _deny()
    try:
        mode, kind, oid, relative = re.fullmatch(
            rb"([0-9]{6}) ([a-z]+) ([0-9a-f]{40})\t(.+)", parts[0]
        ).groups()
    except (AttributeError, TypeError, ValueError):
        _deny()
    if (mode != b"100644" or kind != b"blob"
        or relative != filename.encode("ascii")
        or BLOB_PATTERN.fullmatch(oid.decode("ascii")) is None):
        _deny()
    size_raw = _git(repository, "cat-file", "-s", oid.decode("ascii"))
    try:
        size = int(size_raw)
    except (ValueError, OverflowError):
        _deny()
    if type(size) is not int or not 0 <= size <= MAX_FILE_SIZE:
        _deny()
    content = _git(repository, "cat-file", "blob", oid.decode("ascii"))
    if len(content) != size:
        _deny()
    return content


def collect_git_sources(repository: Path, *, release_sha: str) -> dict[str, bytes]:
    """Return EXACT vetted Git HEAD blobs without running Python source."""
    _validate_ids("hermes-vps", release_sha)
    try:
        if type(repository) is not Path or not repository.is_absolute() or repository.is_symlink():
            _deny()
        top = _git(repository, "rev-parse", "--show-toplevel").decode("utf-8").strip()
        actual = _git(repository, "rev-parse", "HEAD").decode("ascii").strip()
        if (Path(top).resolve(strict=True) != repository.resolve(strict=True)
            or actual != release_sha):
            _deny()
        sources = {name: _git_blob(repository, release_sha, name)
                   for name in SOURCE_FILES}
        if sum(len(item) for item in sources.values()) > MAX_TOTAL_FILE_SIZE:
            _deny()
    except (OSError, UnicodeError, ValueError, TypeError):
        _deny()
    return sources


def _manifest(*, target: str, release_sha: str,
              sources: dict[str, bytes]) -> bytes:
    _validate_ids(target, release_sha)
    if (type(sources) is not dict or set(sources) != set(SOURCE_FILES)
        or any(type(v) is not bytes or len(v) > MAX_FILE_SIZE
               for v in sources.values())
        or sum(len(v) for v in sources.values()) > MAX_TOTAL_FILE_SIZE):
        _deny()
    return _json({
        "schema": SCHEMA, "target": target,
        "release_sha": release_sha,
        "activation": "DISABLED",
        "install_authorized": False,
        "contains_secrets": False,
        "files": [
            {"path": path, "size": len(sources[path]),
             "sha256": _sha256(sources[path])}
            for path in SOURCE_FILES
        ],
    })


def _member(name: str, data: bytes) -> tuple[tarfile.TarInfo, bytes]:
    info = tarfile.TarInfo(name=name)
    info.size = len(data)
    info.mode = 0o444
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mtime = 0
    return info, data


def build_bytes(*, target: str, release_sha: str,
                sources: dict[str, bytes]) -> tuple[bytes, bytes]:
    """Render a deterministic, inert tar.gz and external checksum receipt."""
    manifest = _manifest(target=target, release_sha=release_sha, sources=sources)
    pairs = [_member(path, sources[path]) for path in SOURCE_FILES]
    pairs.append(_member(MANIFEST_NAME, manifest))
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb", filename="", compresslevel=9, mtime=0) as zipped:
        with tarfile.open(fileobj=zipped, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for header, body in pairs:
                archive.addfile(header, io.BytesIO(body))
    payload = buffer.getvalue()
    if len(payload) > MAX_ARCHIVE_SIZE:
        _deny()
    receipt = _json({
        "schema": RECEIPT_SCHEMA,
        "target": target, "release_sha": release_sha,
        "bundle_sha256": _sha256(payload),
        "manifest_sha256": _sha256(manifest),
        "source_count": len(SOURCE_FILES),
        "installation": "NOT_RUN", "activation": "DISABLED",
        "install_authorized": False, "provenance_signature": "NOT_PRESENT",
    })
    verify_bytes(payload, receipt, target=target, release_sha=release_sha)
    return payload, receipt


def verify_bytes(bundle: bytes, receipt: bytes, *,
                 target: str, release_sha: str) -> dict[str, object]:
    """Verify every selected member and receipt; NEVER extract or execute."""
    _validate_ids(target, release_sha)
    if (type(bundle) is not bytes or len(bundle) > MAX_ARCHIVE_SIZE
        or type(receipt) is not bytes or len(receipt) > MAX_RECEIPT_SIZE):
        _deny()
    record = _decode(receipt)
    if (set(record) != {
        "schema", "target", "release_sha", "bundle_sha256",
        "manifest_sha256", "source_count", "installation", "activation",
        "install_authorized", "provenance_signature"}
        or record["schema"] != RECEIPT_SCHEMA or record["target"] != target
        or record["release_sha"] != release_sha
        or record["bundle_sha256"] != _sha256(bundle)
        or type(record["source_count"]) is not int
        or record["source_count"] != len(SOURCE_FILES)
        or record["activation"] != "DISABLED"
        or record["installation"] != "NOT_RUN"
        or record["install_authorized"] is not False
        or record["provenance_signature"] != "NOT_PRESENT"):
        _deny()
    try:
        with tarfile.open(fileobj=io.BytesIO(bundle), mode="r:gz") as tar:
            # Scan at most the fixed allowlist cardinality plus one header.
            # A tiny highly compressed archive with arbitrary TAR entries
            # must not cause unbounded getmembers() allocations.
            contents: dict[str, bytes] = {}
            count = 0
            for member in tar:
                count += 1
                if count > len(SOURCE_FILES) + 1:
                    _deny()
                if (member.name not in set(SOURCE_FILES) | {MANIFEST_NAME}
                    or not member.isfile()
                    or member.mode != 0o444 or member.uid != 0 or member.gid != 0
                    or member.mtime != 0 or member.size < 0
                    or member.size > MAX_FILE_SIZE
                    or member.name in contents):
                    _deny()
                stream = tar.extractfile(member)
                if stream is None:
                    _deny()
                contents[member.name] = stream.read(MAX_FILE_SIZE + 1)
                if len(contents[member.name]) != member.size:
                    _deny()
    except (tarfile.TarError, OSError, EOFError, ValueError, OverflowError):
        _deny()
    if count != len(SOURCE_FILES) + 1 or set(contents) != set(SOURCE_FILES) | {MANIFEST_NAME}:
        _deny()
    manifest_bytes = contents.pop(MANIFEST_NAME)
    if record["manifest_sha256"] != _sha256(manifest_bytes):
        _deny()
    expected = _manifest(target=target, release_sha=release_sha, sources=contents)
    if manifest_bytes != expected:
        _deny()
    return {
        "status": "BUNDLE_SOURCE_VERIFIED",
        "target": target, "release_sha": release_sha,
        "bundle_sha256": record["bundle_sha256"],
        "source_count": len(SOURCE_FILES),
        "install_authorized": False, "connected": False,
        "service_installed": False, "changes_on_owner_host": False,
    }


def _private_output(out_dir: Path, *, require_empty: bool = True) -> None:
    """Only use a private, non-symlinked CI output directory."""
    try:
        if type(out_dir) is not Path or not out_dir.is_absolute():
            _deny()
        for ancestor in (out_dir, *out_dir.parents):
            if stat.S_ISLNK(ancestor.lstat().st_mode):
                _deny()
        info = out_dir.lstat()
        if (not stat.S_ISDIR(info.st_mode)
            or stat.S_IMODE(info.st_mode) != 0o700
            or (os.name == "posix" and info.st_uid != os.geteuid())
            or (require_empty and list(out_dir.iterdir()))):
            _deny()
    except (OSError, ValueError, TypeError):
        _deny()


def _read_private_artifact(path: Path, limit: int) -> bytes:
    """Read a single inode-bound private regular artifact, never follow links."""
    fd = None
    try:
        before = path.lstat()
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or before.st_size <= 0 or before.st_size > limit
            or (os.name == "posix"
                and (before.st_uid != os.geteuid() or before.st_mode & 0o077))):
            _deny()
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        opened = os.fstat(fd)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
            or opened.st_size != before.st_size
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            or (os.name == "posix"
                and (opened.st_uid != os.geteuid() or opened.st_mode & 0o077))):
            _deny()
        data = os.read(fd, limit + 1)
        after = os.fstat(fd)
        if (len(data) != before.st_size or after.st_mode != opened.st_mode
            or (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns)
                != (opened.st_dev, opened.st_ino, opened.st_mtime_ns, opened.st_ctime_ns)):
            _deny()
        return data
    except (OSError, ValueError, TypeError):
        _deny()
    finally:
        if fd is not None:
            os.close(fd)


def _exclusive_write(path: Path, data: bytes) -> None:
    fd = None
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as output:
            fd = None
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
    except (OSError, ValueError, TypeError):
        _deny()
    finally:
        if fd is not None:
            os.close(fd)


def build_from_git(*, repo: Path, target: str,
                   release_sha: str, out_dir: Path) -> dict[str, object]:
    """Generate files only in a precreated PRIVATE EMPTY CI output directory."""
    _private_output(out_dir)
    source = collect_git_sources(repo, release_sha=release_sha)
    bundle, receipt = build_bytes(target=target, release_sha=release_sha,
                                  sources=source)
    _exclusive_write(out_dir / ARCHIVE_NAME, bundle)
    _exclusive_write(out_dir / RECEIPT_NAME, receipt)
    return verify_bytes(bundle, receipt, target=target, release_sha=release_sha)


def verify_local(*, out_dir: Path, target: str,
                 release_sha: str) -> dict[str, object]:
    try:
        _private_output(out_dir, require_empty=False)
        if {item.name for item in out_dir.iterdir()} != {ARCHIVE_NAME, RECEIPT_NAME}:
            _deny()
        bundle = _read_private_artifact(out_dir / ARCHIVE_NAME, MAX_ARCHIVE_SIZE)
        receipt = _read_private_artifact(out_dir / RECEIPT_NAME, MAX_RECEIPT_SIZE)
        return verify_bytes(bundle, receipt, target=target, release_sha=release_sha)
    except (OSError, ValueError, TypeError):
        _deny()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="H454 offline native READ bundle only")
    modes = parser.add_subparsers(dest="mode", required=True)
    for mode in ("build", "verify"):
        command = modes.add_parser(mode)
        command.add_argument("--target", choices=sorted(TARGETS), required=True)
        command.add_argument("--release-sha", required=True)
        command.add_argument("--out-dir", type=Path, required=True)
        if mode == "build":
            command.add_argument("--repo", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.mode == "build":
            report = build_from_git(
                repo=args.repo, target=args.target,
                release_sha=args.release_sha, out_dir=args.out_dir)
        else:
            report = verify_local(
                out_dir=args.out_dir, target=args.target,
                release_sha=args.release_sha)
    except Exception:
        print(_json({"status": "HOLD",
                     "reason": "NATIVE_SOURCE_BUNDLE_DENIED",
                     "install_authorized": False,
                     "service_installed": False}).decode("ascii"))
        return 2
    print(_json(report).decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
