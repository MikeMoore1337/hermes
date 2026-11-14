#!/usr/bin/env python3
"""H454: exact-version, disabled-only original Hermes VPS native migration.

No remote shell, no service activation/enabling, no device enrollment, no BRC/WSS
mutation. This is a separate owner-root TTY operator, not a production deploy.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import pwd
import re
import socket
import stat
import subprocess
import sys
import tarfile

from device_fabric.native_install_preview import parse_candidate
from scripts.h454_native_readonly_bundle import (
    SOURCE_FILES, _bounded_ustar, verify_bytes as verify_bundle,
)
from scripts.h454_native_linux_wheel import (
    stage_wheel, verify_bytes as verify_wheel,
)
from scripts.h454_native_linux_unit_candidate import render_preflight_unit
from scripts.h454_native_linux_active_unit import render_active_unit

OLD = "8a159e0ba2e575dcdb0a2c2fee9e8d5651065da4"
NEW = "e8887bfb7a04aaff9cbb91a1c46003fcd8d5347a"
SOURCE_SHA = "9263a72b746273240fdd0ea96c4d3256b86d3430ce532b54a139841a671afac9"
WHEEL_SHA = "6aa59f0ef92e796b2db6f5f26550c4713c0e4036899fadf02f55e2ed4db0b7ae"
OLD_MANIFEST_SHA = "fa3abc717c0dc211897941ebdb8f8a23a824c2369057ecd441edc7eafcd47062"
OLD_HASHES = {
    "hermes-commander-native-preflight.service": "b036ab8858898b471f0102047833a1afb13635d05319173d0f7d043911213460",
    "hermes-commander-native.service": "828e9f6993fbc5fdd8f8b2964c4f0cccc6008d6e2eb783c23ba750a7005129f2",
}
OLD_RECEIPTS = {
    "preflight-receipt.json": "daf3dce38a17f4c6d2d478adadd36bb846931745fee79da9063f45bf6bac7e6b",
    "active-receipt.json": "e8a780825f04d2ca4835075f75e1e20b1f76b9956c72016e5baffec8660b1c73",
}
TARGET = "hermes-vps"
WORKER = "hermes-commander-native"
MAX_SOURCE = 2_097_152
MAX_WHEEL = 400_000

@dataclass(frozen=True)
class Paths:
    base: Path = Path("/opt/hermes-commander-native")
    state: Path = Path("/var/lib/hermes-commander-native")
    units: Path = Path("/etc/systemd/system")
    staged: Path = Path("/root/h454-native-stage/main-" + NEW + "/hermes-vps")

    @property
    def backup(self) -> Path:
        return self.base / "receipts" / ("h454-migration-" + NEW)

    @property
    def source(self) -> Path:
        return self.base / "releases" / ("main-" + NEW)

    @property
    def dependencies(self) -> Path:
        return self.base / "deps" / ("main-" + NEW)

    @property
    def old_source(self) -> Path:
        return self.base / "releases" / ("main-" + OLD)

    @property
    def old_dependencies(self) -> Path:
        return self.base / "deps" / ("main-" + OLD)


class Hold(ValueError):
    """Sanitized denial; original project paths and secrets never printed."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise Hold(code)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def secure_dir(path: Path, *, uid: int = 0) -> None:
    for directory in (path, *path.parents):
        s = directory.lstat()
        require(stat.S_ISDIR(s.st_mode) and s.st_uid == uid and not s.st_mode & 0o022,
                "UNSAFE_DIRECTORY")


def bounded_read(path: Path, limit: int, *, owners: set[int], private: bool) -> bytes:
    for parent in path.parents:
        require(not parent.is_symlink(), "SYMLINK_PARENT")
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and before.st_uid in owners and 0 < before.st_size <= limit
            and not before.st_mode & (0o077 if private else 0o022),
            "UNSAFE_FILE")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC), "rb") as stream:
        opened = os.fstat(stream.fileno())
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    fields = ("st_dev", "st_ino", "st_size", "st_ctime_ns", "st_mtime_ns", "st_mode")
    require(all(getattr(before, k) == getattr(opened, k) == getattr(after, k)
                for k in fields) and len(data) == before.st_size,
            "FILE_CHANGED")
    return data


def new_file(path: Path, data: bytes, mode: int = 0o600, uid: int | None = None,
             gid: int | None = None) -> None:
    fd = None
    created = False
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        created = True
        with os.fdopen(fd, "wb") as f:
            fd = None
            if uid is not None:
                os.fchown(f.fileno(), uid, gid if gid is not None else -1)
            f.write(data)
            f.flush()
            os.fchmod(f.fileno(), mode)
            os.fsync(f.fileno())
    except Exception:
        if created:
            path.unlink(missing_ok=True)
        raise Hold("NEW_FILE_FAILED") from None
    finally:
        if fd is not None:
            os.close(fd)


def replace_file(path: Path, data: bytes, mode: int, uid: int, gid: int) -> None:
    sibling = path.with_name(".h454-migrate-" + NEW[:12] + "-" + path.name)
    require(not sibling.exists() and not sibling.is_symlink(), "TEMP_NAME_COLLISION")
    try:
        new_file(sibling, data, mode, uid, gid)
        os.replace(sibling, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if sibling.exists():
            sibling.unlink()


def systemd_show(name: str) -> dict[str, str]:
    proc = subprocess.run(
        ["/usr/bin/systemctl", "show", name, "--no-pager", "--property="
         "FragmentPath,LoadState,ActiveState,UnitFileState,User,Group,DropInPaths,"
         "NeedDaemonReload,RestrictSUIDSGID,NoNewPrivileges,ProtectSystem,PrivateNetwork"],
        capture_output=True, check=False, timeout=8,
    )
    require(proc.returncode == 0 and len(proc.stdout) <= 4096, "SYSTEMD_UNVERIFIED")
    return dict(line.split("=", 1) for line in proc.stdout.decode("ascii").splitlines()
                if "=" in line)


def check_units(paths: Paths, *, migrated: bool) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    for name, old_hash in OLD_HASHES.items():
        data = bounded_read(paths.units / name, 16_384, owners={0}, private=False)
        if not migrated:
            require(sha(data) == old_hash and OLD.encode() in data, "UNIT_DRIFT")
        shown = systemd_show(name)
        expected = {
            "FragmentPath": str(paths.units / name),
            "LoadState": "loaded", "ActiveState": "inactive",
            "UnitFileState": "static" if "preflight" in name else "disabled",
            "User": WORKER, "Group": WORKER, "DropInPaths": "",
            "NeedDaemonReload": "no", "NoNewPrivileges": "yes",
            "ProtectSystem": "strict",
            "RestrictSUIDSGID": "no" if migrated else "yes",
            "PrivateNetwork": "yes" if "preflight" in name else "no",
        }
        require(all(shown.get(k) == v for k, v in expected.items()), "UNIT_STATUS_DRIFT")
        out[name] = data
    return out


def docker_snapshot() -> tuple[str, ...]:
    names = (
        "hermes-brc-relay", "hermes-h454-wss-proxy",
        "hermes-brc-relay-h454-native3-v2-rollback",
        "hermes-h454-wss-proxy-h454-native3-v2-rollback",
    )
    proc = subprocess.run(["/usr/bin/docker", "inspect", "--format",
                           "{{.Name}}|{{.Id}}|{{.Image}}|{{.State.Running}}|{{.HostConfig.NetworkMode}}",
                           *names], capture_output=True, timeout=12, check=False)
    require(proc.returncode == 0, "DOCKER_UNVERIFIED")
    lines = tuple(proc.stdout.decode("ascii").splitlines())
    require(len(lines) == 4 and lines[0].startswith("/hermes-brc-relay|")
            and "|true|" in lines[0] and "|true|" in lines[1]
            and "|false|" in lines[2] and "|false|" in lines[3], "DOCKER_DRIFT")
    return lines


def relay_ips(old_active: bytes) -> tuple[str, str]:
    import ipaddress
    match = re.findall(rb"^IPAddressAllow=([0-9.]+)/32$", old_active, re.MULTILINE)
    allowed = {m.decode("ascii") for m in match}
    require(len(match) == len(allowed) and 2 <= len(allowed) <= 3,
            "RELAY_IP_PIN_INVALID")
    actual = {a[4][0] for a in socket.getaddrinfo(
        "hermes.mikemoore.top", 443, family=socket.AF_INET,
        type=socket.SOCK_STREAM)}
    dns = allowed - actual
    require(len(actual) in (1, 2) and actual <= allowed and len(dns) == 1,
            "RELAY_DNS_PIN_DRIFT")
    # render_active_unit verifies public relay IPv4 and loopback/public DNS.
    return ",".join(sorted(actual)), next(iter(dns))


@dataclass(frozen=True)
class Candidate:
    old_manifest: bytes
    new_manifest: bytes
    old_units: dict[str, bytes]
    new_units: dict[str, bytes]
    old_receipts: dict[str, bytes]
    manifest_owner: tuple[int, int]
    bundle: bytes
    receipt: bytes
    wheel: bytes
    source: dict[str, bytes]
    docker: tuple[str, ...]


def inspect(paths: Paths, *, require_absent: bool = True) -> Candidate:
    """Complete read-only admission: no original project file content is read."""
    require(os.geteuid() == 0 and sys.platform == "linux", "ROOT_LINUX_REQUIRED")
    identity = pwd.getpwnam(WORKER)
    require(identity.pw_uid > 0 and identity.pw_gid > 0 and
            identity.pw_shell in ("/usr/sbin/nologin", "/sbin/nologin"),
            "UNSAFE_NATIVE_ACCOUNT")
    for folder in (paths.base / "releases", paths.base / "deps",
                   paths.base / "receipts", paths.units, paths.staged):
        if folder != paths.staged:
            secure_dir(folder)
    secure_dir(paths.staged)
    require(paths.old_source.is_dir() and not paths.old_source.is_symlink()
            and paths.old_dependencies.is_dir() and not paths.old_dependencies.is_symlink(),
            "OLD_DEPENDENCIES_UNVERIFIED")
    secure_dir(paths.old_source)
    secure_dir(paths.old_dependencies)
    if require_absent:
        require(not paths.source.exists() and not paths.source.is_symlink()
                and not paths.dependencies.exists() and not paths.dependencies.is_symlink()
                and not paths.backup.exists() and not paths.backup.is_symlink(),
                "NEW_VERSION_ALREADY_PRESENT")
    private_manifest_path = paths.state / "manifest.json"
    raw = bounded_read(private_manifest_path, 8192, owners={0, identity.pw_uid},
                       private=True)
    require(sha(raw) == OLD_MANIFEST_SHA, "MANIFEST_DRIFT")
    current = parse_candidate(raw, expected_release=OLD, expected_target=TARGET)
    require(len(current.roots) == 1 and current.roots[0][0] == "hermes",
            "ROOT_SCOPE_CHANGED")
    require(not (paths.state / "device.json").exists()
            and not (paths.state / "device.json").is_symlink(),
            "DEVICE_ALREADY_PAIRED")
    old_units = check_units(paths, migrated=False)
    for name in OLD_HASHES:
        require(stat.S_IMODE((paths.units / name).lstat().st_mode) == 0o644,
                "OLD_UNIT_MODE_DRIFT")
    old_receipts = {}
    for filename, digest in OLD_RECEIPTS.items():
        original = (paths.base / "receipts" /
                    (TARGET + "-" + OLD + ("-active.json" if filename.startswith("active") else ".json")))
        value = bounded_read(original, 8192, owners={0}, private=True)
        require(sha(value) == digest, "OLD_RECEIPT_DRIFT")
        old_receipts[filename] = value
    bundle = bounded_read(paths.staged / "h454-native-linux-readonly.tar.gz",
                          MAX_SOURCE, owners={0}, private=True)
    receipt = bounded_read(paths.staged / "h454-native-bundle-receipt.json",
                           4096, owners={0}, private=True)
    wheel = bounded_read(paths.staged / "wheel/websockets-17.2-py3-none-any.whl",
                         MAX_WHEEL, owners={0}, private=True)
    require(sha(bundle) == SOURCE_SHA and sha(wheel) == WHEEL_SHA,
            "NEW_ARTIFACT_DIGEST_DRIFT")
    report = verify_bundle(bundle, receipt, target=TARGET, release_sha=NEW)
    require(report["status"] == "BUNDLE_SOURCE_VERIFIED", "NEW_SOURCE_UNVERIFIED")
    verify_wheel(wheel)
    source = {}
    with tarfile.open(fileobj=io.BytesIO(_bounded_ustar(bundle)), mode="r:") as archive:
        for name in SOURCE_FILES:
            member = archive.getmember(name)
            require(member.isfile() and member.size < 262144, "SOURCE_MEMBER_INVALID")
            source[name] = archive.extractfile(member).read()
    require(len(source) == 13 and b'"RestrictSUIDSGID=no",' in
            source["scripts/h454_native_linux_unit_candidate.py"]
            and b'"RestrictSUIDSGID=yes",' not in
            source["scripts/h454_native_linux_unit_candidate.py"],
            "NEW_PREFLIGHT_SOURCE_NOT_FIXED")
    obj = json.loads(raw.decode("ascii"))
    obj["release_sha"] = NEW
    obj["artifact_sha256"] = SOURCE_SHA
    new_manifest = json.dumps(obj, sort_keys=True, separators=(",", ":"),
                              ensure_ascii=True, allow_nan=False).encode("ascii")
    planned = parse_candidate(new_manifest, expected_release=NEW, expected_target=TARGET)
    require(planned.roots == current.roots and planned.service_identity == WORKER,
            "MANIFEST_SCOPE_CHANGED")
    manifest_sha = sha(new_manifest)
    preflight_text = render_preflight_unit(
        new_manifest, target=TARGET, release_sha=NEW, manifest_sha256=manifest_sha)
    require(preflight_text.count("RestrictSUIDSGID=yes\n") +
            preflight_text.count("RestrictSUIDSGID=no\n") == 1, "PREFLIGHT_RESTRICT_INVALID")
    # The currently deployed trusted owner source is one commit behind #894.
    # Re-render the legacy preflight then apply only its audited one-line fix.
    preflight_text = preflight_text.replace("RestrictSUIDSGID=yes\n",
                                            "RestrictSUIDSGID=no\n")
    relay, dns = relay_ips(old_units["hermes-commander-native.service"])
    active_text = render_active_unit(
        new_manifest, target=TARGET, release_sha=NEW, manifest_sha256=manifest_sha,
        relay_ipv4=relay, dns_ipv4=dns,
    )
    require("RestrictSUIDSGID=no\n" in active_text
            and "NoNewPrivileges=yes\n" in active_text
            and "PrivateNetwork=yes\n" in preflight_text
            and "[Install]\n" not in preflight_text
            and "[Install]\n" in active_text,
            "NEW_UNIT_HARDENING_INVALID")
    unit_map = {
        "hermes-commander-native-preflight.service": preflight_text.encode("ascii"),
        "hermes-commander-native.service": active_text.encode("ascii"),
    }
    metadata = private_manifest_path.lstat()
    require(metadata.st_uid in {0, identity.pw_uid} and not metadata.st_mode & 0o077,
            "MANIFEST_PERMISSIONS_DRIFT")
    return Candidate(raw, new_manifest, old_units, unit_map, old_receipts,
                     (metadata.st_uid, metadata.st_gid), bundle, receipt, wheel,
                     source, docker_snapshot())


def summary(candidate: Candidate) -> dict[str, str | bool]:
    return {
        "status": "VERSIONED_MIGRATION_PLAN_PASS",
        "target": TARGET,
        "old_release": OLD,
        "new_release": NEW,
        "source_sha256": SOURCE_SHA,
        "wheel_sha256": WHEEL_SHA,
        "new_manifest_sha256": sha(candidate.new_manifest),
        "preflight_unit_sha256": sha(candidate.new_units["hermes-commander-native-preflight.service"]),
        "active_unit_sha256": sha(candidate.new_units["hermes-commander-native.service"]),
        "original_roots_preserved": True,
        "device_paired": False,
        "service_started": False,
        "brc_wss_unchanged": True,
    }


def create_backup(paths: Paths, c: Candidate) -> None:
    require(not paths.backup.exists(), "BACKUP_ALREADY_EXISTS")
    paths.backup.mkdir(mode=0o700)
    copies = {
        "old-manifest.json": c.old_manifest,
        "old-preflight.service": c.old_units["hermes-commander-native-preflight.service"],
        "old-active.service": c.old_units["hermes-commander-native.service"],
        "new-manifest.json": c.new_manifest,
        "new-preflight.service": c.new_units["hermes-commander-native-preflight.service"],
        "new-active.service": c.new_units["hermes-commander-native.service"],
        **c.old_receipts,
    }
    for name, data in copies.items():
        new_file(paths.backup / name, data)
    new_file(paths.backup / "candidate.json", json.dumps(summary(c), sort_keys=True,
             separators=(",", ":")).encode("ascii"))
    for name, data in copies.items():
        require(bounded_read(paths.backup / name, 16384, owners={0}, private=True) == data,
                "BACKUP_READBACK_FAILED")


def stage_source(paths: Paths, c: Candidate) -> None:
    root = paths.source
    require(not root.exists() and not root.is_symlink(), "SOURCE_ALREADY_PRESENT")
    root.mkdir(mode=0o755)
    root.chmod(0o755)  # umask 077 must not hide immutable code from service UID
    for name, content in c.source.items():
        entry = root.joinpath(*name.split("/"))
        entry.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        for folder in entry.parents:
            if folder == root:
                break
            require(root in folder.parents, "SOURCE_PATH_ESCAPE")
            require(folder.is_dir() and not folder.is_symlink()
                    and folder.lstat().st_uid == os.geteuid(), "SOURCE_DIR_UNSAFE")
            folder.chmod(0o755)
        new_file(entry, content, 0o444)
    for name, content in c.source.items():
        require(bounded_read(root / name, 262144, owners={os.geteuid()},
                             private=False) == content, "SOURCE_READBACK_FAILED")
    require(len([p for p in root.rglob("*") if p.is_file()]) == len(SOURCE_FILES),
            "SOURCE_FILE_COUNT_INVALID")


def make_new_deps_readable(paths: Paths) -> None:
    """Fix root's 077 umask only on *new*, verified wheel directories."""
    root = paths.dependencies
    require(root.is_dir() and not root.is_symlink(), "NEW_DEPS_UNAVAILABLE")
    for folder in (root, *(p for p in root.rglob("*") if p.is_dir())):
        st = folder.lstat()
        require(stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode)
                and st.st_uid == 0 and not st.st_mode & 0o022,
                "NEW_DEPS_DIR_UNSAFE")
        folder.chmod(0o755)
    require((root / "websockets/sync/client.py").is_file(),
            "NEW_DEPS_CONTENT_INVALID")


def daemon_reload() -> None:
    proc = subprocess.run(["/usr/bin/systemctl", "daemon-reload"],
                          capture_output=True, timeout=15, check=False)
    require(proc.returncode == 0, "SYSTEMD_RELOAD_FAILED")


def verify_installed(paths: Paths, c: Candidate) -> None:
    require(sha(bounded_read(paths.state / "manifest.json", 8192,
             owners={0, c.manifest_owner[0]}, private=True)) == sha(c.new_manifest),
             "NEW_MANIFEST_READBACK_FAILED")
    observed = check_units(paths, migrated=True)
    for name, data in c.new_units.items():
        require(observed[name] == data, "NEW_UNIT_READBACK_FAILED")
    for name, content in c.source.items():
        require(bounded_read(paths.source / name, 262144, owners={0}, private=False)
                == content, "NEW_SOURCE_READBACK_FAILED")
    require((paths.dependencies / "websockets/sync/client.py").is_file(),
            "NEW_DEPS_READBACK_FAILED")
    require(docker_snapshot() == c.docker, "DOCKER_CHANGED_DURING_MIGRATION")
    require(paths.old_source.is_dir() and paths.old_dependencies.is_dir(),
            "OLD_SOURCE_OR_DEPS_LOST")


def apply(paths: Paths, c: Candidate) -> None:
    create_backup(paths, c)
    stage_source(paths, c)
    stage_wheel(c.wheel, target=TARGET, release_sha=NEW,
                root=paths.base / "deps", owner_uid=os.geteuid(),
                check_ancestors=True)
    make_new_deps_readable(paths)
    # Re-check original units and manifest after staging, immediately before
    # overwriting any existing file. No other writer may silently win.
    require(check_units(paths, migrated=False) == c.old_units,
            "OLD_UNIT_CHANGED_BEFORE_SWITCH")
    require(bounded_read(paths.state / "manifest.json", 8192,
                         owners={0, c.manifest_owner[0]}, private=True)
            == c.old_manifest, "OLD_MANIFEST_CHANGED_BEFORE_SWITCH")
    require(docker_snapshot() == c.docker, "DOCKER_CHANGED_BEFORE_SWITCH")
    # Unit files are replaced as individual atomic renames while both are inactive.
    # An immutable private backup is already on disk for recovery after power loss.
    for name, content in c.new_units.items():
        replace_file(paths.units / name, content, 0o644, 0, 0)
    replace_file(paths.state / "manifest.json", c.new_manifest, 0o600,
                 *c.manifest_owner)
    daemon_reload()
    verify_installed(paths, c)
    new_file(paths.backup / "success", b"INSTALLED_DISABLED\n")


def _backup(paths: Paths) -> dict[str, bytes]:
    require(paths.backup.is_dir() and not paths.backup.is_symlink(),
            "BACKUP_UNAVAILABLE")
    secure_dir(paths.backup)
    names = ("old-manifest.json", "old-preflight.service", "old-active.service",
             "new-manifest.json", "new-preflight.service", "new-active.service",
             "preflight-receipt.json", "active-receipt.json", "candidate.json")
    copied = {
        name: bounded_read(paths.backup / name, 16_384, owners={0}, private=True)
        for name in names
    }
    require(sha(copied["old-manifest.json"]) == OLD_MANIFEST_SHA
            and sha(copied["old-preflight.service"]) ==
            OLD_HASHES["hermes-commander-native-preflight.service"]
            and sha(copied["old-active.service"]) ==
            OLD_HASHES["hermes-commander-native.service"]
            and sha(copied["preflight-receipt.json"]) == OLD_RECEIPTS["preflight-receipt.json"]
            and sha(copied["active-receipt.json"]) == OLD_RECEIPTS["active-receipt.json"],
            "BACKUP_DRIFT")
    record = json.loads(copied["candidate.json"].decode("ascii"))
    require(record.get("old_release") == OLD and record.get("new_release") == NEW
            and record.get("new_manifest_sha256") == sha(copied["new-manifest.json"])
            and record.get("preflight_unit_sha256") == sha(copied["new-preflight.service"])
            and record.get("active_unit_sha256") == sha(copied["new-active.service"]),
            "BACKUP_NEW_CANDIDATE_DRIFT")
    new = parse_candidate(copied["new-manifest.json"],
                          expected_release=NEW, expected_target=TARGET)
    old = parse_candidate(copied["old-manifest.json"],
                          expected_release=OLD, expected_target=TARGET)
    require(new.roots == old.roots and new.artifact_sha256 == SOURCE_SHA,
            "BACKUP_MANIFEST_DRIFT")
    return copied


def restore(paths: Paths, backup: dict[str, bytes]) -> None:
    """Only restores old approved bytes over old/new known bytes; no deletion."""
    # Treat a pending systemd manager reload as expected after a crash.
    for name in OLD_HASHES:
        shown = systemd_show(name)
        require(shown.get("LoadState") == "loaded"
                and shown.get("ActiveState") == "inactive"
                and shown.get("UnitFileState") ==
                ("static" if "preflight" in name else "disabled")
                and shown.get("DropInPaths") == ""
                and shown.get("User") == WORKER
                and shown.get("Group") == WORKER,
                "ROLLBACK_UNIT_NOT_INACTIVE")
    current = bounded_read(paths.state / "manifest.json", 8192,
                           owners={0, pwd.getpwnam(WORKER).pw_uid}, private=True)
    require(sha(current) in {sha(backup["old-manifest.json"]),
                             sha(backup["new-manifest.json"])},
            "ROLLBACK_MANIFEST_DRIFT")
    mapping = {
        "hermes-commander-native-preflight.service":
            ("old-preflight.service", "new-preflight.service"),
        "hermes-commander-native.service":
            ("old-active.service", "new-active.service"),
    }
    for name, (old, new) in mapping.items():
        data = bounded_read(paths.units / name, 16384, owners={0}, private=False)
        require(sha(data) in {sha(backup[old]), sha(backup[new])},
                "ROLLBACK_UNIT_DRIFT")
    manifest = paths.state / "manifest.json"
    original = manifest.lstat()
    for name, (old, _new) in mapping.items():
        replace_file(paths.units / name, backup[old], 0o644, 0, 0)
    replace_file(manifest, backup["old-manifest.json"], 0o600,
                 original.st_uid, original.st_gid)
    daemon_reload()
    for name, (old, _new) in mapping.items():
        require(sha(bounded_read(paths.units / name, 16384,
                    owners={0}, private=False)) == sha(backup[old]),
                "ROLLBACK_UNIT_READBACK_FAILED")
    require(sha(bounded_read(manifest, 8192,
                    owners={0, original.st_uid}, private=True)) == OLD_MANIFEST_SHA,
            "ROLLBACK_MANIFEST_READBACK_FAILED")
    check_units(paths, migrated=False)


def owner_tty(action: str, manifest_hash: str, active_hash: str) -> None:
    require(os.geteuid() == 0 and sys.stdin.isatty() and sys.stdout.isatty(),
            "OWNER_TTY_REQUIRED")
    phrase = ("H454 " + action + " DISABLED " + TARGET + " " + NEW + " "
              + manifest_hash + " " + active_hash)
    with open("/dev/tty", "r", encoding="ascii") as source, \
         open("/dev/tty", "w", encoding="ascii") as sink:
        sink.write("Confirm exact disabled native migration (no service start):\n"
                   + phrase + "\n> ")
        sink.flush()
        require(source.readline(320).strip() == phrase, "OWNER_CONFIRMATION_DENIED")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "install-off", "rollback-off"))
    args = parser.parse_args(argv)
    paths = Paths()
    try:
        require(os.geteuid() == 0, "OWNER_ROOT_REQUIRED")
        if args.mode == "plan":
            print(json.dumps(summary(inspect(paths)), sort_keys=True))
            return 0
        with open("/run/lock/h454-native-versioned-migrate.lock", "a+b", buffering=0) as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            if args.mode == "install-off":
                candidate = inspect(paths)
                owner_tty("INSTALL", sha(candidate.new_manifest),
                          sha(candidate.new_units["hermes-commander-native.service"]))
                # Admission repeated after explicit owner consent.
                candidate = inspect(paths)
                try:
                    apply(paths, candidate)
                except Exception:
                    if paths.backup.is_dir():
                        restore(paths, _backup(paths))
                    raise
                print("H454_NATIVE_VERSIONED_MIGRATION=INSTALLED_DISABLED")
                print("H454_OLD_UNIT_BACKUPS=PRESERVED")
                print("H454_NATIVE_PAIRED=NO")
                print("H454_BRC_WSS_CHANGED=NO")
                return 0
            require(args.mode == "rollback-off", "MODE_INVALID")
            backup = _backup(paths)
            owner_tty("ROLLBACK", sha(backup["new-manifest.json"]),
                      sha(backup["new-active.service"]))
            require(docker_snapshot(), "DOCKER_UNVERIFIED")
            restore(paths, backup)
            if not (paths.backup / "rollback-success").exists():
                new_file(paths.backup / "rollback-success", b"RESTORED_OLD_DISABLED\n")
            print("H454_NATIVE_VERSIONED_MIGRATION=ROLLED_BACK_DISABLED")
            print("H454_NEW_SOURCE_AND_DEPS_RETAINED=YES")
            print("H454_BRC_WSS_CHANGED=NO")
            return 0
    except (Hold, OSError, ValueError, KeyError, json.JSONDecodeError, subprocess.TimeoutExpired):
        print("H454_NATIVE_VERSIONED_MIGRATION=HOLD")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())