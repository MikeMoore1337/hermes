#!/usr/bin/env python3
"""H454: original Hermes VPS inert source/private-TLS unit upgrade, e888 -> 30db.

Source-only code. ``plan`` is read-only. ``install-off``/``rollback-off`` are
interactive owner-root-only actions, requiring a separately approved exact
host plan. Never starts/enables services, pairs devices or changes BRC/WSS.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import fcntl
import importlib
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import ssl
import stat
import subprocess
import sys
import tarfile

from device_fabric.native_install_preview import parse_candidate
from scripts.h454_native_readonly_bundle import _bounded_ustar
from scripts.h454_native_linux_wheel import stage_wheel, verify_bytes as verify_wheel
from scripts.h454_native_linux_unit_candidate import render_preflight_unit
from scripts.h454_native_linux_active_unit import render_active_unit

PREVIOUS = "e8887bfb7a04aaff9cbb91a1c46003fcd8d5347a"
CURRENT = "30db4fbab46626985b078d574dbe0b839872840e"
OWNER_SOURCE = "82a51cc0d718e16e6d0be8869436359a06fc94b7"
BUNDLE_SHA = "c61fd03785b5ffda9cc24b058ae779ad4514fb79d276769e21b48f8059a6e111"
MANIFEST_SOURCE_SHA = "9d58b7ddced287cb9eaa8a1e7874946a8b4757175ec70bb7e5f594664454e059"
WHEEL_SHA = "6aa59f0ef92e796b2db6f5f26550c4713c0e4036899fadf02f55e2ed4db0b7ae"
OLD_MANIFEST_SHA = "2fa2794f11d562ec2f2ec7317dac94c3a068bba1449f50268c55dbd8b227a2a1"
OLD_UNITS = {
    "hermes-commander-native-preflight.service": "f8fad39f621838b2d8e98eaeec6a7a59f8ce6d9d8a218f4824719ffe1308b019",
    "hermes-commander-native.service": "d4970ff3bb024e044ada9ac3c8d285e92c1edf9c9ad24005ab357017b55b059a",
}
FIRST_BACKUP = "h454-migration-" + PREVIOUS
SERVICE_USER = "hermes-commander-native"
TARGET = "hermes-vps"
SOURCE_FILES = tuple(sorted((
    "device_fabric/__init__.py",
    "device_fabric/linux_native_files.py",
    "device_fabric/linux_native_outbound.py",
    "device_fabric/linux_native_read_dispatch.py",
    "device_fabric/linux_native_search.py",
    "device_fabric/native_brc_enrollment.py",
    "device_fabric/native_brc_status.py",
    "device_fabric/native_effect_grants.py",
    "device_fabric/native_install_preview.py",
    "device_fabric/native_private_tls.py",
    "scripts/h454_native_install_preflight.py",
    "scripts/h454_native_linux_runtime.py",
    "scripts/h454_native_linux_service.py",
    "scripts/h454_native_linux_unit_candidate.py",
)))
BACKUP_ITEMS = (
    "old-manifest.json", "old-preflight.service", "old-active.service",
    "new-manifest.json", "new-preflight.service", "new-active.service",
    "old-first-backup-success", "old-first-backup-candidate.json",
    "ca.crt", "private-relay.json", "plan.json",
)

class UpgradeHold(ValueError):
    """Fail closed without exposing private owner paths or secret payload."""


def guard(ok: bool, reason: str) -> None:
    if not ok:
        raise UpgradeHold(reason)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def owned_directory(path: Path, *, owner=0, mode=None) -> None:
    guard(path.is_absolute(), "DIR_NOT_ABSOLUTE")
    for element in (path, *path.parents):
        meta = element.lstat()
        guard(stat.S_ISDIR(meta.st_mode) and meta.st_uid == 0
              and not meta.st_mode & 0o022, "UNSAFE_DIRECTORY")
    meta = path.lstat()
    guard(meta.st_uid == owner and (mode is None or stat.S_IMODE(meta.st_mode) == mode),
          "DIRECTORY_OWNER_OR_MODE")


def checked_file(path: Path, limit: int, *, owner=0, private=False,
                 modes=None) -> bytes:
    for element in path.parents:
        guard(not element.is_symlink(), "SYMLINK_PARENT")
    before = path.lstat()
    guard(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
          and before.st_uid == owner and 0 < before.st_size <= limit
          and not before.st_mode & (0o077 if private else 0o022)
          and (modes is None or stat.S_IMODE(before.st_mode) in modes),
          "UNSAFE_FILE")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC), "rb") as stream:
        inside = os.fstat(stream.fileno())
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    fields = ("st_dev", "st_ino", "st_size", "st_ctime_ns", "st_mtime_ns", "st_mode")
    guard(len(raw) == before.st_size and all(
          getattr(before, key) == getattr(inside, key) == getattr(after, key)
          for key in fields), "FILE_CHANGED")
    return raw


def create_file(path: Path, value: bytes, mode=0o600, *, uid=0, gid=0) -> None:
    created = False
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        created = True
        with os.fdopen(fd, "wb") as output:
            os.fchown(output.fileno(), uid, gid)
            os.fchmod(output.fileno(), mode)
            output.write(value)
            output.flush()
            os.fsync(output.fileno())
    except Exception:
        if created:
            path.unlink(missing_ok=True)
        raise UpgradeHold("CREATE_FILE_FAILED") from None


def atomic_replace(path: Path, value: bytes, *, mode: int, uid: int, gid: int) -> None:
    side = path.with_name(".h454-upgrade-" + CURRENT[:12] + "-" + path.name)
    guard(not side.exists() and not side.is_symlink(), "SIBLING_COLLISION")
    try:
        create_file(side, value, mode, uid=uid, gid=gid)
        os.replace(side, path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if side.exists():
            side.unlink()


def raw_show(unit: str) -> dict[str, str]:
    keys = (
        "FragmentPath,LoadState,ActiveState,UnitFileState,User,Group,"
        "DropInPaths,NeedDaemonReload,RestrictSUIDSGID,NoNewPrivileges,"
        "ProtectSystem,PrivateNetwork,IPAddressDeny,IPAddressAllow"
    )
    result = subprocess.run(
        ["/usr/bin/systemctl", "show", unit, "--no-pager", "--property=" + keys],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        timeout=10, check=False,
    )
    guard(result.returncode == 0 and len(result.stdout) < 16384, "SYSTEMD_UNAVAILABLE")
    lines = result.stdout.decode("ascii").splitlines()
    guard(len(lines) == len(set(lines)), "SYSTEMD_DUPLICATE")
    return dict(line.split("=", 1) for line in lines if "=" in line)


def check_units(paths: "Paths", *, current=False) -> dict[str, bytes]:
    found = {}
    for unit, expected in OLD_UNITS.items():
        raw = checked_file(paths.units / unit, 16384, modes={0o644})
        if not current:
            guard(digest(raw) == expected and PREVIOUS.encode() in raw, "OLD_UNIT_CHANGED")
        state = raw_show(unit)
        required = {
            "FragmentPath": str(paths.units / unit),
            "LoadState": "loaded", "ActiveState": "inactive",
            "UnitFileState": "static" if "preflight" in unit else "disabled",
            "User": SERVICE_USER, "Group": SERVICE_USER,
            "DropInPaths": "", "NeedDaemonReload": "no",
            "RestrictSUIDSGID": "no", "NoNewPrivileges": "yes",
            "ProtectSystem": "strict",
            "PrivateNetwork": "yes" if "preflight" in unit else "no",
        }
        guard(all(state.get(k) == v for k, v in required.items()), "UNIT_STATE_CHANGED")
        found[unit] = raw
    return found


def docker_snapshot() -> tuple[str, ...]:
    containers = (
        "hermes-brc-relay", "hermes-h454-wss-proxy",
        "hermes-brc-relay-h454-native3-v2-rollback",
        "hermes-h454-wss-proxy-h454-native3-v2-rollback",
    )
    result = subprocess.run(
        ["/usr/bin/docker", "inspect", "--format",
         "{{.Name}}|{{.Id}}|{{.Image}}|{{.State.Running}}|{{.HostConfig.NetworkMode}}",
         *containers], capture_output=True, check=False, timeout=15,
    )
    guard(result.returncode == 0, "DOCKER_UNAVAILABLE")
    lines = tuple(result.stdout.decode("ascii").splitlines())
    guard(len(lines) == 4 and lines[0].startswith("/hermes-brc-relay|")
          and "|true|" in lines[0] and "|true|" in lines[1]
          and "|false|" in lines[2] and "|false|" in lines[3], "DOCKER_PAIR_CHANGED")
    return lines


def unique(pairs):
    result = {}
    for name, value in pairs:
        guard(name not in result, "DUPLICATE_JSON_FIELD")
        result[name] = value
    return result


def canonical(record: dict) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def verified_source(bundle: bytes, receipt: bytes) -> dict[str, bytes]:
    """Only exact known 30db source TAR with verified 14-file canonical manifest."""
    guard(digest(bundle) == BUNDLE_SHA and len(bundle) <= 2_097_152, "NEW_BUNDLE_CHANGED")
    meta = json.loads(receipt, object_pairs_hook=unique)
    guard(canonical(meta) == receipt and meta == {
        "schema": "h454-native-linux-read-receipt-v1",
        "target": TARGET, "release_sha": CURRENT,
        "bundle_sha256": BUNDLE_SHA, "manifest_sha256": MANIFEST_SOURCE_SHA,
        "source_count": 14, "installation": "NOT_RUN", "activation": "DISABLED",
        "install_authorized": False, "provenance_signature": "NOT_PRESENT",
    }, "RECEIPT_DRIFT")
    out = {}
    with tarfile.open(fileobj=io.BytesIO(_bounded_ustar(bundle)), mode="r:") as opened:
        for member in opened:
            guard(member.name in (*SOURCE_FILES, "h454-native-bundle-manifest.json")
                  and member.name not in out
                  and member.isfile() and member.mode == 0o444
                  and member.uid == member.gid == 0 and member.mtime == 0
                  and 0 <= member.size < 262144,
                  "UNTRUSTED_TAR_MEMBER")
            data = opened.extractfile(member).read(262145)
            guard(len(data) == member.size, "SOURCE_MEMBER_CORRUPT")
            out[member.name] = data
    manifest = out.pop("h454-native-bundle-manifest.json")
    guard(set(out) == set(SOURCE_FILES) and digest(manifest) == MANIFEST_SOURCE_SHA,
          "MANIFEST_OR_SOURCE_FILES_DRIFT")
    structure = json.loads(manifest, object_pairs_hook=unique)
    guard(canonical(structure) == manifest and structure["target"] == TARGET
          and structure["release_sha"] == CURRENT
          and structure["schema"] == "h454-native-linux-read-bundle-v1"
          and structure["activation"] == "DISABLED"
          and structure["install_authorized"] is False
          and structure["contains_secrets"] is False
          and len(structure["files"]) == 14, "SOURCE_MANIFEST_INVALID")
    guard({entry["path"] for entry in structure["files"]} == set(SOURCE_FILES),
          "SOURCE_MANIFEST_PATH_SET_DRIFT")
    for item in structure["files"]:
        guard(set(item) == {"path", "size", "sha256"}
              and item["path"] in SOURCE_FILES
              and item["size"] == len(out[item["path"]])
              and digest(out[item["path"]]) == item["sha256"],
              "SOURCE_FILE_HASH_DRIFT")
    # The new private connector and revised service must be present.
    guard(b"def load_private_relay" in out["device_fabric/native_private_tls.py"]
          and b"private_websocket_connector" in out["scripts/h454_native_linux_service.py"],
          "PRIVATE_RUNTIME_ABSENT")
    return out


def private_relay(paths: "Paths") -> tuple[str, bytes, bytes]:
    """Use existing protected proxy pins, not Cloudflare or a guessed IP."""
    owned_directory(paths.wss, mode=0o700)
    pins_raw = checked_file(paths.wss / "pins.json", 16384, private=True,
                            modes={0o600})
    pins = json.loads(pins_raw, object_pairs_hook=unique)
    guard(pins.get("version") == 1 and
          pins.get("relay_name") == "hermes-brc-relay" and
          pins.get("sidecar_name") == "hermes-h454-wss-proxy" and
          pins.get("relay_ipv4") != pins.get("gateway_ipv4") and
          isinstance(pins.get("tls_directory"), str) and
          isinstance(pins.get("ca_sha256"), str) and
          re.fullmatch("[a-f0-9]{64}", pins["ca_sha256"]) is not None,
          "WSS_PIN_DRIFT")
    ip = ipaddress.IPv4Address(pins["relay_ipv4"])
    guard(str(ip) == pins["relay_ipv4"] and any(ip in network for network in (
        ipaddress.IPv4Network("10.0.0.0/8"), ipaddress.IPv4Network("172.16.0.0/12"),
        ipaddress.IPv4Network("192.168.0.0/16"))), "PRIVATE_IP_INVALID")
    ca_dir = Path(pins["tls_directory"])
    owned_directory(ca_dir, mode=0o700)
    ca = checked_file(ca_dir / "ca.crt", 8192, modes={0o444})
    guard(digest(ca) == pins["ca_sha256"] and ca.startswith(b"-----BEGIN CERTIFICATE-----")
          and ca.count(b"-----BEGIN CERTIFICATE-----") == 1,
          "CA_PIN_DRIFT")
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    tls.load_verify_locations(cadata=ca.decode("ascii"))
    config = canonical({
        "schema": "h454-private-relay-v1", "target": TARGET,
        "release_sha": CURRENT, "relay_ipv4": str(ip), "port": 3001,
        "server_name": "brc-agent.internal", "ca_sha256": digest(ca),
    })
    return str(ip), ca, config



LEGACY_SOURCE_BLOBS = {
    "scripts/h454_native_linux_active_unit.py": "5076629a87a4c0cd20dbfbdc7d614a6e254408cf",
    "scripts/h454_native_linux_unit_candidate.py": "104723ec0e33350e45ea8f9690f84204630f11c8",
    "scripts/h454_native_readonly_bundle.py": "26c1fac60616889e2fb5b91f1ac314e4193d58e5",
    "scripts/h454_native_linux_wheel.py": "831f2cb49c748c8bc3c1ed830fe51272ffdd19ba",
    "device_fabric/native_install_preview.py": "72b1e8661bb170db81412203f29deea40fddf56e",
}

def guard_legacy_imports() -> None:
    """Run against the already installed owner-source release, not a mutable checkout."""
    source = Path("/opt/hermes-agent-owner/releases/main-" + OWNER_SOURCE)
    guard(source.is_dir() and not source.is_symlink(), "LEGACY_SOURCE_UNAVAILABLE")
    for name, blob_sha in LEGACY_SOURCE_BLOBS.items():
        loaded = importlib.import_module(name.replace("/", ".").removesuffix(".py"))
        path = Path(loaded.__file__)
        guard(path == source / name, "SOURCE_IMPORT_DRIFT")
        data = checked_file(path, 150000)
        header = b"blob " + str(len(data)).encode("ascii") + b"\x00"
        guard(hashlib.sha1(header + data).hexdigest() == blob_sha, "SOURCE_GIT_BLOB_DRIFT")

@dataclass(frozen=True)
class Paths:
    base: Path = Path("/opt/hermes-commander-native")
    state: Path = Path("/var/lib/hermes-commander-native")
    units: Path = Path("/etc/systemd/system")
    wss: Path = Path("/var/lib/hermes-h454-wss-sidecar")
    staged: Path = Path("/root/h454-native-stage/main-" + CURRENT + "/hermes-vps")
    wheel: Path = Path("/root/h454-native-stage/main-" + PREVIOUS + "/hermes-vps/wheel/websockets-17.2-py3-none-any.whl")

    @property
    def old_source(self) -> Path:
        return self.base / "releases" / ("main-" + PREVIOUS)

    @property
    def old_deps(self) -> Path:
        return self.base / "deps" / ("main-" + PREVIOUS)

    @property
    def source(self) -> Path:
        return self.base / "releases" / ("main-" + CURRENT)

    @property
    def deps(self) -> Path:
        return self.base / "deps" / ("main-" + CURRENT)

    @property
    def trust(self) -> Path:
        return self.base / "trust"

    @property
    def backup(self) -> Path:
        return self.base / "receipts" / ("h454-private-migration-" + CURRENT)

    @property
    def first_backup(self) -> Path:
        return self.base / "receipts" / FIRST_BACKUP


@dataclass(frozen=True)
class Preview:
    manifest_old: bytes
    manifest_new: bytes
    unit_old: dict[str, bytes]
    unit_new: dict[str, bytes]
    source: dict[str, bytes]
    bundle: bytes
    ca: bytes
    trust: bytes
    wheel: bytes
    old_backup: dict[str, bytes]
    origin_docker: tuple[str, ...]
    manifest_uid: int
    manifest_gid: int
    relay_ipv4: str


def _unit_rendered(new_manifest: bytes, relay_ipv4: str) -> dict[str, bytes]:
    """Transform the existing pinned legacy renderer to the exact private unit.

    Active legacy renderer is the audited 5076629a Git blob from the installed
    source-only owner release. Changes match PR #897's private_relay=True branch.
    """
    manifest_sha = digest(new_manifest)
    preflight = render_preflight_unit(new_manifest, target=TARGET,
                                       release_sha=CURRENT, manifest_sha256=manifest_sha)
    guard(preflight.count("RestrictSUIDSGID=yes\n") == 1,
          "LEGACY_PREFLIGHT_RENDERER_CHANGED")
    preflight = preflight.replace("RestrictSUIDSGID=yes\n", "RestrictSUIDSGID=no\n")
    # An older trusted public-renderer can create the private candidate only
    # after a bounded transformation of three fixed, audited line groups.
    # The rendered public /32s are used only as an inert source-string fixture.
    active = render_active_unit(new_manifest, target=TARGET,
                                release_sha=CURRENT, manifest_sha256=manifest_sha,
                                relay_ipv4="8.8.8.8", dns_ipv4="1.1.1.1")
    anchors = (
        ('AssertPathExists=/opt/hermes-commander-native/deps/main-' + CURRENT +
         '/websockets/sync/client.py\n',
         'AssertPathExists=/opt/hermes-commander-native/deps/main-' + CURRENT +
         '/websockets/sync/client.py\n'
         'AssertPathExists=/opt/hermes-commander-native/trust/private-relay.json\n'
         'AssertPathExists=/opt/hermes-commander-native/trust/ca.crt\n'),
        ('IPAddressAllow=8.8.8.8/32\nIPAddressAllow=1.1.1.1/32\n',
         'IPAddressAllow=' + relay_ipv4 + '/32\n'),
        ('ReadOnlyPaths=/var/lib/hermes-commander-native\n',
         'ReadOnlyPaths=/var/lib/hermes-commander-native\n'
         'ReadOnlyPaths=/opt/hermes-commander-native/trust\n'),
    )
    for old, new in anchors:
        guard(active.count(old) == 1, "UNIT_TRANSFORM_ANCHOR_MISMATCH")
        active = active.replace(old, new)
    guard(active.count("IPAddressAllow=") == 1 and
          active.count("RestrictSUIDSGID=no\n") == 1 and
          "IPAddressDeny=any\n" in active,
          "NEW_PRIVATE_UNIT_INVALID")
    return {
        "hermes-commander-native-preflight.service": preflight.encode("ascii"),
        "hermes-commander-native.service": active.encode("ascii"),
    }


def inspect(paths: Paths) -> Preview:
    guard(os.geteuid() == 0 and sys.platform == "linux", "ROOT_LINUX_REQUIRED")
    guard_legacy_imports()
    identity = pwd.getpwnam(SERVICE_USER)
    guard(identity.pw_uid > 0 and identity.pw_gid > 0 and
          identity.pw_shell in ("/usr/sbin/nologin", "/sbin/nologin"),
          "NATIVE_IDENTITY_CHANGED")
    for directory in (paths.base / "releases", paths.base / "deps",
                      paths.base / "receipts", paths.units, paths.staged):
        owned_directory(directory)
    owned_directory(paths.old_source)
    owned_directory(paths.old_deps)
    owned_directory(paths.first_backup, mode=0o700)
    guard(all(not p.exists() and not p.is_symlink() for p in
              (paths.source, paths.deps, paths.trust, paths.backup)),
          "UPGRADE_ALREADY_STAGED")
    backup = {
        "old-first-backup-success": checked_file(
            paths.first_backup / "success", 128, private=True, modes={0o600}),
        "old-first-backup-candidate.json": checked_file(
            paths.first_backup / "candidate.json", 4096, private=True, modes={0o600}),
    }
    guard(backup["old-first-backup-success"] == b"INSTALLED_DISABLED\n",
          "PREVIOUS_MIGRATION_INCOMPLETE")
    first_manifest = checked_file(paths.first_backup / "new-manifest.json", 8192,
                                  private=True, modes={0o600})
    first_preflight = checked_file(paths.first_backup / "new-preflight.service", 16384,
                                   private=True, modes={0o600})
    first_active = checked_file(paths.first_backup / "new-active.service", 16384,
                                private=True, modes={0o600})
    guard(digest(first_manifest) == OLD_MANIFEST_SHA
          and digest(first_preflight) == OLD_UNITS["hermes-commander-native-preflight.service"]
          and digest(first_active) == OLD_UNITS["hermes-commander-native.service"],
          "PREVIOUS_BACKUP_DRIFT")
    previous = json.loads(backup["old-first-backup-candidate.json"], object_pairs_hook=unique)
    guard(previous["new_release"] == PREVIOUS and
          previous["new_manifest_sha256"] == OLD_MANIFEST_SHA and
          previous["preflight_unit_sha256"] == OLD_UNITS["hermes-commander-native-preflight.service"] and
          previous["active_unit_sha256"] == OLD_UNITS["hermes-commander-native.service"],
          "PREVIOUS_MIGRATION_DRIFT")
    current_manifest = paths.state / "manifest.json"
    owner = current_manifest.lstat().st_uid
    guard(owner in (0, identity.pw_uid), "MANIFEST_OWNER_CHANGED")
    raw = checked_file(current_manifest, 8192,
                       owner=owner, private=True, modes={0o600})
    guard(digest(raw) == OLD_MANIFEST_SHA, "OLD_MANIFEST_CHANGED")
    candidate_old = parse_candidate(raw, expected_release=PREVIOUS, expected_target=TARGET)
    guard(len(candidate_old.roots) == 1 and candidate_old.roots[0][0] == "hermes",
          "ROOT_SCOPE_CHANGED")
    guard(not (paths.state / "device.json").exists()
          and not (paths.state / "device.json").is_symlink(),
          "DEVICE_ALREADY_PAIRED")
    old_units = check_units(paths)
    owned_directory(paths.staged, mode=0o700)
    artifact = checked_file(paths.staged / "h454-native-linux-readonly.tar.gz",
                            2_097_152, private=True, modes={0o600})
    receipt = checked_file(paths.staged / "h454-native-bundle-receipt.json",
                           4096, private=True, modes={0o600})
    sources = verified_source(artifact, receipt)
    wheel = checked_file(paths.wheel, 400_000, private=True, modes={0o600})
    guard(digest(wheel) == WHEEL_SHA, "WHEEL_DRIFT")
    verify_wheel(wheel)
    relay_ip, ca, trust = private_relay(paths)
    config = json.loads(raw, object_pairs_hook=unique)
    config["release_sha"] = CURRENT
    config["artifact_sha256"] = BUNDLE_SHA
    new_manifest = canonical(config)
    candidate_new = parse_candidate(new_manifest, expected_release=CURRENT,
                                    expected_target=TARGET)
    guard(candidate_old.roots == candidate_new.roots and
          candidate_new.service_identity == SERVICE_USER,
          "NATIVE_MANIFEST_SCOPE_CHANGED")
    new_units = _unit_rendered(new_manifest, relay_ip)
    meta = (paths.state / "manifest.json").lstat()
    guard(meta.st_uid == owner, "MANIFEST_OWNER_CHANGED_DURING_PLAN")
    return Preview(raw, new_manifest, old_units, new_units, sources, artifact,
                   ca, trust, wheel, backup, docker_snapshot(), meta.st_uid,
                   meta.st_gid, relay_ip)


def plan_result(candidate: Preview) -> dict:
    return {
        "status": "H454_PRIVATE_UPGRADE_PLAN_PASS",
        "target": TARGET, "old_release": PREVIOUS, "new_release": CURRENT,
        "source_sha256": BUNDLE_SHA, "wheel_sha256": WHEEL_SHA,
        "manifest_sha256": digest(candidate.manifest_new),
        "preflight_unit_sha256": digest(candidate.unit_new["hermes-commander-native-preflight.service"]),
        "active_unit_sha256": digest(candidate.unit_new["hermes-commander-native.service"]),
        "trust_config_sha256": digest(candidate.trust),
        "trust_ca_sha256": digest(candidate.ca),
        "private_egress_singleton": True,
        "original_roots_preserved": True,
        "native_paired": False, "services_started": False,
        "brc_wss_changed": False,
    }


def backup_copy(paths: Paths, c: Preview) -> None:
    guard(not paths.backup.exists() and not paths.backup.is_symlink(),
          "BACKUP_EXISTS")
    paths.backup.mkdir(mode=0o700)
    copies = {
        "old-manifest.json": c.manifest_old,
        "old-preflight.service": c.unit_old["hermes-commander-native-preflight.service"],
        "old-active.service": c.unit_old["hermes-commander-native.service"],
        "new-manifest.json": c.manifest_new,
        "new-preflight.service": c.unit_new["hermes-commander-native-preflight.service"],
        "new-active.service": c.unit_new["hermes-commander-native.service"],
        "old-first-backup-success": c.old_backup["old-first-backup-success"],
        "old-first-backup-candidate.json": c.old_backup["old-first-backup-candidate.json"],
        "ca.crt": c.ca,
        "private-relay.json": c.trust,
        "plan.json": canonical(plan_result(c)),
    }
    for name, data in copies.items():
        create_file(paths.backup / name, data, 0o600)
    for name, data in copies.items():
        guard(checked_file(paths.backup / name, 16384,
                           private=True, modes={0o600}) == data,
              "BACKUP_READBACK_FAILED")


def stage_new(paths: Paths, c: Preview) -> None:
    paths.source.mkdir(mode=0o755)
    paths.source.chmod(0o755)
    for name, data in c.source.items():
        path = paths.source.joinpath(*name.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        for parent in (path.parent, *path.parents):
            if parent == paths.source:
                break
            if paths.source in parent.parents:
                guard(parent.lstat().st_uid == 0 and not parent.is_symlink(),
                      "SOURCE_DIRECTORY_CHANGED")
                parent.chmod(0o755)
        create_file(path, data, 0o444)
    guard(len([p for p in paths.source.rglob("*") if p.is_file()]) == 14,
          "SOURCE_COUNT_WRONG")
    for name, data in c.source.items():
        guard(checked_file(paths.source / name, 262144, modes={0o444}) == data,
              "SOURCE_CONTENT_CHANGED")
    stage_wheel(c.wheel, target=TARGET, release_sha=CURRENT,
                root=paths.base / "deps", owner_uid=0, check_ancestors=True)
    for directory in (paths.deps, *(p for p in paths.deps.rglob("*") if p.is_dir())):
        guard(directory.lstat().st_uid == 0 and not directory.is_symlink(),
              "DEPS_DIRECTORY_CHANGED")
        directory.chmod(0o755)
    guard((paths.deps / "websockets/sync/client.py").is_file(), "DEPENDENCIES_MISSING")
    paths.trust.mkdir(mode=0o755)
    paths.trust.chmod(0o755)
    create_file(paths.trust / "ca.crt", c.ca, 0o444)
    create_file(paths.trust / "private-relay.json", c.trust, 0o444)
    guard(checked_file(paths.trust / "ca.crt", 8192, modes={0o444}) == c.ca
          and checked_file(paths.trust / "private-relay.json", 2048, modes={0o444}) == c.trust,
          "PRIVATE_TRUST_CHANGED")


def reload_systemd() -> None:
    result = subprocess.run(["/usr/bin/systemctl", "daemon-reload"],
                            capture_output=True, timeout=15, check=False)
    guard(result.returncode == 0, "DAEMON_RELOAD_FAILED")


def verify_after(paths: Paths, c: Preview) -> None:
    for name, data in c.unit_new.items():
        guard(checked_file(paths.units / name, 16384, modes={0o644}) == data,
              "UNIT_READBACK_FAILED")
    guard(checked_file(paths.state / "manifest.json", 8192,
                       owner=c.manifest_uid, private=True, modes={0o600}) == c.manifest_new,
          "MANIFEST_READBACK_FAILED")
    observed = check_units(paths, current=True)
    guard(observed == c.unit_new, "SYSTEMD_UNIT_CONTENT_CHANGED")
    guard(docker_snapshot() == c.origin_docker, "BRC_WSS_CHANGED")
    guard(paths.old_source.is_dir() and paths.old_deps.is_dir()
          and paths.first_backup.is_dir(), "ORIGINAL_ROLLBACK_LOST")


def apply(paths: Paths, c: Preview) -> None:
    backup_copy(paths, c)
    stage_new(paths, c)
    guard(check_units(paths) == c.unit_old, "OLD_UNIT_DRIFT_BEFORE_SWITCH")
    guard(checked_file(paths.state / "manifest.json", 8192,
                       owner=c.manifest_uid, private=True, modes={0o600}) == c.manifest_old,
          "OLD_MANIFEST_DRIFT_BEFORE_SWITCH")
    guard(docker_snapshot() == c.origin_docker, "DOCKER_CHANGED_BEFORE_SWITCH")
    for name, text in c.unit_new.items():
        atomic_replace(paths.units / name, text, mode=0o644, uid=0, gid=0)
    atomic_replace(paths.state / "manifest.json", c.manifest_new,
                   mode=0o600, uid=c.manifest_uid, gid=c.manifest_gid)
    reload_systemd()
    verify_after(paths, c)
    create_file(paths.backup / "success", b"INSTALLED_DISABLED_PRIVATE\n", 0o600)


def saved_backup(paths: Paths) -> dict[str, bytes]:
    owned_directory(paths.backup, mode=0o700)
    raw = {name: checked_file(paths.backup / name, 16384,
                              private=True, modes={0o600}) for name in BACKUP_ITEMS}
    p = json.loads(raw["plan.json"], object_pairs_hook=unique)
    guard(p["status"] == "H454_PRIVATE_UPGRADE_PLAN_PASS"
          and p["old_release"] == PREVIOUS and p["new_release"] == CURRENT
          and p["manifest_sha256"] == digest(raw["new-manifest.json"])
          and p["active_unit_sha256"] == digest(raw["new-active.service"])
          and p["preflight_unit_sha256"] == digest(raw["new-preflight.service"])
          and digest(raw["old-manifest.json"]) == OLD_MANIFEST_SHA
          and digest(raw["old-active.service"]) == OLD_UNITS["hermes-commander-native.service"]
          and digest(raw["old-preflight.service"]) == OLD_UNITS["hermes-commander-native-preflight.service"]
          and digest(raw["private-relay.json"]) == p["trust_config_sha256"]
          and digest(raw["ca.crt"]) == p["trust_ca_sha256"],
          "BACKUP_INVALID")
    return raw


def restore(paths: Paths, saved: dict[str, bytes]) -> None:
    for unit in OLD_UNITS:
        data = raw_show(unit)
        guard(data.get("LoadState") == "loaded" and data.get("ActiveState") == "inactive"
              and data.get("UnitFileState") == ("static" if "preflight" in unit else "disabled")
              and data.get("DropInPaths") == "" and data.get("User") == SERVICE_USER
              and data.get("Group") == SERVICE_USER,
              "ROLLBACK_UNSAFE_UNIT")
    manifest = paths.state / "manifest.json"
    uid = manifest.lstat().st_uid
    guard(uid in (0, pwd.getpwnam(SERVICE_USER).pw_uid), "ROLLBACK_MANIFEST_OWNER")
    current = checked_file(manifest, 8192, owner=uid,
                           private=True, modes={0o600})
    guard(digest(current) in (digest(saved["old-manifest.json"]),
                              digest(saved["new-manifest.json"])),
          "ROLLBACK_FOREIGN_MANIFEST")
    map_units = {
        "hermes-commander-native-preflight.service": ("old-preflight.service", "new-preflight.service"),
        "hermes-commander-native.service": ("old-active.service", "new-active.service"),
    }
    for unit, (old, new) in map_units.items():
        raw = checked_file(paths.units / unit, 16384, modes={0o644})
        guard(digest(raw) in (digest(saved[old]), digest(saved[new])),
              "ROLLBACK_FOREIGN_UNIT")
    for unit, (old, _new) in map_units.items():
        atomic_replace(paths.units / unit, saved[old], mode=0o644, uid=0, gid=0)
    metadata = (paths.state / "manifest.json").lstat()
    atomic_replace(paths.state / "manifest.json", saved["old-manifest.json"],
                   mode=0o600, uid=metadata.st_uid, gid=metadata.st_gid)
    reload_systemd()
    check_units(paths)
    guard(checked_file(paths.state / "manifest.json", 8192,
                       owner=metadata.st_uid, private=True, modes={0o600}) == saved["old-manifest.json"],
          "RESTORE_MANIFEST_MISMATCH")


def typed_approval(mode: str, plan: dict) -> None:
    guard(os.geteuid() == 0 and sys.stdin.isatty() and sys.stdout.isatty(),
          "OWNER_TTY_REQUIRED")
    phrase = ("H454 " + mode + " PRIVATE DISABLED " + TARGET + " " + CURRENT
              + " " + plan["manifest_sha256"] + " " + plan["active_unit_sha256"])
    with open("/dev/tty", "r", encoding="ascii") as inp, \
         open("/dev/tty", "w", encoding="ascii") as out:
        out.write("Confirm exact private disabled native migration (no service start):\n" + phrase + "\n> ")
        out.flush()
        guard(inp.readline(350).strip() == phrase, "OWNER_REFUSED")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "install-off", "rollback-off"))
    parsed = parser.parse_args(argv)
    paths = Paths()
    try:
        guard(os.geteuid() == 0, "ROOT_REQUIRED")
        if parsed.mode == "plan":
            print(json.dumps(plan_result(inspect(paths)), sort_keys=True))
            return 0
        with open("/run/lock/h454-native-private-version-upgrade.lock", "a+b", buffering=0) as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            if parsed.mode == "install-off":
                first = inspect(paths)
                typed_approval("INSTALL", plan_result(first))
                ready = inspect(paths)
                guard(plan_result(first) == plan_result(ready)
                      and first.origin_docker == ready.origin_docker, "PLAN_DRIFT")
                try:
                    apply(paths, ready)
                except Exception:
                    if paths.backup.is_dir():
                        restore(paths, saved_backup(paths))
                    raise
                print("H454_NATIVE_PRIVATE_MIGRATION=INSTALLED_DISABLED")
                print("H454_NATIVE_OLD_VERSIONS_AND_BACKUPS=PRESERVED")
                print("H454_NATIVE_PAIRED=NO")
                print("H454_BRC_WSS_CHANGED=NO")
                return 0
            saved = saved_backup(paths)
            plan = json.loads(saved["plan.json"])
            typed_approval("ROLLBACK", plan)
            guard(docker_snapshot(), "DOCKER_UNAVAILABLE")
            restore(paths, saved)
            if not (paths.backup / "rollback-success").exists():
                create_file(paths.backup / "rollback-success", b"OLD_DISABLED_RESTORED\n")
            print("H454_NATIVE_PRIVATE_MIGRATION=ROLLED_BACK_DISABLED")
            print("H454_NEW_VERSION_RETAINED=YES")
            return 0
    except (UpgradeHold, OSError, ValueError, KeyError, IndexError,
            json.JSONDecodeError, subprocess.TimeoutExpired, tarfile.TarError):
        print("H454_NATIVE_PRIVATE_MIGRATION=HOLD")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())