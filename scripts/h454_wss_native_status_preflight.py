#!/usr/bin/env python3
"""H454: original Hermes VPS read-only gate before a private native-status WSS rollout.

This is NOT a sidecar cutover, file-staging utility, or an approval issuer.
It verifies the installed dormant native release, existing live Docker pair,
immutable old/new proxy source, and absence of a conflicting rollback slot.
No Docker/systemd modifications, secret output, or owner device registration.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys

from scripts import h454_stage1_pair_cutover as stage1

OWNER_SOURCE = "82a51cc0d718e16e6d0be8869436359a06fc94b7"
NATIVE_RELEASE = "30db4fbab46626985b078d574dbe0b839872840e"
OLD_PROXY_BLOB = "7a0f4c20095ba2d98850c4e8e16d1823c60a1f06"
NEW_PROXY_BLOB = "014c3ec08d2b532f710b52601efcb2a3dae4c633"
# Original owner-VPS pair attested after the approved H454 native3 joint switch
# (Nov 13, 2026) and source-only release; do NOT use the previous fork
# rollback image stage1.FORK_IMAGE as the current running relay.
LIVE_RELAY_IMAGE = "sha256:3488e1ff44bb0843ecbc62a1951277ccbf118d1f3ba899b7636a66aa84d55e06"
LIVE_RELAY_ID = "c10587c6bdb51bcbdd4ccea65d5020a6a18deefaa13fb9f9d04eca4661b848d0"
LIVE_SIDECAR_ID = "ad1977a65f10051a15eb69343f5925f9c47188bd4686bfefea8834c6667fd653"
NATIVE_MANIFEST_SHA256 = "8af5e283ae473a3ef94a83908253a5bc47e64ef82a95be6cb38bf834cb0b9747"
PREFLIGHT_UNIT_SHA256 = "2478a19c69e807bb93c5f99e4958862403a920bf98dec04c558add390972ce68"
ACTIVE_UNIT_SHA256 = "75a681a6c6157acc3356513483b886f81097f958ef94d5d816a6eaf9c7ac4390"
TRUST_CA_SHA256 = "014868af3edc97e04c58099746964bde1d65d2f38c931360e27a8f309b8c0f7c"
TRUST_CONFIG_SHA256 = "7ed257d75ca61649fd139657466d95d8358eb5c295eeacd14ae991188ff2f595"
SIDECAR_CHECKPOINT = "hermes-h454-wss-proxy-native-status-rollback"
SIDECAR_CHECKPOINT_NEW = SIDECAR_CHECKPOINT + "-new"
HISTORICAL_NATIVE3_FILE = "native3-original-pins.json"
HISTORICAL_NATIVE3_SHA256 = "a7efdbb4d0d5eec05890929b27e4e76ee6c38ee20bb13d18e99cc5a2a67ee0cb"
HISTORICAL_RELAY_ID = "ec5e42db0d6ba1b65f1343fc4e6b6ac956a4715b35e654b663ed6d469818f57b"
HISTORICAL_PROXY_ID = "714eb4224c99fdd33a4b723ef782a72bc9674c52b91ada8c32e2f11fd706cab6"
HISTORICAL_RELAY_CHECKPOINT = "hermes-brc-relay-h454-native3-v2-rollback"
HISTORICAL_PROXY_CHECKPOINT = "hermes-h454-wss-proxy-h454-native3-v2-rollback"
ROOT = Path("/var/lib/hermes-h454-wss-sidecar")
STATE = Path("/var/lib/hermes-commander-native")
BASE = Path("/opt/hermes-commander-native")
UNIT_DIR = Path("/etc/systemd/system")
NATIVE_USER = "hermes-commander-native"


class Hold(ValueError):
    """Only constant, non-sensitive reason codes cross the CLI boundary."""


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise Hold(reason)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob(raw: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


def check_proxy_source(old: bytes, candidate: bytes, pinned_sha256: str) -> None:
    """Neither a self-asserted manifest nor a new branch can change source pins."""
    require(type(old) is bytes and 0 < len(old) <= 100000,
            "OLD_PROXY_SIZE_CHANGED")
    require(type(candidate) is bytes and 0 < len(candidate) <= 100000,
            "CANDIDATE_PROXY_SIZE_CHANGED")
    require(sha256(old) == pinned_sha256 and git_blob(old) == OLD_PROXY_BLOB,
            "ACTIVE_PROXY_SOURCE_CHANGED")
    require(git_blob(candidate) == NEW_PROXY_BLOB and candidate != old,
            "CANDIDATE_PROXY_SOURCE_CHANGED")


def read_fixed(path: Path, *, uid: set[int], modes: set[int],
               limit: int = 100000) -> bytes:
    """Reject symlinks, writable ancestors, size/owner drift and partial reads."""
    require(path.is_absolute(), "SOURCE_PATH_INVALID")
    for parent in path.parents:
        metadata = parent.lstat()
        require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid in uid
                and not metadata.st_mode & 0o022, "SOURCE_PARENT_CHANGED")
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and before.st_uid in uid and stat.S_IMODE(before.st_mode) in modes
            and 0 < before.st_size <= limit, "SOURCE_FILE_CHANGED")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC), "rb") as stream:
        inside = os.fstat(stream.fileno())
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    keys = ("st_dev", "st_ino", "st_size", "st_mode", "st_mtime_ns", "st_ctime_ns")
    require(len(raw) == before.st_size and all(
        getattr(before, key) == getattr(inside, key) == getattr(after, key)
        for key in keys), "SOURCE_READ_DRIFT")
    return raw


def unit_state(raw: str, expected: str) -> None:
    items = raw.strip().splitlines()
    require(len(items) == 3 and len(set(items)) == 3 and all("=" in item for item in items),
            "NATIVE_UNIT_STATE_INVALID")
    found = dict(item.split("=", 1) for item in items)
    require(found == {"ActiveState": "inactive", "UnitFileState": expected,
                      "NeedDaemonReload": "no"}, "NATIVE_UNIT_NOT_DISABLED")


def native_release() -> None:
    service_uid = pwd.getpwnam(NATIVE_USER).pw_uid
    require(service_uid > 0, "NATIVE_IDENTITY_CHANGED")
    checks = (
        (STATE / "manifest.json", NATIVE_MANIFEST_SHA256, {0, service_uid}, {0o600}),
        (UNIT_DIR / "hermes-commander-native-preflight.service",
         PREFLIGHT_UNIT_SHA256, {0}, {0o644}),
        (UNIT_DIR / "hermes-commander-native.service",
         ACTIVE_UNIT_SHA256, {0}, {0o644}),
        (BASE / "trust" / "ca.crt", TRUST_CA_SHA256, {0}, {0o444}),
        (BASE / "trust" / "private-relay.json", TRUST_CONFIG_SHA256, {0}, {0o444}),
    )
    for path, pinned, owners, modes in checks:
        require(sha256(read_fixed(path, uid=owners | {0}, modes=modes)) == pinned,
                "NATIVE_INSTALL_PIN_CHANGED")
    require(not (STATE / "device.json").exists()
            and not (STATE / "device.json").is_symlink(), "NATIVE_ALREADY_PAIRED")
    require((BASE / "releases" / ("main-" + NATIVE_RELEASE)).is_dir()
            and (BASE / "deps" / ("main-" + NATIVE_RELEASE)).is_dir(),
            "NATIVE_RELEASE_NOT_INSTALLED")
    for name, state in (
        ("hermes-commander-native.service", "disabled"),
        ("hermes-commander-native-preflight.service", "static"),
    ):
        outcome = subprocess.run(
            ["/usr/bin/systemctl", "show", name, "--no-pager",
             "--property=ActiveState,UnitFileState,NeedDaemonReload"],
            check=False, capture_output=True, text=True, timeout=10,
        )
        require(outcome.returncode == 0 and len(outcome.stdout) < 512,
                "NATIVE_SYSTEMD_UNAVAILABLE")
        unit_state(outcome.stdout, state)


def verify_completed_native3_history(wss, live: dict) -> bool:
    """Admit only the exact, retained *completed* Nov-13 native3 backup.

    History is NOT a pending operation and must never be deleted for a new
    sidecar-only upgrade. A foreign marker, changed digest, or missing/active
    original rollback container is still a hard refusal.
    """
    historical = ROOT / HISTORICAL_NATIVE3_FILE
    if not historical.exists() and not historical.is_symlink():
        return False
    raw = read_fixed(historical, uid={0}, modes={0o600}, limit=16384)
    require(sha256(raw) == HISTORICAL_NATIVE3_SHA256,
            "HISTORICAL_NATIVE3_PINS_DRIFT")
    saved = wss._pins(raw)
    require(saved["relay_name"] == stage1.legacy.NAME
            and saved["sidecar_name"] == stage1.PROXY
            and saved["relay_id"] == HISTORICAL_RELAY_ID
            and saved["sidecar_id"] == HISTORICAL_PROXY_ID
            and saved["relay_image"] == stage1.FORK_IMAGE
            and saved["sidecar_image"] == stage1.LEGACY_IMAGE,
            "HISTORICAL_NATIVE3_IDENTITY_DRIFT")
    # Only the relay image/CIDs/IP and rebuilt sidecar profile may change.
    # Certificates, key identity and network provenance remain pinned.
    immutable = (
        "version", "relay_name", "sidecar_name", "sidecar_image",
        "network_id", "network_name", "gateway_ipv4", "proxy_sha256",
        "ca_sha256", "certificate_sha256", "key_sha256", "tls_directory",
    )
    require(all(saved[k] == live[k] for k in immutable),
            "HISTORICAL_NATIVE3_TRUST_DRIFT")
    for name, identity, image in (
        (HISTORICAL_RELAY_CHECKPOINT, HISTORICAL_RELAY_ID, stage1.FORK_IMAGE),
        (HISTORICAL_PROXY_CHECKPOINT, HISTORICAL_PROXY_ID, stage1.LEGACY_IMAGE),
    ):
        # A successful, exact Docker listing is essential. Do not use optional
        # inspect as "absent" proof when the Docker daemon is unavailable.
        listing = stage1.docker(
            "container", "ls", "--all", "--no-trunc",
            "--filter", "name=^/" + name + "$", "--format", "{{.Names}}",
        )
        require(listing == name, "HISTORICAL_NATIVE3_CHECKPOINT_MISSING")
        item = stage1.inspect("container", name)
        require(item["Name"] == "/" + name
                and item["Id"] == identity
                and item["Image"] == image
                and item["State"]["Running"] is False,
                "HISTORICAL_NATIVE3_CHECKPOINT_DRIFT")
        if name == HISTORICAL_PROXY_CHECKPOINT:
            require(item["HostConfig"]["NetworkMode"] ==
                    "container:" + HISTORICAL_RELAY_ID,
                    "HISTORICAL_NATIVE3_NAMESPACE_DRIFT")
    return True


def no_conflicting_transaction(wss, live: dict) -> bool:
    # A historical native3-original-pins.json is intentionally NOT in this
    # list: it is admissible only through verify_completed_native3_history.
    for name in (
        "prepare.pending", "reconcile.pending", "native3-pair.pending",
        "native-status-upgrade.pending", "native-status-original-pins.json",
        "native-status-upgrade-evidence",
    ):
        path = ROOT / name
        require(not path.exists() and not path.is_symlink(),
                "EXISTING_WSS_TRANSACTION")
    completed_history = verify_completed_native3_history(wss, live)
    for checkpoint in (SIDECAR_CHECKPOINT, SIDECAR_CHECKPOINT_NEW):
        result = stage1.docker(
            "container", "ls", "--all", "--no-trunc",
            "--filter", "name=^/" + checkpoint + "$",
            "--format", "{{.Names}}",
        )
        require(result == "", "SIDECAR_CHECKPOINT_OCCUPIED")
    return completed_history



def check_pinned_live_pair(pins: dict) -> None:
    """Match the specific, accepted original-VPS pair, not merely self-signed pins.

    The prior stage1.FORK_IMAGE is a retained rollback checkpoint, not the
    currently running owner-authorized relay. Any later pair replacement needs
    its own verified release, updated exact pins, and explicit approval.
    """
    require(pins["relay_name"] == stage1.legacy.NAME
            and pins["sidecar_name"] == stage1.PROXY
            and pins["relay_image"] == LIVE_RELAY_IMAGE
            and pins["sidecar_image"] == stage1.LEGACY_IMAGE
            and pins["relay_id"] == LIVE_RELAY_ID
            and pins["sidecar_id"] == LIVE_SIDECAR_ID,
            "EXISTING_BRC_WSS_PAIR_CHANGED")


def plan(candidate: Path) -> dict:
    require(sys.platform == "linux" and os.geteuid() == 0,
            "ORIGINAL_LINUX_ROOT_REQUIRED")
    original_root = Path("/opt/hermes-agent-owner/releases/main-" + OWNER_SOURCE)
    require(Path(stage1.__file__).resolve()
            == original_root / "scripts/h454_stage1_pair_cutover.py",
            "OWNER_SOURCE_IMPORT_CHANGED")
    require(candidate.parent == Path("/root") and candidate.name.startswith(
        "h454-wss-native-status-"), "CANDIDATE_NOT_ROOT_STAGED")
    new_source = read_fixed(candidate, uid={0}, modes={0o600}, limit=100000)
    native_release()
    with stage1.locked_pins() as raw:
        wss = stage1.load_existing_wss()
        pins = wss._pins(raw)
        check_pinned_live_pair(pins)
        directory = wss._directory(ROOT)
        try:
            old_source = wss._read_file(directory, "proxy.mjs", 0o444)
        finally:
            os.close(directory)
        check_proxy_source(old_source, new_source, pins["proxy_sha256"])
        relay, sidecar = wss._snapshot(pins, ROOT, Path(pins["tls_directory"]))
        wss._namespace(relay, sidecar)
        tls_dir = wss._directory(Path(pins["tls_directory"]))
        try:
            ca = wss._read_file(tls_dir, "ca.crt", 0o444)
        finally:
            os.close(tls_dir)
        wss._tls(pins, ca)
        require(sha256(ca) == TRUST_CA_SHA256, "TLS_TRUST_PIN_CHANGED")
        historical_native3_verified = no_conflicting_transaction(wss, pins)
        return {
            "status": "H454_WSS_NATIVE_STATUS_PREPARE_PLAN_PASS",
            "owner_source": OWNER_SOURCE,
            "native_release": NATIVE_RELEASE,
            "old_proxy_git_blob": OLD_PROXY_BLOB,
            "new_proxy_git_blob": NEW_PROXY_BLOB,
            "current_proxy_sha256": sha256(old_source),
            "candidate_proxy_sha256": sha256(new_source),
            "relay_container_id": relay["Id"],
            "sidecar_container_id": sidecar["Id"],
            "relay_image": LIVE_RELAY_IMAGE,
            "native_services_inactive": True,
            "native_paired": False,
            "brc_wss_mutation": False,
            "sidecar_native_status_deployed": False,
            "cutover_approval": "NOT_GRANTED",
            "completed_native3_history_verified": historical_native3_verified,
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan",))
    parser.add_argument("--candidate-source", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(plan(args.candidate_source), sort_keys=True))
        return 0
    except Exception as exc:
        reason = str(exc) if isinstance(exc, Hold) else "ORIGINAL_HOST_EVIDENCE_UNAVAILABLE"
        if not re.fullmatch("[A-Z_]{1,64}", reason):
            reason = "ORIGINAL_HOST_EVIDENCE_UNAVAILABLE"
        print(json.dumps({"status": "H454_WSS_NATIVE_STATUS_PREPARE_PLAN_HOLD",
                          "reason": reason}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
