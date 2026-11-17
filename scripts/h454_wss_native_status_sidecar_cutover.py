#!/usr/bin/env python3
"""H454: source-only, owner-gated WSS native-status sidecar-only transaction.

The original relay container/image, SQLite, OAuth, WSS CA/key and all native
services remain unchanged. This file is NOT installed or activated by a merge.
Cutover/rollback require separate owner approval and an original root TTY.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import sys

from scripts import h454_stage1_pair_cutover as stage1

ROOT = stage1.PIN_ROOT
BACKUP = ROOT / "native-status-upgrade-evidence"
ORIGINAL = ROOT / "native-status-original-pins.json"
PENDING = ROOT / "native-status-upgrade.pending"
CHECKPOINT = "hermes-h454-wss-proxy-native-status-rollback"
CHECKPOINT_NEW = CHECKPOINT + "-new"
PREFLIGHT = Path("/root/h454_wss_native_status_preflight.py")
PREFLIGHT_BLOB = "6caf8ffc488dd5dc399fef40f02db8109f6facf5"
SOURCE_BLOB = "014c3ec08d2b532f710b52601efcb2a3dae4c633"
OLD_BLOB = "7a0f4c20095ba2d98850c4e8e16d1823c60a1f06"
ARTIFACTS = ("old-pins.json", "old-proxy.mjs", "candidate-proxy.mjs",
             "relay-id.txt", "sidecar-id.txt", "preflight-blob.txt")


class Refused(ValueError):
    """The CLI may print only constant status strings, never host secrets."""


def gate(ok, code):
    if not ok:
        raise Refused(code)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob(data: bytes) -> str:
    return hashlib.sha1(
        b"blob " + str(len(data)).encode("ascii") + b"\0" + data
    ).hexdigest()


def verified_preflight():
    gate(PREFLIGHT.parent == Path("/root") and not PREFLIGHT.is_symlink(),
         "PREFLIGHT_SOURCE_PATH")
    info = PREFLIGHT.lstat()
    gate(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
         info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600 and
         0 < info.st_size <= 20000, "PREFLIGHT_SOURCE_METADATA")
    with os.fdopen(os.open(PREFLIGHT, os.O_RDONLY | os.O_NOFOLLOW), "rb") as src:
        data = src.read(20001)
    gate(len(data) == info.st_size and git_blob(data) == PREFLIGHT_BLOB,
         "PREFLIGHT_SOURCE_CHANGED")
    spec = importlib.util.spec_from_file_location("h454_pinned_wss_preflight", PREFLIGHT)
    gate(spec is not None and spec.loader is not None, "PREFLIGHT_LOAD_REFUSED")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    gate(module.NEW_PROXY_BLOB == SOURCE_BLOB and
         module.OLD_PROXY_BLOB == OLD_BLOB, "PREFLIGHT_PINS_CHANGED")
    return module


def canonical(document: dict) -> bytes:
    return (json.dumps(document, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True) + "\n").encode("ascii")


def checked_file(path: Path, *, mode: int, limit=100000) -> bytes:
    gate(path.is_absolute() and not path.is_symlink(), "BACKUP_PATH_CHANGED")
    info = path.lstat()
    gate(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
         info.st_gid == 0 and info.st_nlink == 1 and
         stat.S_IMODE(info.st_mode) == mode and 0 < info.st_size <= limit,
         "BACKUP_METADATA_CHANGED")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as src:
        data = src.read(limit + 1)
    gate(len(data) == info.st_size, "BACKUP_READ_CHANGED")
    return data


def persist(name: str, value: bytes) -> None:
    gate(name in ARTIFACTS, "BACKUP_ITEM_UNKNOWN")
    path = BACKUP / name
    stage1.write_once(path, value)
    gate(checked_file(path, mode=0o600) == value, "BACKUP_READBACK_FAILED")


def backup(original_pins: bytes, old_source: bytes, candidate: bytes,
           relay_id: str, sidecar_id: str) -> None:
    gate(not BACKUP.exists() and not BACKUP.is_symlink(), "OLD_UPGRADE_EVIDENCE_PRESENT")
    gate(not ORIGINAL.exists() and not ORIGINAL.is_symlink(), "ORIGINAL_PIN_EVIDENCE_PRESENT")
    BACKUP.mkdir(mode=0o700)
    stage1.protected(BACKUP, 0o700, directory=True)
    for name, content in (
        ("old-pins.json", original_pins),
        ("old-proxy.mjs", old_source),
        ("candidate-proxy.mjs", candidate),
        ("relay-id.txt", (relay_id + "\n").encode("ascii")),
        ("sidecar-id.txt", (sidecar_id + "\n").encode("ascii")),
        ("preflight-blob.txt", (PREFLIGHT_BLOB + "\n").encode("ascii")),
    ):
        persist(name, content)
    stage1.write_once(ORIGINAL, original_pins)
    gate(checked_file(ORIGINAL, mode=0o600) == original_pins,
         "ORIGINAL_PIN_READBACK_FAILED")
    stage1.sync_pin_directory()


def read_backup() -> dict[str, bytes]:
    stage1.protected(BACKUP, 0o700, directory=True)
    saved = {name: checked_file(BACKUP / name, mode=0o600)
             for name in ARTIFACTS}
    gate(checked_file(ORIGINAL, mode=0o600) == saved["old-pins.json"],
         "ORIGINAL_PIN_BACKUP_DRIFT")
    gate(saved["preflight-blob.txt"] == (PREFLIGHT_BLOB + "\n").encode("ascii") and
         git_blob(saved["old-proxy.mjs"]) == OLD_BLOB and
         git_blob(saved["candidate-proxy.mjs"]) == SOURCE_BLOB and
         stage1.HEX.fullmatch(saved["relay-id.txt"].decode().strip()) and
         stage1.HEX.fullmatch(saved["sidecar-id.txt"].decode().strip()),
         "BACKUP_SOURCE_OR_IDENTITY_DRIFT")
    return saved


def replace_proxy(data: bytes) -> None:
    gate(git_blob(data) in {OLD_BLOB, SOURCE_BLOB}, "PROXY_REPLACE_FOREIGN_SOURCE")
    tmp = ROOT / ".h454-native-status-proxy.tmp"
    gate(not tmp.exists() and not tmp.is_symlink(), "PROXY_TEMP_COLLISION")
    stage1.write_once(tmp, data)
    os.chmod(tmp, 0o444)
    gate(checked_file(tmp, mode=0o444) == data, "PROXY_TEMP_DRIFT")
    os.replace(tmp, ROOT / "proxy.mjs")
    stage1.sync_pin_directory()


def fresh_pins(wss, old: dict, new_id: str, candidate: bytes, relay_id: str) -> bytes:
    gate(stage1.HEX.fullmatch(new_id) is not None and
         stage1.HEX.fullmatch(relay_id) is not None and
         old["relay_id"] == relay_id, "NEW_PROXY_IDENTITY_INVALID")
    observed = stage1.inspect("container", new_id)
    gate(observed["Id"] == new_id and observed["Image"] == stage1.LEGACY_IMAGE and
         observed["Name"] == "/" + stage1.PROXY,
         "NEW_PROXY_CONTAINER_UNTRUSTED")
    updated = dict(old, sidecar_id=new_id, proxy_sha256=digest(candidate),
                   profile_sha256=wss.profile_sha256(observed))
    raw = canonical(updated)
    wss._pins(raw)
    wss._snapshot(updated, ROOT, Path(updated["tls_directory"]))
    return raw


def private_status_denied(pins: dict, ca: bytes) -> None:
    """Prove the deployed new route exists but denies anonymous requests."""
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_verify_locations(cadata=ca.decode("ascii"))
    with socket.create_connection((pins["relay_ipv4"], 3001), timeout=3) as raw:
        with tls.wrap_socket(raw, server_hostname="brc-agent.internal") as peer:
            peer.settimeout(3)
            peer.sendall(b"GET /device/native-status HTTP/1.1\r\n"
                         b"Host: brc-agent.internal\r\nConnection: close\r\n\r\n")
            response = b""
            while b"\r\n" not in response and len(response) < 4096:
                piece = peer.recv(512)
                if not piece:
                    break
                response += piece
    gate(response.split(b"\r\n", 1)[0] == b"HTTP/1.1 403 Forbidden",
         "PRIVATE_STATUS_NOT_DENIED")


def verify_live(wss, pins: dict, original_relay_id: str, *, status=False) -> None:
    gate(pins["relay_id"] == original_relay_id and
         pins["relay_image"] == stage1.FORK_IMAGE and
         pins["sidecar_image"] == stage1.LEGACY_IMAGE, "BRC_IDENTITY_CHANGED")
    relay, proxy = wss._snapshot(pins, ROOT, Path(pins["tls_directory"]))
    gate(relay["Id"] == original_relay_id and
         relay["State"]["Running"] is True, "BRC_CONTAINER_CHANGED")
    wss._namespace(relay, proxy)
    directory = wss._directory(Path(pins["tls_directory"]))
    try:
        ca = wss._read_file(directory, "ca.crt", 0o444)
    finally:
        os.close(directory)
    wss._tls(pins, ca)
    if status:
        private_status_denied(pins, ca)


def current_name(name: str) -> dict | None:
    gate(name in (stage1.PROXY, CHECKPOINT, CHECKPOINT_NEW), "UNKNOWN_PROXY_NAME")
    found = stage1.docker(
        "container", "ls", "--all", "--no-trunc",
        "--filter", "name=^/" + name + "$", "--format", "{{.Names}}")
    gate(found in ("", name), "PROXY_DISCOVERY_AMBIGUOUS")
    if not found:
        return None
    observed = stage1.inspect("container", name)
    gate(observed["Name"] == "/" + name and
         stage1.HEX.fullmatch(observed["Id"]) is not None,
         "PROXY_DISCOVERY_DRIFT")
    return observed


def owner_tty(mode: str, pins_sha: str, old_id: str, candidate_sha: str) -> None:
    gate(os.geteuid() == 0 and sys.stdin.isatty() and sys.stdout.isatty(),
         "ORIGINAL_OWNER_TTY_REQUIRED")
    phrase = "H454 WSS " + mode + " SIDECAR ONLY " + pins_sha + " " + old_id + " " + candidate_sha
    with open("/dev/tty", encoding="ascii") as terminal, open("/dev/tty", "w", encoding="ascii") as screen:
        screen.write("Confirm an independently approved original-Hermes-VPS sidecar-only transaction:\n"
                     + phrase + "\n> ")
        screen.flush()
        gate(terminal.readline(400).strip() == phrase, "OWNER_DECLINED")


def normal_plan(module, candidate: Path) -> dict:
    result = module.plan(candidate)
    gate(result.get("status") == "H454_WSS_NATIVE_STATUS_PREPARE_PLAN_PASS"
         and result.get("sidecar_native_status_deployed") is False
         and result.get("brc_wss_mutation") is False,
         "PREFLIGHT_REPORT_UNEXPECTED")
    return result


def update_pending_new(new_id: str) -> None:
    """Durably retain a new container ID before touching protected live pins."""
    gate(stage1.HEX.fullmatch(new_id) is not None, "PENDING_NEW_ID_INVALID")
    current = json.loads(checked_file(PENDING, mode=0o600))
    gate(current.get("schema") == 1 and
         current.get("action") == "cutover" and
         current.get("new_sidecar_id") == "",
         "PENDING_SOURCE_CHANGED")
    current["new_sidecar_id"] = new_id
    tmp = ROOT / ".h454-native-status-pending.tmp"
    gate(not tmp.exists() and not tmp.is_symlink(), "PENDING_TEMP_COLLISION")
    stage1.write_once(tmp, canonical(current))
    os.replace(tmp, PENDING)
    stage1.sync_pin_directory()
    gate(json.loads(checked_file(PENDING, mode=0o600)) == current,
         "PENDING_READBACK_FAILED")


def pending_record(saved: dict[str, bytes]) -> dict:
    """Only exact retained backup identity can authorize recovery."""
    doc = json.loads(checked_file(PENDING, mode=0o600))
    gate(type(doc) is dict and set(doc) == {
        "schema", "action", "relay_id", "old_sidecar_id",
        "new_sidecar_id", "old_proxy_sha256", "candidate_proxy_sha256",
    } and type(doc["schema"]) is int and doc["schema"] == 1 and
         doc["action"] in ("cutover", "rollback") and
         doc["relay_id"] == saved["relay-id.txt"].decode("ascii").strip() and
         doc["old_sidecar_id"] == saved["sidecar-id.txt"].decode("ascii").strip() and
         doc["old_proxy_sha256"] == digest(saved["old-proxy.mjs"]) and
         doc["candidate_proxy_sha256"] == digest(saved["candidate-proxy.mjs"]) and
         (doc["new_sidecar_id"] == "" or
          stage1.HEX.fullmatch(doc["new_sidecar_id"]) is not None),
         "PENDING_IDENTITY_DRIFT")
    return doc


def valid_new_proxy(proxy: dict, known_id: str, relay_id: str) -> None:
    """Never stop/remove a container based on name or image alone."""
    host = proxy.get("HostConfig") or {}
    config = proxy.get("Config") or {}
    mounts = proxy.get("Mounts") or []
    expected = {
        "/run/h454-wss/proxy.mjs": str(ROOT / "proxy.mjs"),
    }
    gate(known_id != "" and proxy.get("Id") == known_id and
         proxy.get("Image") == stage1.LEGACY_IMAGE and
         config.get("User") == "65534:65534" and
         (config.get("Labels") or {}).get("com.hermes.h454.role") == "wss-proxy" and
         host.get("NetworkMode") == "container:" + relay_id and
         host.get("ReadonlyRootfs") is True and host.get("Privileged") is False and
         host.get("CapDrop") == ["ALL"] and host.get("PidsLimit") == 32 and
         host.get("Memory") == 128 * 1024 * 1024 and
         host.get("PortBindings") in ({}, None) and
         host.get("CapAdd") in ([], None) and
         isinstance(mounts, list) and len(mounts) == 3 and
         sum(m.get("Destination") == "/run/h454-wss/proxy.mjs" and
             m.get("Source") == expected["/run/h454-wss/proxy.mjs"] and
             m.get("Type") == "bind" and m.get("RW") is False for m in mounts) == 1,
         "FOREIGN_NEW_PROXY_REFUSED")


def restore_known(wss, saved: dict[str, bytes],
                  known_new_id: str, preflight) -> None:
    """Restore only a demonstrably owned partial candidate; never guess Docker state.

    Caller must hold the existing relay lock AND the existing WSS pin lock.
    The legacy BRC relay is never stopped, renamed, removed or restarted.
    """
    old_id = saved["sidecar-id.txt"].decode("ascii").strip()
    relay_id = saved["relay-id.txt"].decode("ascii").strip()
    original = wss._pins(saved["old-pins.json"])
    gate(original["sidecar_id"] == old_id and original["relay_id"] == relay_id
         and original["proxy_sha256"] == digest(saved["old-proxy.mjs"]),
         "RESTORE_ORIGINAL_PINS_INVALID")
    relay = stage1.inspect("container", stage1.legacy.NAME)
    gate(relay["Id"] == relay_id and relay["Image"] == stage1.FORK_IMAGE
         and relay["State"]["Running"] is True, "RESTORE_RELAY_CHANGED")
    checkpoint = current_name(CHECKPOINT)
    current = current_name(stage1.PROXY)
    gate(current_name(CHECKPOINT_NEW) is None, "FOREIGN_ROLLBACK_SLOT")
    active_source = checked_file(ROOT / "proxy.mjs", mode=0o444)
    gate(git_blob(active_source) in (OLD_BLOB, SOURCE_BLOB),
         "FOREIGN_PROXY_SOURCE_REFUSED")
    live_pins = wss._pins(checked_file(stage1.PINS, mode=0o600))
    gate(live_pins["relay_id"] == relay_id and
         live_pins["sidecar_id"] in (old_id, known_new_id) and
         live_pins["proxy_sha256"] in (
             digest(saved["old-proxy.mjs"]), digest(saved["candidate-proxy.mjs"])),
         "FOREIGN_PIN_STATE_REFUSED")
    if checkpoint is None:
        # Failure before rename. The only acceptable live proxy is the OLD one.
        gate(current is not None and current["Id"] == old_id and
             current["Image"] == stage1.LEGACY_IMAGE and
             active_source == saved["old-proxy.mjs"] and
             live_pins["sidecar_id"] == old_id,
             "UNRECOGNIZED_PRE_RENAME_PHASE")
        stage1.docker("update", "--restart", "unless-stopped", old_id)
        if current["State"]["Running"] is not True:
            stage1.docker("start", old_id)
    else:
        gate(checkpoint["Id"] == old_id and
             checkpoint["Image"] == stage1.LEGACY_IMAGE and
             checkpoint["State"]["Running"] is False,
             "ORIGINAL_CHECKPOINT_CHANGED")
        if current is not None:
            valid_new_proxy(current, known_new_id, relay_id)
            stage1.docker("stop", "--time", "12", known_new_id)
            stage1.docker("update", "--restart", "no", known_new_id)
            stage1.docker("rm", "--force", known_new_id)
            gate(current_name(stage1.PROXY) is None,
                 "NEW_PROXY_REMOVAL_UNVERIFIED")
        if active_source != saved["old-proxy.mjs"]:
            replace_proxy(saved["old-proxy.mjs"])
        gate(checked_file(ROOT / "proxy.mjs", mode=0o444) == saved["old-proxy.mjs"],
             "RESTORED_PROXY_SOURCE_MISMATCH")
        if checked_file(stage1.PINS, mode=0o600) != saved["old-pins.json"]:
            stage1.replace_pins(saved["old-pins.json"])
        stage1.docker("rename", old_id, stage1.PROXY)
        stage1.docker("update", "--restart", "unless-stopped", old_id)
        stage1.docker("start", old_id)
    gate(current_name(stage1.PROXY)["Id"] == old_id and
         checked_file(stage1.PINS, mode=0o600) == saved["old-pins.json"],
         "RESTORED_PROXY_IDENTITY_MISMATCH")
    verify_live(wss, original, relay_id)
    preflight.native_release()


def cutover(candidate: Path) -> dict:
    preflight = verified_preflight()
    preview = normal_plan(preflight, candidate)
    owner_tty("CUTOVER", preview["current_proxy_sha256"],
              preview["sidecar_container_id"], preview["candidate_proxy_sha256"])
    # Owner confirmation is not a drift bypass.
    gate(normal_plan(preflight, candidate) == preview, "PLAN_CHANGED_AFTER_APPROVAL")
    new_bytes = preflight.read_fixed(candidate, uid={0}, modes={0o600})
    with stage1.legacy.lock():
        with stage1.locked_pins() as raw:
            wss = stage1.load_existing_wss()
            pins = wss._pins(raw)
            gate(pins["relay_id"] == preview["relay_container_id"] and
                 pins["sidecar_id"] == preview["sidecar_container_id"] and
                 digest(raw) == digest((ROOT / "pins.json").read_bytes()),
                 "LIVE_PINS_CHANGED")
            directory = wss._directory(ROOT)
            try:
                old_bytes = wss._read_file(directory, "proxy.mjs", 0o444)
            finally:
                os.close(directory)
            preflight.check_proxy_source(old_bytes, new_bytes, pins["proxy_sha256"])
            verify_live(wss, pins, preview["relay_container_id"])
            gate(current_name(CHECKPOINT) is None and
                 current_name(stage1.PROXY)["Id"] == pins["sidecar_id"],
                 "ROLLBACK_CHECKPOINT_OR_PROXY_CHANGED")
            gate(not BACKUP.exists() and not BACKUP.is_symlink() and
                 not PENDING.exists() and not PENDING.is_symlink() and
                 current_name(CHECKPOINT_NEW) is None,
                 "UPGRADE_ALREADY_PREPARED")
            # Independent retained source/pins before any Docker mutation.
            backup(raw, old_bytes, new_bytes, pins["relay_id"], pins["sidecar_id"])
            stage1.write_once(PENDING, canonical({
                "schema": 1, "relay_id": pins["relay_id"],
                "old_sidecar_id": pins["sidecar_id"],
                "old_proxy_sha256": digest(old_bytes),
                "candidate_proxy_sha256": digest(new_bytes),
            }))
            stage1.sync_pin_directory()
            new_id = ""
            try:
                stage1.docker("stop", "--time", "12", pins["sidecar_id"])
                stage1.docker("update", "--restart", "no", pins["sidecar_id"])
                stage1.docker("rename", pins["sidecar_id"], CHECKPOINT)
                replace_proxy(new_bytes)
                new_id = stage1.create_sidecar(pins, pins["relay_id"],
                                               stage1.inspect("container", CHECKPOINT))
                next_raw = fresh_pins(wss, pins, new_id, new_bytes, pins["relay_id"])
                stage1.replace_pins(next_raw)
                stage1.docker("start", new_id)
                verify_live(wss, wss._pins(next_raw), pins["relay_id"], status=True)
                preflight.native_release()
                gate(current_name(CHECKPOINT)["Id"] == pins["sidecar_id"] and
                     current_name(stage1.PROXY)["Id"] == new_id,
                     "POST_CUTOVER_CONTAINER_CHANGED")
                PENDING.unlink()
                stage1.sync_pin_directory()
            except Exception as exc:
                # Retain the original files/containers and pending marker for
                # an independent owner recovery; never guess/delete a container
                # after an ambiguous Docker operation.
                raise Refused("CUTOVER_INCOMPLETE_OWNER_RECOVERY_REQUIRED") from exc
        # Reconciler acquires pins lock itself. Only call it after release.
        gate(wss.reconcile(str(stage1.PINS)) == "READY",
             "POST_CUTOVER_WSS_RECONCILE_HOLD")
    return {
        "status": "H454_WSS_NATIVE_STATUS_SWITCHED_PENDING_OWNER_ACCEPTANCE",
        "relay_changed": False, "native_service_started": False,
        "device_paired": False, "rollback_checkpoint_retained": True,
    }


def rollback() -> dict:
    preflight = verified_preflight()
    gate(os.geteuid() == 0, "ORIGINAL_ROOT_REQUIRED")
    saved = read_backup()
    relay_id = saved["relay-id.txt"].decode("ascii").strip()
    old_id = saved["sidecar-id.txt"].decode("ascii").strip()
    old_pins = stage1.load_existing_wss()._pins(saved["old-pins.json"])
    gate(old_pins["relay_id"] == relay_id and old_pins["sidecar_id"] == old_id,
         "ROLLBACK_ORIGINAL_IDENTITY_CHANGED")
    active = current_name(stage1.PROXY)
    old = current_name(CHECKPOINT)
    gate(active is not None and old is not None and old["Id"] == old_id,
         "ROLLBACK_CONTAINER_STATE_CHANGED")
    pins_raw = checked_file(stage1.PINS, mode=0o600)
    current = stage1.load_existing_wss()._pins(pins_raw)
    gate(current["relay_id"] == relay_id and
         current["sidecar_id"] == active["Id"] and
         current["proxy_sha256"] == digest(saved["candidate-proxy.mjs"]) and
         git_blob(checked_file(ROOT / "proxy.mjs", mode=0o444)) == SOURCE_BLOB,
         "ROLLBACK_ACTIVE_PIN_CHANGED")
    owner_tty("ROLLBACK", digest(pins_raw), old_id,
              digest(saved["candidate-proxy.mjs"]))
    with stage1.legacy.lock():
        with stage1.locked_pins() as latest:
            gate(latest == pins_raw and current_name(stage1.PROXY)["Id"] == active["Id"]
                 and current_name(CHECKPOINT)["Id"] == old_id, "ROLLBACK_RACE")
            gate(not PENDING.exists() and not PENDING.is_symlink(),
                 "RECOVER_PENDING_FIRST")
            stage1.write_once(PENDING, canonical({
                "schema": 1, "action": "rollback",
                "relay_id": relay_id, "old_sidecar_id": old_id,
                "new_sidecar_id": active["Id"],
            }))
            stage1.docker("stop", "--time", "12", active["Id"])
            stage1.docker("update", "--restart", "no", active["Id"])
            stage1.docker("rename", active["Id"], CHECKPOINT + "-new")
            replace_proxy(saved["old-proxy.mjs"])
            stage1.replace_pins(saved["old-pins.json"])
            stage1.docker("rename", old_id, stage1.PROXY)
            stage1.docker("update", "--restart", "unless-stopped", old_id)
            stage1.docker("start", old_id)
            wss = stage1.load_existing_wss()
            verify_live(wss, old_pins, relay_id)
            preflight.native_release()
            PENDING.unlink()
            stage1.sync_pin_directory()
        gate(wss.reconcile(str(stage1.PINS)) == "READY",
             "POST_ROLLBACK_RECONCILE_HOLD")
    return {"status": "H454_WSS_NATIVE_STATUS_OLD_PROXY_RESTORED",
            "relay_changed": False, "native_service_started": False,
            "evidence_retained": True}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "cutover", "rollback"))
    parser.add_argument("--candidate-source", type=Path)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    try:
        gate((args.mode == "plan") != args.execute,
             "EXPLICIT_MODE_OR_EXECUTE_REQUIRED")
        preflight = verified_preflight()
        if args.mode in ("plan", "cutover"):
            gate(args.candidate_source is not None, "CANDIDATE_SOURCE_REQUIRED")
        if args.mode == "plan":
            result = normal_plan(preflight, args.candidate_source)
        elif args.mode == "cutover":
            result = cutover(args.candidate_source)
        else:
            gate(args.candidate_source is None, "ROLLBACK_NO_CANDIDATE_REQUIRED")
            result = rollback()
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception as exc:
        reason = str(exc) if isinstance(exc, Refused) else "OWNER_HOST_RUNTIME_HOLD"
        if not re.fullmatch("[A-Z_]{1,72}", reason):
            reason = "OWNER_HOST_RUNTIME_HOLD"
        print(json.dumps({"status": "H454_WSS_NATIVE_STATUS_OPERATOR_HOLD",
                          "reason": reason}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
