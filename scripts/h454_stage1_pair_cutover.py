#!/usr/bin/env python3
"""#454: exact-image, one-time relay and pinned WSS sidecar cutover.

Default is a read-only plan. No new service, credential issuer, storage engine,
network permission or agent pairing. Mutations require a separate, root-owned
approval for the installed exact Hermes source SHA and both original IDs.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import stat
import subprocess
import tempfile
import types

from scripts import h15_brc_transactional_upgrade as legacy
from scripts import h15_brc_upgrade_preflight as baseline
from scripts import h15_brc_state_rollback_guard as credential_guard
from scripts import h454_fork_image_offline_metadata as fork_metadata

FORK_COMMIT = "09d1a7ef83d1b6c5aecc7439d8d0829a8b742713"
FORK_IMAGE = "sha256:7dd283729e164ccd0bb4477b4e8edab342fc4ca350922acee6b4d4f33de8bfa1"
LEGACY_IMAGE = "sha256:6e5f74ae35d38713ba8cd4c7b7167eb92f57a2ea439c91b4c29d5aa8b7f2a589"
ARCHIVE_HASH = "5853b9fe50f83775aafa0d22bbc21867cb1bcb7e8eb6e3d289a9962132ef7213"
ARCHIVE = Path("/var/tmp/h454-stage1-image.koLrSWVF/relay.tar.gz")
PIN_ROOT = Path("/var/lib/hermes-h454-wss-sidecar")
WSS_SOURCE_BLOB = "3f496e90a3aa26be69b3c2a24f413910e69af02c"
ORIGINAL_PINS_SHA256 = "46b45a6b2b1873db0581e2d8d55fadaf18091b788432fc2a84440ebcbe60fbaa"
ORIGINAL_PROFILE_SHA256 = "24b679a8887665909864f1eae3a11f8bd07a07e510aae5e22384c6b096f17f86"
OBSERVED_PROFILE_SHA256 = "07f3bc0b2a2b9ab2d58f558a897180dc81c9e6b63fdc0461795e15b2a6133344"
PINS = PIN_ROOT / "pins.json"
PINS_OLD = PIN_ROOT / "stage1-original-pins.json"
PENDING = PIN_ROOT / "reconcile.pending"
APPROVAL = Path("/etc/hermes-brc-relay/stage1-fork-approval.json")
LIVE_SHA = Path("/var/lib/hermes-main-deploy/last-success.sha")
PROXY = "hermes-h454-wss-proxy"
RELAY_OLD = "hermes-brc-relay-h454-stage1-rollback"
PROXY_OLD = "hermes-h454-wss-proxy-h454-stage1-rollback"
HEX = re.compile(r"[0-9a-f]{64}\Z")
wss = None


class Hold(Exception):
    """Sanitized fail-closed status, with no credentials or host data."""


def require(condition, reason):
    if not condition:
        raise Hold(reason)


def protected(path, mode, directory=False):
    meta = path.lstat()
    require(
        meta.st_uid == 0 and meta.st_gid == 0 and stat.S_IMODE(meta.st_mode) == mode
        and (stat.S_ISDIR(meta.st_mode) if directory else stat.S_ISREG(meta.st_mode))
        and (directory or meta.st_nlink == 1), "UNSAFE_PROTECTED_FILE"
    )


def digest_bytes(data):
    return hashlib.sha256(data).hexdigest()


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as reader:
        for block in iter(lambda: reader.read(1048576), b""):
            result.update(block)
    return result.hexdigest()


def docker(*args, optional=False):
    try:
        proc = subprocess.run(
            ["/usr/bin/docker", *args], capture_output=True, text=True, timeout=50,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise Hold("DOCKER_RESULT_AMBIGUOUS") from error
    if proc.returncode:
        require(optional, "DOCKER_OPERATION_FAILED")
        return ""
    require(len(proc.stdout) <= 1048576, "DOCKER_OUTPUT_UNBOUNDED")
    return proc.stdout.strip()


def inspect(kind, name, optional=False):
    require(kind in ("container", "image"), "INVALID_INSPECT_KIND")
    response = docker(kind, "inspect", name, optional=optional)
    if not response and optional:
        return None
    records = json.loads(response)
    require(isinstance(records, list) and len(records) == 1
            and isinstance(records[0], dict), "INSPECT_INVALID")
    return records[0]


def write_once(path, data):
    require(not path.exists() and not path.is_symlink(), "PIN_COLLISION")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as writer:
        writer.write(data)
        writer.flush()
        os.fsync(writer.fileno())


def sync_pin_directory():
    fd = os.open(PIN_ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def replace_pins(data):
    temporary = PIN_ROOT / "stage1-pins.tmp"
    write_once(temporary, data)
    os.replace(temporary, PINS)
    sync_pin_directory()


@contextmanager
def locked_pins():
    protected(PIN_ROOT, 0o700, directory=True)
    protected(PINS, 0o600)
    fd = os.open(PINS, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        info = os.fstat(fd)
        named = PINS.stat()
        require((info.st_dev, info.st_ino) == (named.st_dev, named.st_ino), "PIN_RACE")
        yield os.read(fd, 16385)
    finally:
        os.close(fd)


def load_existing_wss():
    """Run only the already installed, independently Git-blob-pinned reconciler."""
    path = PIN_ROOT / "reconcile.py"
    protected(path, 0o444)
    raw = path.read_bytes()
    blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    require(blob == WSS_SOURCE_BLOB, "INSTALLED_WSS_SOURCE_DRIFT")
    return types.SimpleNamespace(**runpy.run_path(str(path)))


def read_old_pin_pair(raw):
    pins = wss._pins(raw)
    require(pins["relay_name"] == legacy.NAME and pins["sidecar_name"] == PROXY
            and pins["relay_image"] == LEGACY_IMAGE
            and pins["sidecar_image"] == LEGACY_IMAGE, "EXISTING_WSS_PINS_CHANGED")
    observed = inspect("container", pins["sidecar_id"])
    actual_profile = wss.profile_sha256(observed)
    attested = raw
    if actual_profile != pins["profile_sha256"]:
        # Owner-scoped dual-pin recovery of observed Docker metadata drift.
        # Both the original complete pin file and the two profile fingerprints
        # are immutable inputs. No live pin is silently rewritten in preflight.
        require(digest_bytes(raw) == ORIGINAL_PINS_SHA256
                and pins["profile_sha256"] == ORIGINAL_PROFILE_SHA256
                and actual_profile == OBSERVED_PROFILE_SHA256,
                "UNATTESTED_WSS_PROFILE_DRIFT")
        pins = dict(pins, profile_sha256=actual_profile)
        attested = (json.dumps(pins, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        wss._pins(attested)
    # Still enforce every original WSS security invariant, TLS identity,
    # container/network binding, non-root runtime and mount contract.
    relay, sidecar = wss._snapshot(pins, PIN_ROOT, Path(pins["tls_directory"]))
    wss._namespace(relay, sidecar)
    fd = wss._directory(Path(pins["tls_directory"]))
    try:
        ca = wss._read_file(fd, "ca.crt", 0o444)
    finally:
        os.close(fd)
    wss._tls(pins, ca)
    return pins, relay, sidecar, attested

def read_only(release_sha):
    require(os.geteuid() == 0 and re.fullmatch(r"[0-9a-f]{40}", release_sha),
            "ROOT_OR_SHA")
    require(LIVE_SHA.read_text().strip() == release_sha, "INSTALLED_SHA_MISMATCH")
    protected(ARCHIVE.parent, 0o700, directory=True)
    protected(ARCHIVE, 0o600)
    require(all(HEX.fullmatch(value) for value in (
        ORIGINAL_PINS_SHA256, ORIGINAL_PROFILE_SHA256, OBSERVED_PROFILE_SHA256,
        ARCHIVE_HASH)), "INVALID_STAGE1_PINS")
    require(ARCHIVE.stat().st_size <= 200000000
            and digest(ARCHIVE) == ARCHIVE_HASH, "ARCHIVE_DRIFT")
    image = inspect("image", FORK_IMAGE)
    fork_metadata.verify_fork_image_metadata(
        image, expected_image=FORK_IMAGE, expected_source_commit=FORK_COMMIT
    )
    old = inspect("container", legacy.NAME)
    require(baseline.current_gate(old, FORK_IMAGE) == LEGACY_IMAGE
            and old["Config"]["User"] == "979:975", "EXISTING_RELAY_CHANGED")
    require(inspect("container", RELAY_OLD, optional=True) is None
            and inspect("container", PROXY_OLD, optional=True) is None,
            "EXISTING_STAGE1_CHECKPOINT")
    require(not PINS_OLD.exists() and not PENDING.exists(), "RECOVERY_REQUIRED")
    legacy.check_files()
    protected(legacy.BACKUPS, 0o700, directory=True)
    return old


def approval(release_sha, relay, sidecar):
    protected(APPROVAL.parent, 0o700, directory=True)
    protected(APPROVAL, 0o600)
    require(APPROVAL.stat().st_size <= 4096, "APPROVAL_OVERSIZED")
    def unique(items):
        result = {}
        for name, value in items:
            require(name not in result, "DUPLICATE_APPROVAL_KEY")
            result[name] = value
        return result
    record = json.loads(APPROVAL.read_text(encoding="utf-8"), object_pairs_hook=unique)
    require(set(record) == {
        "schema", "decision", "release_sha", "fork_commit", "image",
        "archive_sha256", "legacy_image", "relay_id", "sidecar_id",
        "original_pins_sha256", "observed_sidecar_profile_sha256"
    } and type(record["schema"]) is int and record["schema"] == 1
        and record["decision"] == "OWNER_APPROVED_H454_STAGE1_RELAY_WSS_CUTOVER"
        and record["release_sha"] == release_sha
        and record["fork_commit"] == FORK_COMMIT
        and record["image"] == FORK_IMAGE
        and record["archive_sha256"] == ARCHIVE_HASH
        and record["legacy_image"] == LEGACY_IMAGE
        and record["original_pins_sha256"] == ORIGINAL_PINS_SHA256
        and record["observed_sidecar_profile_sha256"] == OBSERVED_PROFILE_SHA256
        and record["relay_id"] == relay["Id"]
        and record["sidecar_id"] == sidecar["Id"], "APPROVAL_IDENTITY_MISMATCH")


def new_relay_args():
    args = legacy.run_args(FORK_IMAGE, "979:975")
    require(args[:2] == ["run", "-d"] and args[-1] == FORK_IMAGE,
            "LEGACY_RUNTIME_RECIPE_DRIFT")
    args[-1:-1] = ["-e", "BRC_DB=/state/relay.sqlite", "-e", "HOME=/tmp"]
    return args


def create_sidecar(pins, relay_id, old_proxy):
    require(HEX.fullmatch(relay_id), "NEW_RELAY_ID_INVALID")
    labels = old_proxy["Config"]["Labels"]
    request = labels.get("com.hermes.h454.request")
    require(isinstance(request, str) and HEX.fullmatch(request)
            and labels.get("com.hermes.h454.role") == "wss-proxy", "PROXY_LABEL_DRIFT")
    args = [
        "create", "--pull=never", "--name", PROXY,
        "--label", "com.hermes.h454.role=wss-proxy",
        "--label", "com.hermes.h454.request=" + request,
        "--network", "container:" + relay_id,
        "--restart", "unless-stopped", "--read-only", "--user", "65534:65534",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--pids-limit", "32", "--memory", "128m",
        "-e", "H454_SSH_SOURCE_IPV4=" + pins["gateway_ipv4"]
    ]
    for source, dest in (
        (PIN_ROOT / "proxy.mjs", "/run/h454-wss/proxy.mjs"),
        (Path(pins["tls_directory"]) / "relay.key", "/run/h454-wss/relay.key"),
        (Path(pins["tls_directory"]) / "relay.crt", "/run/h454-wss/relay.crt"),
    ):
        args.extend(["--mount", "type=bind,src=" + str(source)
                     + ",dst=" + dest + ",readonly"])
    args.extend(["--entrypoint", "node", LEGACY_IMAGE, "/run/h454-wss/proxy.mjs"])
    result = docker(*args)
    require(HEX.fullmatch(result), "SIDECAR_CREATE_AMBIGUOUS")
    return result


def updated_pins(original, relay_id, sidecar_id):
    new = dict(original, relay_id=relay_id, relay_image=FORK_IMAGE,
               sidecar_id=sidecar_id,
               profile_sha256=wss.profile_sha256(inspect("container", sidecar_id)))
    raw = (json.dumps(new, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    wss._pins(raw)
    wss._snapshot(new, PIN_ROOT, Path(new["tls_directory"]))
    return raw


def compare_auth(before, after):
    with tempfile.TemporaryDirectory(prefix="h454-stage1-compare-",
                                     dir=legacy.BACKUPS) as scratch:
        a, b = Path(scratch) / "before.sqlite", Path(scratch) / "after.sqlite"
        shutil.copyfile(before, a)
        shutil.copyfile(after, b)
        a.chmod(0o600)
        b.chmod(0o600)
        require(credential_guard.compare_disposable_copies(a, b) ==
                "PASS_READ_ONLY_NO_CREDENTIAL_REINTRODUCTION", "AUTH_STATE_REGRESSION")


def restore(original_pins, old_relay, old_proxy, new_relay_id, new_proxy_id, count):
    """Only remove identified task-owned candidates; never restore stale SQLite."""
    current_proxy = inspect("container", PROXY, optional=True)
    if current_proxy and current_proxy["Id"] != old_proxy["Id"]:
        require(new_proxy_id and current_proxy.get("Id") == new_proxy_id
                and current_proxy.get("Image") == LEGACY_IMAGE,
                "FOREIGN_SIDE_CAR")
        require(isinstance(original_pins.get("tls_directory"), str),
                "FOREIGN_SIDE_CAR")
        labels = (current_proxy.get("Config") or {}).get("Labels") or {}
        old_labels = old_proxy["Config"].get("Labels") or {}
        host = current_proxy.get("HostConfig") or {}
        expected_mounts = {
            "/run/h454-wss/proxy.mjs": str(PIN_ROOT / "proxy.mjs"),
            "/run/h454-wss/relay.key": str(Path(original_pins["tls_directory"]) / "relay.key"),
            "/run/h454-wss/relay.crt": str(Path(original_pins["tls_directory"]) / "relay.crt"),
        }
        mounts = current_proxy.get("Mounts") or []
        require(new_proxy_id and current_proxy["Id"] == new_proxy_id
                and current_proxy["Image"] == LEGACY_IMAGE
                and labels.get("com.hermes.h454.role") == "wss-proxy"
                and labels.get("com.hermes.h454.request") ==
                    old_labels.get("com.hermes.h454.request")
                and current_proxy["Config"]["User"] == "65534:65534"
                and host["NetworkMode"] == "container:" + new_relay_id
                and host["ReadonlyRootfs"] is True and host["Privileged"] is False
                and "ALL" in (host.get("CapDrop") or [])
                and set(host.get("SecurityOpt") or []) == {"no-new-privileges"}
                and len(mounts) == 3
                and all(mnt["Type"] == "bind" and mnt["RW"] is False
                        and expected_mounts.get(mnt["Destination"]) == mnt["Source"]
                        for mnt in mounts), "FOREIGN_SIDE_CAR")
        docker("rm", "-f", new_proxy_id)
    current_relay = inspect("container", legacy.NAME, optional=True)
    if current_relay and current_relay["Id"] != old_relay["Id"]:
        require(new_relay_id and current_relay.get("Id") == new_relay_id
                and current_relay.get("Image") == FORK_IMAGE,
                "FOREIGN_RELAY")
        host = current_relay.get("HostConfig") or {}
        mounts = current_relay.get("Mounts") or []
        require(new_relay_id and current_relay["Id"] == new_relay_id
                and current_relay["Image"] == FORK_IMAGE
                and current_relay["Config"]["User"] == "979:975"
                and current_relay["Config"]["Labels"].get("com.hermes.scope") ==
                    "h15-brc-owner-relay"
                and host["NetworkMode"] == "hermes-brc-internal"
                and host["ReadonlyRootfs"] is True and host["Privileged"] is False
                and "ALL" in (host.get("CapDrop") or [])
                and set(host.get("SecurityOpt") or []) == {"no-new-privileges"}
                and len(mounts) == 1 and mounts[0]["Type"] == "bind"
                and mounts[0]["Source"] == "/var/lib/hermes-brc-relay"
                and mounts[0]["Destination"] == "/state"
                and mounts[0]["RW"] is True, "FOREIGN_RELAY")
        docker("rm", "-f", new_relay_id)
    checkpoint = inspect("container", RELAY_OLD, optional=True)
    if checkpoint:
        require(checkpoint["Id"] == old_relay["Id"]
                and checkpoint["Image"] == LEGACY_IMAGE, "RELAY_CHECKPOINT_CHANGED")
        docker("rename", RELAY_OLD, legacy.NAME)
    recovered_relay = inspect("container", legacy.NAME)
    require(recovered_relay["Id"] == old_relay["Id"], "OLD_RELAY_MISSING")
    if not recovered_relay["State"]["Running"]:
        docker("start", legacy.NAME)
    checkpoint = inspect("container", PROXY_OLD, optional=True)
    if checkpoint:
        require(checkpoint["Id"] == old_proxy["Id"]
                and checkpoint["Image"] == LEGACY_IMAGE, "PROXY_CHECKPOINT_CHANGED")
        docker("rename", PROXY_OLD, PROXY)
    recovered_proxy = inspect("container", PROXY)
    require(recovered_proxy["Id"] == old_proxy["Id"], "OLD_PROXY_MISSING")
    if not recovered_proxy["State"]["Running"]:
        docker("start", PROXY)
    original = PINS_OLD.read_bytes()
    if PINS.read_bytes() != original:
        replace_pins(original)
    read_old_pin_pair(original)
    require(legacy.healthy(count, tries=60), "OLD_DEVICES_NOT_RECONNECTED")
    docker("update", "--restart", "unless-stopped", legacy.NAME)
    docker("update", "--restart", "unless-stopped", PROXY)
    PENDING.unlink()
    sync_pin_directory()


def cutover(release_sha):
    global wss
    with legacy.lock():
        read_only(release_sha)
        wss = load_existing_wss()
        with locked_pins() as original_raw:
            original, relay, proxy, attested_raw = read_old_pin_pair(original_raw)
            approval(release_sha, relay, proxy)
            baseline_devices = legacy.devices()
            require(baseline_devices >= 1, "NO_LIVE_DEVICES")
            before = legacy.snapshot()
            write_once(PINS_OLD, attested_raw)
            marker = {
                "schema": 1, "original_pin_sha256": digest(PINS_OLD),
                "release_sha": release_sha, "devices": baseline_devices
            }
            write_once(PENDING, (json.dumps(marker, sort_keys=True) + "\n").encode("ascii"))
            sync_pin_directory()
            new_relay_id = new_proxy_id = ""
            try:
                docker("stop", "--time", "12", PROXY)
                docker("update", "--restart", "no", PROXY)
                docker("rename", PROXY, PROXY_OLD)
                docker("stop", "--time", "20", legacy.NAME)
                docker("update", "--restart", "no", legacy.NAME)
                docker("rename", legacy.NAME, RELAY_OLD)
                new_relay_id = docker(*new_relay_args())
                require(HEX.fullmatch(new_relay_id), "RELAY_CREATE_AMBIGUOUS")
                candidate = inspect("container", legacy.NAME)
                require(candidate["Id"] == new_relay_id
                        and candidate["Image"] == FORK_IMAGE
                        and candidate["Config"]["User"] == "979:975",
                        "NEW_RELAY_IDENTITY_DRIFT")
                new_proxy_id = create_sidecar(original, new_relay_id, proxy)
                next_raw = updated_pins(original, new_relay_id, new_proxy_id)
                replace_pins(next_raw)
                docker("start", new_proxy_id)
                new_pins = wss._pins(next_raw)
                new_relay, new_proxy = wss._snapshot(
                    new_pins, PIN_ROOT, Path(original["tls_directory"]))
                wss._namespace(new_relay, new_proxy)
                require(legacy.healthy(baseline_devices, tries=120),
                        "CANDIDATE_DEVICES_NOT_RECONNECTED")
                after = legacy.snapshot()
                compare_auth(before, after)
                docker("update", "--restart", "unless-stopped", legacy.NAME)
                PENDING.unlink()
                sync_pin_directory()
                require(wss.reconcile(str(PINS)) == "READY", "WSS_NOT_READY")
                return new_relay_id, new_proxy_id
            except Exception as original_error:
                try:
                    restore(original, relay, proxy, new_relay_id,
                            new_proxy_id, baseline_devices)
                except Exception as rollback_error:
                    raise Hold("ROLLBACK_INCOMPLETE_MANUAL_RECOVERY_REQUIRED") from rollback_error
                raise Hold("CUTOVER_FAILED_ORIGINAL_PAIR_RESTORED") from original_error


def rollback_pair(release_sha, *, after_success=False):
    """Recover interrupted stages or restore old binaries after final regression."""
    global wss
    require(os.geteuid() == 0 and re.fullmatch(r"[0-9a-f]{40}", release_sha),
            "ROOT_OR_SHA")
    require(LIVE_SHA.read_text().strip() == release_sha, "INSTALLED_SHA_MISMATCH")
    with legacy.lock():
        wss = load_existing_wss()
        protected(PIN_ROOT, 0o700, directory=True)
        protected(PINS_OLD, 0o600)
        with locked_pins():
            saved = PINS_OLD.read_bytes()
            original = wss._pins(saved)
            require(original["relay_name"] == legacy.NAME
                    and original["sidecar_name"] == PROXY
                    and original["relay_image"] == LEGACY_IMAGE
                    and original["sidecar_image"] == LEGACY_IMAGE,
                    "ORIGINAL_PIN_SCOPE_CHANGED")
            old_relay = inspect("container", RELAY_OLD, optional=True)
            if old_relay is None:
                old_relay = inspect("container", legacy.NAME)
            old_proxy = inspect("container", PROXY_OLD, optional=True)
            if old_proxy is None:
                old_proxy = inspect("container", PROXY)
            require(old_relay["Id"] == original["relay_id"]
                    and old_relay["Image"] == LEGACY_IMAGE
                    and old_proxy["Id"] == original["sidecar_id"]
                    and old_proxy["Image"] == LEGACY_IMAGE,
                    "CHECKPOINT_IDENTITIES_CHANGED")
            approval(release_sha, old_relay, old_proxy)
            if after_success:
                require(not PENDING.exists(), "PENDING_RECOVERY_REQUIRED")
                current_pins = wss._pins(PINS.read_bytes())
                require(current_pins["relay_image"] == FORK_IMAGE
                        and current_pins["sidecar_image"] == LEGACY_IMAGE,
                        "FORK_PAIR_NOT_ACTIVE")
                try:
                    count = legacy.devices()
                except (OSError, ValueError, legacy.CutoverDenied):
                    # A broken new relay must not prevent recovery of the old
                    # one. The full client/device matrix remains a post-rollback gate.
                    count = 1
                count = max(1, count)
                data = {
                    "schema": 1, "original_pin_sha256": digest(PINS_OLD),
                    "release_sha": release_sha, "devices": count
                }
                write_once(PENDING, (json.dumps(data, sort_keys=True) + "\n").encode("ascii"))
                sync_pin_directory()
            else:
                protected(PENDING, 0o600)
                data = json.loads(PENDING.read_bytes())
                require(set(data) == {
                    "schema", "original_pin_sha256", "release_sha", "devices"
                } and type(data["schema"]) is int and data["schema"] == 1
                    and data["original_pin_sha256"] == digest(PINS_OLD)
                    and data["release_sha"] == release_sha
                    and type(data["devices"]) is int and 1 <= data["devices"] <= 25,
                    "PENDING_RECEIPT_CHANGED")
                count = data["devices"]
            new_relay = inspect("container", legacy.NAME, optional=True)
            new_proxy = inspect("container", PROXY, optional=True)
            relay_id = new_relay["Id"] if new_relay and \
                new_relay["Image"] == FORK_IMAGE else ""
            proxy_id = new_proxy["Id"] if new_proxy and \
                new_proxy["Image"] == LEGACY_IMAGE and \
                new_proxy["HostConfig"]["NetworkMode"] == "container:" + relay_id else ""
            restore(original, old_relay, old_proxy, relay_id, proxy_id, count)
            require(wss.reconcile(str(PINS)) == "READY", "OLD_WSS_NOT_READY")
            return old_relay["Id"], old_proxy["Id"]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "cutover", "recover", "rollback"))
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    try:
        require(not args.execute if args.mode == "plan" else args.execute,
                "EXPLICIT_MODE_GUARD")
        if args.mode == "plan":
            global wss
            with legacy.lock():
                read_only(args.release_sha)
                wss = load_existing_wss()
                with locked_pins() as raw:
                    read_old_pin_pair(raw)
            print("H454_STAGE1_PAIR_PREFLIGHT=PASS_NO_MUTATIONS")
        elif args.mode == "cutover":
            relay_id, sidecar_id = cutover(args.release_sha)
            print("H454_STAGE1_PAIR=SWITCHED_PENDING_POST_DEPLOY_ACCEPTANCE")
            print("H454_STAGE1_RELAY_ID=" + relay_id)
            print("H454_STAGE1_PROXY_ID=" + sidecar_id)
        else:
            relay_id, sidecar_id = rollback_pair(
                args.release_sha, after_success=args.mode == "rollback")
            print("H454_STAGE1_PAIR=ORIGINAL_PAIR_RESTORED")
            print("H454_STAGE1_RELAY_ID=" + relay_id)
            print("H454_STAGE1_PROXY_ID=" + sidecar_id)
        return 0
    except (Hold, OSError, ValueError, KeyError, baseline.UpgradeDenied,
            credential_guard.CredentialRegressionDenied) as error:
        detail = str(error) if isinstance(error, Hold) else type(error).__name__
        print("H454_STAGE1_PAIR=HOLD:" + detail)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
