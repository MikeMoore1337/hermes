#!/usr/bin/env python3
"""H454 Stage 2: owner-gated joint relay/WSS native3 cutover.

Unlike the historical single-relay operator, this changes both members of the
pinned network-namespace pair. This module is DORMANT until separately deployed
and authorized. No Windows native permissions or agent pairing are granted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

from scripts import h15_brc_transactional_upgrade as legacy
from scripts import h15_brc_upgrade_preflight as candidate
from scripts import h454_native3_paired_preflight as admission
from scripts import h454_stage1_pair_cutover as stage1

APPROVAL = Path("/etc/hermes-brc-relay/native3-paired-approval.json")
ORIGINAL_PINS = stage1.PIN_ROOT / "native3-original-pins.json"
PENDING = admission.PAIR_PENDING
PAIR_RELAY = admission.RELAY_CHECKPOINT
PAIR_PROXY = admission.PROXY_CHECKPOINT


class TransactionDenied(ValueError):
    """Only constant, non-sensitive reason codes may cross this boundary."""


def require(ok: bool, code: str) -> None:
    if not ok:
        raise TransactionDenied(code)


def strict_container(name: str):
    """Differentiate an absent name from an unavailable Docker daemon."""
    require(name in (legacy.NAME, stage1.PROXY, PAIR_RELAY, PAIR_PROXY),
            "UNKNOWN_CONTAINER_NAME")
    result = stage1.docker(
        "container", "ls", "--all", "--no-trunc",
        "--filter", "name=^/" + name + "$", "--format", "{{.Names}}")
    require(result in ("", name), "CONTAINER_DISCOVERY_AMBIGUOUS")
    if not result:
        return None
    obj = stage1.inspect("container", name)
    require(obj.get("Name") == "/" + name and stage1.HEX.fullmatch(
        str(obj.get("Id", ""))), "CONTAINER_IDENTITY_AMBIGUOUS")
    return obj


def approval_record(*, release_sha: str, candidate_sha: str, image: str,
                    archive_sha: str, runtime: str, relay: dict,
                    proxy: dict, raw_pins: bytes) -> None:
    """Reject stale approvals, duplicate keys and foreign relay/WSS identities."""
    stage1.protected(APPROVAL.parent, 0o700, directory=True)
    stage1.protected(APPROVAL, 0o600)
    require(APPROVAL.stat().st_size <= 4096, "APPROVAL_TOO_LARGE")

    def unique(items):
        record = {}
        for key, value in items:
            require(key not in record, "APPROVAL_DUPLICATE_KEY")
            record[key] = value
        return record

    doc = json.loads(APPROVAL.read_bytes(), object_pairs_hook=unique)
    expected = {
        "schema": 1,
        "decision": "OWNER_APPROVED_H454_NATIVE3_JOINT_RELAY_WSS_CUTOVER",
        "scope": "EXISTING_PAIRED_DEVICES_NO_HOST_PERMISSION_CHANGE",
        "release_sha": release_sha,
        "candidate_sha": candidate_sha,
        "ci_config_image_id": image,
        "archive_sha256": archive_sha,
        "runtime_image_id": runtime,
        "previous_relay_image": stage1.FORK_IMAGE,
        "previous_proxy_image": stage1.LEGACY_IMAGE,
        "previous_relay_id": relay["Id"],
        "previous_proxy_id": proxy["Id"],
        "previous_pins_sha256": hashlib.sha256(raw_pins).hexdigest(),
        "relay_checkpoint": PAIR_RELAY,
        "proxy_checkpoint": PAIR_PROXY,
    }
    require(type(doc) is dict and doc == expected
            and type(doc.get("schema")) is int,
            "APPROVAL_SCOPE_OR_IDENTITY_MISMATCH")


def pending_write(receipt: dict) -> None:
    """Durable checkpoint identity; never overwrite an unrelated marker."""
    data = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) +
            "\n").encode("ascii")
    temp = stage1.PIN_ROOT / "native3-pair.pending.tmp"
    stage1.write_once(temp, data)
    try:
        os.replace(temp, PENDING)
        stage1.sync_pin_directory()
    finally:
        if temp.exists():
            temp.unlink()


def candidate_relay_args(image: str, user: str) -> list[str]:
    require(user == "979:975", "OLD_RELAY_USER_CHANGED")
    args = legacy.run_args(
        image, user, registry_source=str(candidate.PINNED_REGISTRY_SOURCE))
    require(args[:2] == ["run", "-d"] and args[-1] == image
            and args.count("--mount") == 2
            and "--privileged" not in args
            and "--publish" not in args, "NEW_RELAY_RECIPE_DRIFT")
    return args


def updated_pins(wss, old: dict, relay_id: str, proxy_id: str,
                 image: str) -> bytes:
    require(stage1.HEX.fullmatch(relay_id) and
            stage1.HEX.fullmatch(proxy_id), "NEW_PAIR_ID_INVALID")
    new = dict(old, relay_image=image, relay_id=relay_id,
               sidecar_id=proxy_id,
               profile_sha256=wss.profile_sha256(
                   stage1.inspect("container", proxy_id)))
    raw = (json.dumps(new, sort_keys=True, separators=(",", ":")) +
           "\n").encode("ascii")
    wss._pins(raw)
    return raw


def owned_candidate(obj, expected_id: str, image: str, kind: str,
                    relay_id: str = "", *, old_proxy: dict | None = None,
                    old_pins: dict | None = None) -> None:
    """Never delete a container without matching exact ID and sandbox profile."""
    require(obj is not None and obj.get("Id") == expected_id
            and obj.get("Image") == image, "FOREIGN_CANDIDATE_CONTAINER")
    cfg = obj.get("Config") or {}
    host = obj.get("HostConfig") or {}
    mounts = obj.get("Mounts") or []
    opts = host.get("SecurityOpt") or []
    require(host.get("Privileged") is False and
            host.get("ReadonlyRootfs") is True and
            host.get("CapDrop") == ["ALL"] and
            isinstance(opts, list) and len(opts) == 1 and
            opts[0] in ("no-new-privileges", "no-new-privileges:true") and
            host.get("CapAdd") in (None, []) and
            host.get("Devices") in (None, []) and
            host.get("Binds") in (None, []) and
            host.get("PortBindings") in (None, {}) and
            host.get("PidMode") not in ("host",) and
            host.get("UsernsMode") not in ("host",),
            "FOREIGN_CANDIDATE_CONTAINER")
    if kind == "relay":
        require(cfg.get("User") == "979:975" and
                (cfg.get("Labels") or {}).get("com.hermes.scope")
                == "h15-brc-owner-relay" and
                host.get("NetworkMode") == "hermes-brc-internal" and
                type(host.get("PidsLimit")) is int and
                1 <= host["PidsLimit"] <= 128 and
                type(host.get("Memory")) is int and
                128 * 1024 * 1024 <= host["Memory"] <= 1024 * 1024 * 1024 and
                candidate.registry_mount_source(obj)
                == str(candidate.PINNED_REGISTRY_SOURCE) and
                len(mounts) == 2, "FOREIGN_CANDIDATE_RELAY")
    else:
        labels = cfg.get("Labels") or {}
        require(old_proxy is not None and old_pins is not None,
                "FOREIGN_CANDIDATE_PROXY")
        original_labels = (old_proxy.get("Config") or {}).get("Labels") or {}
        expected_mounts = {
            "/run/h454-wss/proxy.mjs": str(stage1.PIN_ROOT / "proxy.mjs"),
            "/run/h454-wss/relay.key":
                str(Path(old_pins["tls_directory"]) / "relay.key"),
            "/run/h454-wss/relay.crt":
                str(Path(old_pins["tls_directory"]) / "relay.crt"),
        }
        original_request = original_labels.get("com.hermes.h454.request")
        require(isinstance(original_request, str) and
                stage1.HEX.fullmatch(original_request) is not None and
                cfg.get("User") == "65534:65534"
                and labels.get("com.hermes.h454.role") == "wss-proxy"
                and labels.get("com.hermes.h454.request") == original_request
                and host.get("NetworkMode") == "container:" + relay_id
                and host.get("PidsLimit") == 32
                and host.get("Memory") == 128 * 1024 * 1024
                and len(mounts) == 3 and
                all(isinstance(m, dict) and m.get("Type") == "bind" and
                    m.get("RW") is False and
                    expected_mounts.get(m.get("Destination")) == m.get("Source")
                    for m in mounts),
                "FOREIGN_CANDIDATE_PROXY")


def restore_pair(*, relay: dict, proxy: dict, original: bytes,
                 image: str, relay_id: str, proxy_id: str,
                 baseline: int, wss) -> None:
    """Rollback both names or refuse rather than deleting unidentified data."""
    current_proxy = strict_container(stage1.PROXY)
    if current_proxy and current_proxy["Id"] != proxy["Id"]:
        require(bool(proxy_id), "AMBIGUOUS_PROXY_MANUAL_RECOVERY")
        owned_candidate(current_proxy, proxy_id, stage1.LEGACY_IMAGE,
                        "proxy", relay_id, old_proxy=proxy,
                        old_pins=wss._pins(original))
        stage1.docker("rm", "-f", proxy_id)
    current_relay = strict_container(legacy.NAME)
    if current_relay and current_relay["Id"] != relay["Id"]:
        require(bool(relay_id), "AMBIGUOUS_RELAY_MANUAL_RECOVERY")
        owned_candidate(current_relay, relay_id, image, "relay")
        stage1.docker("rm", "-f", relay_id)

    for checkpoint_name, original_name, original_obj in (
        (PAIR_RELAY, legacy.NAME, relay),
        (PAIR_PROXY, stage1.PROXY, proxy),
    ):
        checkpoint = strict_container(checkpoint_name)
        if checkpoint:
            require(checkpoint["Id"] == original_obj["Id"]
                    and checkpoint["Image"] == original_obj["Image"],
                    "FOREIGN_ROLLBACK_CHECKPOINT")
            require(strict_container(original_name) is None,
                    "ROLLBACK_NAME_OCCUPIED")
            stage1.docker("rename", checkpoint_name, original_name)
        existing = strict_container(original_name)
        require(existing is not None and
                existing["Id"] == original_obj["Id"],
                "ORIGINAL_CONTAINER_UNAVAILABLE")

    for name in (legacy.NAME, stage1.PROXY):
        current = strict_container(name)
        if (current.get("State") or {}).get("Running") is not True:
            stage1.docker("start", name)
        stage1.docker("update", "--restart", "unless-stopped", name)
    if stage1.PINS.read_bytes() != original:
        stage1.replace_pins(original)
    restored = wss._pins(original)
    wss._snapshot(restored, stage1.PIN_ROOT,
                  Path(restored["tls_directory"]))
    require(legacy.healthy(baseline, tries=60),
            "ORIGINAL_PAIR_RECONNECT_NOT_VERIFIED")
    if PENDING.exists():
        stage1.protected(PENDING, 0o600)
        PENDING.unlink()
        stage1.sync_pin_directory()


def cutover(*, release_sha: str, bundle: Path, image: str,
            archive_sha: str, candidate_sha: str) -> dict:
    require(os.geteuid() == 0, "ROOT_REQUIRED")
    admission.verify_installed_source(release_sha)
    with legacy.lock():
        stage1.protected(legacy.BACKUPS, 0o700, directory=True)
        legacy.check_files()
        checked = candidate.admit(bundle, image, archive_sha, candidate_sha)
        require(checked.get("status") == "PREFLIGHT_PASS"
                and checked.get("bundle_verified") is True
                and checked.get("changes_performed") is False
                and checked.get("current_image") == stage1.FORK_IMAGE
                and checked.get("deployment_approved") is False,
                "CANDIDATE_NOT_ATTESTED")
        runtime = checked["candidate_image"]
        wss = stage1.load_existing_wss()
        relay, proxy = admission.verify_pair(wss)
        admission.check_free_checkpoints()
        baseline = legacy.devices()
        require(type(baseline) is int and 1 <= baseline <= 25,
                "BASELINE_DEVICES_UNAVAILABLE")
        with stage1.locked_pins() as original:
            pins = wss._pins(original)
            require(pins["relay_id"] == relay["Id"] and
                    pins["sidecar_id"] == proxy["Id"] and
                    pins["relay_image"] == stage1.FORK_IMAGE and
                    pins["sidecar_image"] == stage1.LEGACY_IMAGE,
                    "PAIR_CHANGED_AFTER_PREFLIGHT")
            # Fail on a concurrent Docker replacement after the pinned read.
            require(strict_container(legacy.NAME)["Id"] == relay["Id"] and
                    strict_container(stage1.PROXY)["Id"] == proxy["Id"],
                    "LIVE_PAIR_CHANGED")
            approval_record(
                release_sha=release_sha, candidate_sha=candidate_sha,
                image=image, archive_sha=archive_sha, runtime=runtime,
                relay=relay, proxy=proxy, raw_pins=original)
            require(not ORIGINAL_PINS.exists() and
                    not ORIGINAL_PINS.is_symlink() and
                    not PENDING.exists() and not PENDING.is_symlink(),
                    "PREVIOUS_TRANSACTION_NOT_CLEARED")
            # Both SQLite snapshots are copies; never write an older
            # credential database back onto the live relay.
            before = legacy.snapshot()
            stage1.write_once(ORIGINAL_PINS, original)
            receipt = {
                "schema": 1, "release_sha": release_sha,
                "candidate_sha": candidate_sha, "runtime_image": runtime,
                "relay_id": relay["Id"], "proxy_id": proxy["Id"],
                "pins_sha256": hashlib.sha256(original).hexdigest(),
                "baseline": baseline, "new_relay_id": "",
                "new_proxy_id": "",
            }
            pending_write(receipt)
            new_relay_id = new_proxy_id = ""
            try:
                stage1.docker("stop", "--time", "12", stage1.PROXY)
                stage1.docker("update", "--restart", "no", stage1.PROXY)
                stage1.docker("rename", stage1.PROXY, PAIR_PROXY)
                stage1.docker("stop", "--time", "20", legacy.NAME)
                stage1.docker("update", "--restart", "no", legacy.NAME)
                stage1.docker("rename", legacy.NAME, PAIR_RELAY)
                new_relay_id = stage1.docker(
                    *candidate_relay_args(runtime, relay["Config"]["User"]))
                require(stage1.HEX.fullmatch(new_relay_id),
                        "NEW_RELAY_CREATE_AMBIGUOUS")
                receipt["new_relay_id"] = new_relay_id
                pending_write(receipt)
                new_relay = strict_container(legacy.NAME)
                require(new_relay["Id"] == new_relay_id and
                        new_relay["Image"] == runtime,
                        "NEW_RELAY_IMAGE_OR_ID_DRIFT")
                new_proxy_id = stage1.create_sidecar(pins, new_relay_id, proxy)
                receipt["new_proxy_id"] = new_proxy_id
                pending_write(receipt)
                stage1.replace_pins(
                    updated_pins(wss, pins, new_relay_id,
                                 new_proxy_id, runtime))
                stage1.docker("start", new_proxy_id)
                fresh = wss._pins(stage1.PINS.read_bytes())
                new_relay, new_proxy = wss._snapshot(
                    fresh, stage1.PIN_ROOT, Path(fresh["tls_directory"]))
                wss._namespace(new_relay, new_proxy)
                require(legacy.healthy(baseline, tries=120),
                        "NEW_PAIR_RECONNECT_FAILED")
                after = legacy.snapshot()
                stage1.compare_auth(before, after)
                stage1.docker("update", "--restart", "unless-stopped",
                              legacy.NAME)
                stage1.docker("update", "--restart", "unless-stopped",
                              stage1.PROXY)
                # Assert the *running compiled* candidate contract, including
                # the original immutable Stage 1 registry and denied host rights.
                actual = candidate.inspect(["container", "inspect", legacy.NAME])
                require(candidate.current_gate(actual, stage1.FORK_IMAGE)
                        == runtime, "CANDIDATE_RUNTIME_SECURITY_DRIFT")
                PENDING.unlink()
                stage1.sync_pin_directory()
            except Exception as exc:
                try:
                    restore_pair(
                        relay=relay, proxy=proxy, original=original,
                        image=runtime, relay_id=new_relay_id,
                        proxy_id=new_proxy_id, baseline=baseline, wss=wss)
                except Exception as restore_exc:
                    raise TransactionDenied(
                        "PAIR_ROLLBACK_INCOMPLETE_MANUAL_RECOVERY") from restore_exc
                raise TransactionDenied(
                    "PAIR_CUTOVER_FAILED_ORIGINAL_RESTORED") from exc

        # Reconciler takes its own pin lock: never call inside locked_pins().
        try:
            require(wss.reconcile(str(stage1.PINS)) == "READY",
                    "WSS_POST_CUTOVER_NOT_READY")
        except Exception as exc:
            with stage1.locked_pins():
                try:
                    restore_pair(
                        relay=relay, proxy=proxy, original=original,
                        image=runtime, relay_id=new_relay_id,
                        proxy_id=new_proxy_id, baseline=baseline, wss=wss)
                except Exception as restore_exc:
                    raise TransactionDenied(
                        "POST_CUTOVER_ROLLBACK_INCOMPLETE") from restore_exc
            raise TransactionDenied(
                "WSS_FAILED_ORIGINAL_PAIR_RESTORED") from exc

        return {
            "status": "SWITCHED_PENDING_CHATGPT_CODEX_LIVE_ACCEPTANCE",
            "candidate_runtime_image_id": runtime,
            "previous_relay_image": stage1.FORK_IMAGE,
            "previous_proxy_image": stage1.LEGACY_IMAGE,
            "previous_containers_retained": True,
            "sqlite_backup_retained": True,
            "native_windows_activated": False,
            "client_e2e_verified": False,
        }



def verified_candidate_for_recovery(bundle: Path, image: str,
                                    archive_sha: str, candidate_sha: str) -> str:
    """Attest imported OCI independently; the old relay may be stopped."""
    record = candidate.verify(
        directory=bundle, expected_archive_sha=archive_sha,
        expected_image_id=image, expected_hermes_sha=candidate_sha)
    require(record.get("owner_agents_paired") is False and
            record.get("production_mcp_enabled") is False,
            "RECOVERY_BUNDLE_OUT_OF_SCOPE")
    imported, runtime = candidate.candidate_runtime_image(
        bundle, image, candidate_sha)
    candidate.candidate_gate(imported, runtime)
    return runtime


def pending_read() -> dict:
    """Strict, sanitized recovery marker with original and new identities."""
    stage1.protected(PENDING, 0o600)

    def unique(items):
        found = {}
        for key, value in items:
            require(key not in found, "PENDING_DUPLICATE_KEY")
            found[key] = value
        return found

    require(PENDING.stat().st_size <= 4096, "PENDING_TOO_LARGE")
    doc = json.loads(PENDING.read_bytes(), object_pairs_hook=unique)
    require(type(doc) is dict and set(doc) == {
        "schema", "release_sha", "candidate_sha", "runtime_image",
        "relay_id", "proxy_id", "pins_sha256", "baseline",
        "new_relay_id", "new_proxy_id",
    } and type(doc["schema"]) is int and doc["schema"] == 1
            and type(doc["baseline"]) is int
            and 1 <= doc["baseline"] <= 25
            and stage1.HEX.fullmatch(str(doc["relay_id"]))
            and stage1.HEX.fullmatch(str(doc["proxy_id"]))
            and stage1.HEX.fullmatch(str(doc["pins_sha256"]))
            and candidate.IMAGE.fullmatch(str(doc["runtime_image"]))
            and all(not value or stage1.HEX.fullmatch(value)
                    for value in (doc["new_relay_id"], doc["new_proxy_id"])),
            "PENDING_RECEIPT_INVALID")
    return doc


def restore_authorized(*, release_sha: str, bundle: Path, image: str,
                       archive_sha: str, candidate_sha: str,
                       after_success: bool) -> dict:
    """Recover an interrupted pair or roll back a successful switch.

    A failed or ambiguous identity check refuses to delete *anything*.
    Unlike first-time cutover, this cannot call admit(): the old relay may
    legitimately be stopped or renamed during recovery.
    """
    require(os.geteuid() == 0, "ROOT_REQUIRED")
    admission.verify_installed_source(release_sha)
    with legacy.lock():
        stage1.protected(legacy.BACKUPS, 0o700, directory=True)
        legacy.check_files()
        runtime = verified_candidate_for_recovery(
            bundle, image, archive_sha, candidate_sha)
        stage1.protected(stage1.PIN_ROOT, 0o700, directory=True)
        stage1.protected(ORIGINAL_PINS, 0o600)
        original = ORIGINAL_PINS.read_bytes()
        wss = stage1.load_existing_wss()
        pins = wss._pins(original)
        require(pins["relay_image"] == stage1.FORK_IMAGE and
                pins["sidecar_image"] == stage1.LEGACY_IMAGE and
                pins["relay_name"] == legacy.NAME and
                pins["sidecar_name"] == stage1.PROXY,
                "ORIGINAL_PIN_SCOPE_CHANGED")
        relay = strict_container(PAIR_RELAY) or strict_container(legacy.NAME)
        proxy = strict_container(PAIR_PROXY) or strict_container(stage1.PROXY)
        require(relay is not None and proxy is not None and
                relay["Id"] == pins["relay_id"] and
                proxy["Id"] == pins["sidecar_id"] and
                relay["Image"] == stage1.FORK_IMAGE and
                proxy["Image"] == stage1.LEGACY_IMAGE,
                "OLD_CHECKPOINT_IDENTITY_CHANGED")
        approval_record(
            release_sha=release_sha, candidate_sha=candidate_sha,
            image=image, archive_sha=archive_sha, runtime=runtime,
            relay=relay, proxy=proxy, raw_pins=original)
        with stage1.locked_pins() as active_raw:
            current = wss._pins(active_raw)
            if after_success:
                require(not PENDING.exists() and not PENDING.is_symlink(),
                        "PENDING_RECOVERY_REQUIRED")
                require(current["relay_image"] == runtime and
                        current["sidecar_image"] == stage1.LEGACY_IMAGE
                        and stage1.HEX.fullmatch(current["relay_id"])
                        and stage1.HEX.fullmatch(current["sidecar_id"]),
                        "ACTIVE_CANDIDATE_PAIR_NOT_VERIFIED")
                require(strict_container(legacy.NAME)["Id"] ==
                        current["relay_id"] and
                        strict_container(stage1.PROXY)["Id"] ==
                        current["sidecar_id"],
                        "ACTIVE_CANDIDATE_IDS_CHANGED")
                try:
                    baseline = legacy.devices()
                except (OSError, ValueError, legacy.CutoverDenied):
                    baseline = 1
                require(type(baseline) is int and 1 <= baseline <= 25,
                        "ROLLBACK_BASELINE_INVALID")
                data = {
                    "schema": 1, "release_sha": release_sha,
                    "candidate_sha": candidate_sha, "runtime_image": runtime,
                    "relay_id": relay["Id"], "proxy_id": proxy["Id"],
                    "pins_sha256": hashlib.sha256(original).hexdigest(),
                    "baseline": baseline, "new_relay_id": current["relay_id"],
                    "new_proxy_id": current["sidecar_id"],
                }
                pending_write(data)
            else:
                require(PENDING.exists() and not PENDING.is_symlink(),
                        "NO_RECOVERY_MARKER")
                data = pending_read()
                require(data["release_sha"] == release_sha
                        and data["candidate_sha"] == candidate_sha
                        and data["runtime_image"] == runtime
                        and data["relay_id"] == relay["Id"]
                        and data["proxy_id"] == proxy["Id"]
                        and data["pins_sha256"] ==
                            hashlib.sha256(original).hexdigest(),
                        "RECOVERY_MARKER_DRIFT")
            restore_pair(
                relay=relay, proxy=proxy, original=original,
                image=runtime, relay_id=data["new_relay_id"],
                proxy_id=data["new_proxy_id"],
                baseline=data["baseline"], wss=wss)

        require(wss.reconcile(str(stage1.PINS)) == "READY",
                "RESTORED_WSS_NOT_READY")
        return {
            "status": "ORIGINAL_PAIR_RESTORED_PENDING_CLIENT_VERIFICATION",
            "previous_relay_image": stage1.FORK_IMAGE,
            "previous_proxy_image": stage1.LEGACY_IMAGE,
            "client_e2e_verified": False,
            "host_permissions_changed": False,
            "auth_database_reverted": False,
        }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "cutover", "recover", "rollback"))
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--bundle-dir", required=True, type=Path)
    parser.add_argument("--image", required=True)
    parser.add_argument("--archive-sha", required=True)
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    try:
        require((args.mode != "plan") == args.execute,
                "EXPLICIT_CUTOVER_EXECUTE_REQUIRED")
        kwargs = dict(
            release_sha=args.release_sha, bundle=args.bundle_dir,
            image=args.image, archive_sha=args.archive_sha,
            candidate_sha=args.candidate_sha)
        result = (admission.plan(**kwargs) if args.mode == "plan"
                  else cutover(**kwargs) if args.mode == "cutover"
                  else restore_authorized(
                      **kwargs, after_success=args.mode == "rollback"))
    except Exception as exc:
        reason = str(exc) if isinstance(exc, TransactionDenied) else (
            str(exc) if isinstance(exc, admission.PairDenied)
            else "ATTESTATION_OR_TRANSACTION_UNAVAILABLE")
        print(json.dumps({"status": "REFUSED", "reason": reason},
                         sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
