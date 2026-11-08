#!/usr/bin/env python3
"""H454 native3: read-only admission of the existing relay + WSS proxy pair.

This is NOT a cutover implementation. It does not load images, pair devices,
rotate credentials, write pin files, or change Docker containers. A separate
owner-authorized joint transaction must be reviewed before live activation.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re

from scripts import h15_brc_transactional_upgrade as legacy
from scripts import h15_brc_upgrade_preflight as candidate
from scripts import h454_stage1_pair_cutover as stage1

RELAY_CHECKPOINT = "hermes-brc-relay-h454-native3-v2-rollback"
PROXY_CHECKPOINT = "hermes-h454-wss-proxy-h454-native3-v2-rollback"
PAIR_PENDING = stage1.PIN_ROOT / "native3-pair.pending"
# A retained original-pin snapshot means a prior joint cutover occurred.
# Its presence is intentional incident/recovery evidence, not a free retry slot.
ORIGINAL_PINS = stage1.PIN_ROOT / "native3-original-pins.json"
HEX40 = re.compile(r"[0-9a-f]{40}\Z")


class PairDenied(ValueError):
    """No secrets, TLS content, or Docker inspection payload in this reason."""


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise PairDenied(reason)


def verify_installed_source(release_sha: str) -> None:
    """Run only the exactly installed source, never an unpinned module mirror."""
    require(isinstance(release_sha, str) and HEX40.fullmatch(release_sha),
            "INVALID_RELEASE_PIN")
    expected = Path("/opt/hermes-agent-owner/releases") / ("main-" + release_sha)
    require(Path(__file__).resolve().parents[1] == expected,
            "OPERATOR_SOURCE_NOT_INSTALLED")
    require(stage1.LIVE_SHA.read_text(encoding="ascii").strip() == release_sha,
            "INSTALLED_RELEASE_CHANGED")


def verify_pair(wss) -> tuple[dict, dict]:
    """Reuse the pinned WSS reconciler's strict pair, TLS and netns checks."""
    stage1.protected(stage1.PIN_ROOT, 0o700, directory=True)
    stage1.protected(stage1.PINS, 0o600)
    require(not stage1.PENDING.exists() and not stage1.PENDING.is_symlink()
            and not PAIR_PENDING.exists() and not PAIR_PENDING.is_symlink(),
            "PENDING_PAIR_RECOVERY_REQUIRED")
    with stage1.locked_pins() as raw:
        pins = wss._pins(raw)
        require(pins.get("relay_name") == legacy.NAME
                and pins.get("sidecar_name") == stage1.PROXY
                and pins.get("relay_image") == stage1.FORK_IMAGE
                and pins.get("sidecar_image") == stage1.LEGACY_IMAGE,
                "PAIR_IDENTITY_CHANGED")
        relay, proxy = wss._snapshot(
            pins, stage1.PIN_ROOT, Path(pins["tls_directory"])
        )
        wss._namespace(relay, proxy)
        fd = wss._directory(Path(pins["tls_directory"]))
        try:
            ca = wss._read_file(fd, "ca.crt", 0o444)
        finally:
            os.close(fd)
        wss._tls(pins, ca)
        require(relay.get("Id") == pins["relay_id"]
                and proxy.get("Id") == pins["sidecar_id"]
                and relay.get("Image") == stage1.FORK_IMAGE
                and proxy.get("Image") == stage1.LEGACY_IMAGE,
                "PAIR_IMAGE_OR_CONTAINER_CHANGED")
        require((relay.get("State") or {}).get("Running") is True
                and (proxy.get("State") or {}).get("Running") is True,
                "PAIR_NOT_RUNNING")
        require((proxy.get("HostConfig") or {}).get("NetworkMode")
                == "container:" + relay["Id"], "PAIR_NAMESPACE_CHANGED")
        require(candidate.registry_mount_source(relay)
                == str(candidate.PINNED_REGISTRY_SOURCE),
                "STAGE1_WORKSPACE_REGISTRY_MISSING")
    return relay, proxy


def require_no_previous_transaction() -> None:
    """Fail closed while the exact original pin evidence is retained.

    A successful rollback leaves this snapshot in place. Checking only live
    containers/checkpoint names would incorrectly claim a new cutover is ready.
    Re-arming is a distinct reviewed, owner-authorized recovery operation;
    the plan never removes, renames, reads or overwrites the snapshot.
    """
    # lstat never follows an attacker-controlled symlink into a remote or
    # otherwise inaccessible target. Only an absent directory entry is clean.
    try:
        ORIGINAL_PINS.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise PairDenied("ORIGINAL_PIN_STATE_UNVERIFIABLE") from exc
    raise PairDenied("PREVIOUS_TRANSACTION_NOT_CLEARED")


def check_free_checkpoints() -> None:
    """Verify absence from a *successful* Docker list, never optional inspect.

    The legacy optional Docker inspector conflates daemon/API failures with
    'not found'. That is unsuitable for selecting rollback checkpoint names.
    """
    for checkpoint in (RELAY_CHECKPOINT, PROXY_CHECKPOINT):
        visible = stage1.docker(
            "container", "ls", "--all",
            "--filter", "name=^/" + checkpoint + "$",
            "--format", "{{.Names}}",
        )
        require(visible == "", "ROLLBACK_CHECKPOINT_ALREADY_EXISTS")


def plan(*, release_sha: str, bundle: Path, image: str,
         archive_sha: str, candidate_sha: str) -> dict:
    """Fail-closed proof only: safe for the existing active owner pair."""
    require(os.geteuid() == 0, "ROOT_REQUIRED")
    verify_installed_source(release_sha)
    with legacy.lock():
        stage1.protected(legacy.BACKUPS, 0o700, directory=True)
        legacy.check_files()
        # Check persisted cutover evidence *before* expensive OCI attestation.
        # This is read-only and prevents false PASS after an owner rollback.
        require_no_previous_transaction()
        inspected = candidate.admit(bundle, image, archive_sha, candidate_sha)
        require(inspected.get("status") == "PREFLIGHT_PASS"
                and inspected.get("bundle_verified") is True
                and inspected.get("changes_performed") is False
                and inspected.get("deployment_approved") is False
                and inspected.get("current_image") == stage1.FORK_IMAGE,
                "CANDIDATE_OR_PREVIOUS_IMAGE_INVALID")
        wss = stage1.load_existing_wss()
        relay, proxy = verify_pair(wss)
        require(relay.get("Image") == inspected["current_image"],
                "CANDIDATE_PAIR_IMAGE_DRIFT")
        check_free_checkpoints()
        devices = legacy.devices()
        require(type(devices) is int and 1 <= devices <= 25,
                "OWNER_BASELINE_UNAVAILABLE")
        return {
            "status": "PAIR_PREFLIGHT_PASS_NO_MUTATIONS",
            "current_main_sha": release_sha,
            "candidate_source_sha": candidate_sha,
            "ci_config_image_id": image,
            "candidate_runtime_image_id": inspected["candidate_image"],
            "previous_relay_image": stage1.FORK_IMAGE,
            "previous_proxy_image": stage1.LEGACY_IMAGE,
            "wss_pinned_pair_valid": True,
            "registry_pinned": True,
            "rollback_slots_available": True,
            "baseline_devices": devices,
            "owner_approval": "NOT_CHECKED_NOT_GRANTED",
            "deployment_approved": False,
            "changes_performed": False,
        }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("mode", choices=("plan",))
    ap.add_argument("--release-sha", required=True)
    ap.add_argument("--bundle-dir", required=True, type=Path)
    ap.add_argument("--image", required=True)
    ap.add_argument("--archive-sha", required=True)
    ap.add_argument("--candidate-sha", required=True)
    args = ap.parse_args(argv)
    try:
        report = plan(
            release_sha=args.release_sha, bundle=args.bundle_dir,
            image=args.image, archive_sha=args.archive_sha,
            candidate_sha=args.candidate_sha,
        )
    except Exception as exc:
        # A pinned WSS utility can raise several classes with private payloads.
        # Only local allowlisted failure codes are ever returned to the caller.
        reason = (str(exc) if isinstance(exc, PairDenied)
                  else "ATTESTATION_OR_RUNTIME_UNAVAILABLE")
        print(json.dumps({"status": "REFUSED", "reason": reason},
                         sort_keys=True))
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
