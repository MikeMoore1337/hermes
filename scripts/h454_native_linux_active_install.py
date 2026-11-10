"""Hermes #454 - root-console installation of a verified DISABLED Linux WSS unit.

This stage ONLY registers an exactly reviewed, root-owned systemd source
unit. It never starts, enables, pairs, unpauses or modifies original projects.
Existing independently verified *disabled preflight* source release + receipt
are required; any active/foreign unit, changed byte or unsafe path refuses.
Owner approval is an interactive root TTY with exact SHA and unit digest.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from typing import Callable

from scripts.h454_native_linux_install_off import (
    DisabledPlan, DisabledInstallDenied, InstallPaths, plan_bytes,
    _directory, _fixed_paths, _validate_existing, _write_new,
    _verify_service_user, _reload_daemon,
)
from scripts.h454_native_linux_active_unit import (
    UNIT_NAME, render_active_unit, LinuxActiveUnitDenied,
)
from scripts.h454_native_readonly_bundle import (
    MAX_ARCHIVE_SIZE, MAX_RECEIPT_SIZE, _read_private_artifact,
)
from scripts.h454_native_install_preflight import _private_manifest

SCHEMA = "h454-native-linux-active-unit-install-v1"


class ActiveInstallDenied(ValueError):
    """Constant denial, no private manifest/host path/unit error text."""


def _deny():
    raise ActiveInstallDenied("native_active_unit_install_denied")


def _unit_receipt(plan: DisabledPlan, unit: bytes) -> bytes:
    return json.dumps({
        "schema": SCHEMA,
        "target": plan.target,
        "release_sha": plan.release_sha,
        "source_sha256": plan.bundle_sha256,
        "manifest_sha256": plan.manifest_sha256,
        "unit_sha256": hashlib.sha256(unit).hexdigest(),
        "state": "INSTALLED_DISABLED",
        "activated": False,
        "paired": False,
    },sort_keys=True,separators=(",",":")).encode("ascii")


def _paths(plan: DisabledPlan, paths: InstallPaths) -> tuple[Path, Path]:
    if type(plan) is not DisabledPlan or type(paths) is not InstallPaths:
        _deny()
    return (
        paths.units / UNIT_NAME,
        paths.receipts / (plan.target + "-" + plan.release_sha + "-active.json"),
    )


def _safe_to_write(plan: DisabledPlan, paths: InstallPaths,
                   *, owner_uid: int, ancestors: bool) -> None:
    try:
        if sys.platform != "linux":
            _deny()
        for folder in (paths.releases, paths.units, paths.receipts):
            _directory(folder, uid=owner_uid, ancestors=ancestors)
        _validate_existing(plan, paths)
    except Exception:
        raise ActiveInstallDenied("native_active_unit_install_denied") from None


def _exact_active_unit(plan: DisabledPlan, *, unit_text: str,
                       manifest: bytes, relay_ipv4: str, dns_ipv4: str) -> bytes:
    try:
        expected = render_active_unit(
            manifest, target=plan.target,
            release_sha=plan.release_sha,
            manifest_sha256=plan.manifest_sha256,
            relay_ipv4=relay_ipv4, dns_ipv4=dns_ipv4,
        )
        if type(unit_text) is not str or unit_text != expected:
            _deny()
        data = expected.encode("ascii")
        if (len(data) > 8192 or data.count(b"[Service]\n") != 1
            or data.count(b"[Install]\n") != 1):
            _deny()
        return data
    except Exception:
        raise ActiveInstallDenied("native_active_unit_install_denied") from None


def _disabled_unit(unit: str) -> bool:
    try:
        active = subprocess.run(
            ["/usr/bin/systemctl","is-active",unit],
            capture_output=True,timeout=8,check=False,
        )
        enabled = subprocess.run(
            ["/usr/bin/systemctl","is-enabled",unit],
            capture_output=True,timeout=8,check=False,
        )
        return (active.returncode == 3 and active.stdout.strip() == b"inactive"
                and enabled.returncode == 1
                and enabled.stdout.strip() == b"disabled")
    except Exception:
        return False


def install_disabled(
    plan: DisabledPlan, *,
    unit_text: str, manifest: bytes, relay_ipv4: str, dns_ipv4: str,
    paths: InstallPaths,
    reload_daemon: Callable[[], None],
    is_disabled: Callable[[str], bool],
    owner_uid: int, ancestors: bool,
) -> dict[str, object]:
    """Only exclusive writes for this exact NEW unit and private receipt."""
    try:
        _safe_to_write(plan, paths,owner_uid=owner_uid,ancestors=ancestors)
        unit_bytes = _exact_active_unit(
            plan, unit_text=unit_text, manifest=manifest,
            relay_ipv4=relay_ipv4, dns_ipv4=dns_ipv4,
        )
        unit, receipt = _paths(plan,paths)
        if (unit.exists() or unit.is_symlink()
            or receipt.exists() or receipt.is_symlink()):
            _deny()
        created_unit = False
        created_receipt = False
        try:
            _write_new(unit,unit_bytes,0o644)
            created_unit = True
            _write_new(receipt,_unit_receipt(plan,unit_bytes),0o600)
            created_receipt = True
            reload_daemon()
            if is_disabled(UNIT_NAME) is not True:
                _deny()
            return {
                "status":"NATIVE_ACTIVE_UNIT_INSTALLED_DISABLED",
                "target":plan.target,"release_sha":plan.release_sha,
                "unit":UNIT_NAME,"started":False,"enabled":False,
                "device_paired":False,"owner_host_e2e":False,
            }
        except Exception:
            if created_unit:
                unit.unlink(missing_ok=True)
            if created_receipt:
                receipt.unlink(missing_ok=True)
            if created_unit:
                try:
                    reload_daemon()
                except Exception:
                    pass
            _deny()
    except Exception:
        raise ActiveInstallDenied("native_active_unit_install_denied") from None


def rollback_disabled(
    plan: DisabledPlan, *, unit_text: str, manifest: bytes, relay_ipv4: str, dns_ipv4: str,
    paths: InstallPaths,
    reload_daemon: Callable[[], None],
    is_disabled: Callable[[str], bool],
    owner_uid: int, ancestors: bool,
) -> dict[str, object]:
    """Remove only the exact reviewed unit after independent disabled proof.

    The immutable original source bundle/receipt and preflight unit remain;
    this rollback NEVER touches the real host original project roots.
    """
    _safe_to_write(plan,paths,owner_uid=owner_uid,ancestors=ancestors)
    try:
        data = _exact_active_unit(
            plan, unit_text=unit_text, manifest=manifest,
            relay_ipv4=relay_ipv4, dns_ipv4=dns_ipv4,
        )
        unit,receipt = _paths(plan,paths)
        if (unit.is_symlink() or not unit.is_file()
            or receipt.is_symlink() or not receipt.is_file()
            or unit.stat().st_nlink != 1 or receipt.stat().st_nlink != 1
            or unit.read_bytes() != data
            or _read_private_artifact(receipt,4096) != _unit_receipt(plan,data)
            or is_disabled(UNIT_NAME) is not True):
            _deny()
        unit.unlink()
        reload_daemon()
        return {
            "status":"NATIVE_ACTIVE_UNIT_ROLLED_BACK",
            "target":plan.target,"release_sha":plan.release_sha,
            "unit_removed":True,"receipt_preserved":receipt.exists(),
            "source_preserved":True,"original_host_files_untouched":True,
        }
    except Exception:
        raise ActiveInstallDenied("native_active_unit_install_denied") from None


def _owner_tty_confirm(plan: DisabledPlan, action: str, unit: str):
    if (sys.platform != "linux" or os.geteuid() != 0
        or not sys.stdin.isatty() or not sys.stdout.isatty()
        or action not in ("INSTALL", "ROLLBACK")):
        _deny()
    required = (
        "H454 " + action + " DISABLED-NATIVE-UNIT " + plan.target
        + " " + plan.release_sha + " "
        + hashlib.sha256(unit.encode("ascii")).hexdigest()
    )
    try:
        with open("/dev/tty","r",encoding="ascii") as source, \
             open("/dev/tty","w",encoding="ascii") as sink:
            sink.write("Review exact disabled native unit action:\n" + required + "\n> ")
            sink.flush()
            if source.readline(256).strip() != required:
                _deny()
    except Exception:
        _deny()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="H454 owner-root disabled native unit")
    parser.add_argument("action",choices=("install-disabled","rollback-disabled"))
    parser.add_argument("--target",choices=("hermes-vps","yfc-vps"),required=True)
    parser.add_argument("--release-sha",required=True)
    parser.add_argument("--bundle-sha256",required=True)
    parser.add_argument("--manifest",type=Path,required=True)
    parser.add_argument("--bundle",type=Path,required=True)
    parser.add_argument("--receipt",type=Path,required=True)
    parser.add_argument("--relay-ipv4",required=True)
    parser.add_argument("--dns-ipv4",required=True)
    args = parser.parse_args(argv)
    try:
        plan = plan_bytes(
            target=args.target,release_sha=args.release_sha,
            bundle_sha256=args.bundle_sha256,
            manifest=_private_manifest(args.manifest),
            bundle=_read_private_artifact(args.bundle,MAX_ARCHIVE_SIZE),
            receipt=_read_private_artifact(args.receipt,MAX_RECEIPT_SIZE),
        )
        unit_text = render_active_unit(
            _private_manifest(args.manifest),
            target=args.target,release_sha=args.release_sha,
            manifest_sha256=plan.manifest_sha256,
            relay_ipv4=args.relay_ipv4,dns_ipv4=args.dns_ipv4,
        )
        _verify_service_user()
        _owner_tty_confirm(plan,"INSTALL" if args.action=="install-disabled"
                           else "ROLLBACK",unit_text)
        common=dict(plan=plan,unit_text=unit_text,
                    manifest=_private_manifest(args.manifest),
                    relay_ipv4=args.relay_ipv4,dns_ipv4=args.dns_ipv4,
                    paths=InstallPaths(),reload_daemon=_reload_daemon,
                    is_disabled=_disabled_unit,owner_uid=0,ancestors=True)
        result=(install_disabled(**common) if args.action=="install-disabled"
                else rollback_disabled(**common))
        print(json.dumps(result,sort_keys=True,separators=(",",":")))
        return 0
    except Exception:
        print('{"status":"HOLD","reason":"NATIVE_ACTIVE_UNIT_INSTALL_DENIED"}')
        return 2


if __name__=="__main__":
    raise SystemExit(main())
