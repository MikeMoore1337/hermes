#!/usr/bin/env python3
"""Validate read-only OCI probe evidence from disposable GitHub CI.

Presence of vulnerable system tools is observational, not a CVE waiver.
"""
import argparse
import json
from pathlib import Path


def review(probe, inspect):
    config = inspect["HostConfig"]
    if (probe["uid"] != 65534 or probe["gid"] != 65534 or
            int(probe["cap_eff_hex"], 16) != 0 or
            int(probe["cap_bnd_hex"], 16) != 0 or
            probe["no_new_privs"] != 1 or probe["seccomp_mode"] != 2 or
            probe["root_write_denied"] is not True or
            probe["block_devices"] != []):
        raise ValueError("kernel_scope_unconfirmed")
    if (config["NetworkMode"] != "none" or
            config["ReadonlyRootfs"] is not True or
            config["Privileged"] is not False or
            config["CapDrop"] != ["ALL"] or
            "no-new-privileges" not in config["SecurityOpt"] or
            config.get("Binds") or config.get("Mounts") or
            config.get("Devices") or config.get("PortBindings") or
            inspect["Config"]["User"] != "65534:65534" or
            inspect["State"]["ExitCode"] != 0):
        raise ValueError("docker_scope_unconfirmed")
    binaries = probe["observed_binaries"]
    expected = {"mount", "umount", "nsenter", "unshare", "fdisk",
                "sfdisk", "infocmp", "gzip", "perl", "setfacl", "getfacl"}
    if set(binaries) != expected or any(type(v) is not bool for v in binaries.values()):
        raise ValueError("incomplete_binary_inventory")
    return {
        "schema": "h15-oci-runtime-observation-v1",
        "image_id": inspect["Image"],
        "kernel_isolation": "CI_PASS",
        "observed_binaries": binaries,
        "systemd_homed_binary": probe["observed_systemd_homed_binary"],
        "perl_archive_tar_module": probe["observed_perl_archive_tar_module"],
        "exploitability_assessed": False,
        "release_approved": False,
        "public_mcp_enabled": False,
        "device_commands_enabled": False,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument("--inspect", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        if any(p.is_symlink() or p.stat().st_size > 500_000
               for p in (args.probe, args.inspect)):
            raise ValueError("oversized_or_linked")
        probe = json.loads(args.probe.read_text("utf-8"))
        inspect = json.loads(args.inspect.read_text("utf-8"))
        if len(inspect) != 1:
            raise ValueError("unexpected_inspect")
        report = review(probe, inspect[0])
        with args.out.open("x", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, sort_keys=True)
    except (ValueError, OSError, TypeError, KeyError):
        print("H15_RUNTIME_SCOPE=UNCONFIRMED")
        return 2
    print("H15_RUNTIME_SCOPE=CI_ISOLATED_NO_RELEASE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
