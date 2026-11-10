"""H454 read-only Linux original-host inventory for a dedicated forced SSH key.

No host file contents, source scans, shell, commands, network, users or
service mutations. Not a native agent, install permit or root discovery.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import pwd
import stat
import sys

SCHEMA = "h454-linux-native-inventory-v1"
TARGETS = frozenset(("hermes-vps", "yfc-vps"))
STATE = frozenset(("PRESENT", "ABSENT", "BLOCKED", "UNVERIFIED"))
FIELDS = frozenset(("schema", "target", "arch", "systemd", "service_user",
                    "service_unit", "release_directory", "owner_roots",
                    "native_host_pass", "host_changes"))
MAX_BYTES = 4096


class InventoryDenied(ValueError):
    pass


def _unique(items):
    out = {}
    for key, value in items:
        if key in out:
            raise InventoryDenied("h454_inventory_denied")
        out[key] = value
    return out


def _path_status(path: Path, *, directory: bool) -> str:
    try:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            return "BLOCKED"
        if directory and not stat.S_ISDIR(info.st_mode):
            return "BLOCKED"
        if not directory and not stat.S_ISREG(info.st_mode):
            return "BLOCKED"
        return "PRESENT"
    except FileNotFoundError:
        return "ABSENT"
    except OSError:
        return "UNVERIFIED"


def _identity() -> str:
    try:
        u = pwd.getpwnam("hermes-commander-native")
        if (u.pw_uid == 0 or u.pw_gid == 0
            or u.pw_shell not in ("/usr/sbin/nologin", "/sbin/nologin")):
            return "BLOCKED"
        return "PRESENT"
    except KeyError:
        return "ABSENT"
    except OSError:
        return "UNVERIFIED"


def inventory(target: str) -> dict[str, object]:
    if (sys.platform != "linux" or target not in TARGETS
        or os.geteuid() == 0 or os.getegid() == 0
        or os.environ.get("SSH_ORIGINAL_COMMAND") != "inventory"):
        raise InventoryDenied("h454_inventory_denied")
    arch = {"x86_64": "x64", "aarch64": "arm64"}.get(platform.machine().lower())
    if arch is None:
        raise InventoryDenied("h454_inventory_denied")
    return {
        "schema": SCHEMA, "target": target, "arch": arch,
        "systemd": "PRESENT" if Path("/run/systemd/system").is_dir() else "ABSENT",
        "service_user": _identity(),
        "service_unit": _path_status(
            Path("/etc/systemd/system/hermes-commander-native-preflight.service"),
            directory=False),
        "release_directory": _path_status(
            Path("/opt/hermes-commander-native/releases"), directory=True),
        "owner_roots": "UNVERIFIED",  # no guessed Docker/host paths
        "native_host_pass": False, "host_changes": False,
    }


def verify_report(raw: bytes, *, expected_target: str) -> dict[str, object]:
    try:
        if (type(raw) is not bytes or not 0 < len(raw) <= MAX_BYTES
            or expected_target not in TARGETS):
            raise InventoryDenied("h454_inventory_denied")
        data = json.loads(
            raw.decode("ascii"), object_pairs_hook=_unique,
            parse_constant=lambda _v: (_ for _ in ()).throw(ValueError()),
        )
        if (type(data) is not dict or set(data) != FIELDS
            or data["schema"] != SCHEMA or data["target"] != expected_target
            or data["arch"] not in ("x64", "arm64")
            or data["owner_roots"] != "UNVERIFIED"
            or data["native_host_pass"] is not False
            or data["host_changes"] is not False):
            raise InventoryDenied("h454_inventory_denied")
        for name in ("systemd", "service_user", "service_unit", "release_directory"):
            if type(data[name]) is not str or data[name] not in STATE:
                raise InventoryDenied("h454_inventory_denied")
        canonical = json.dumps(
            data, sort_keys=True, separators=(",", ":")
        ).encode("ascii")
        # The forced inventory CLI emits one trailing LF via print().
        # Reject multiple lines, spaces, or any other noncanonical payload.
        if raw not in (canonical, canonical + b"\n"):
            raise InventoryDenied("h454_inventory_denied")
        return data
    except Exception:
        raise InventoryDenied("h454_inventory_denied") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="H454 read-only original-host inventory")
    parser.add_argument("--target", choices=sorted(TARGETS), required=True)
    parser.add_argument("--verify-stdin", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = (verify_report(sys.stdin.buffer.read(MAX_BYTES + 1),
                                expected_target=args.target)
                  if args.verify_stdin else inventory(args.target))
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except Exception:
        print('{"status":"HOLD","reason":"H454_INVENTORY_DENIED"}')
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
