"""H-24/#191: owner-gated, UID-scoped Google-only network guard.

No OAuth, Google Search Console calls or GSC service/timer activation.
The root-only installer only affects its dedicated nft table and two
namespaced systemd files; unexpected existing state is refused.
"""
from __future__ import annotations

import argparse
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import socket
import stat
import subprocess
import sys

if __package__:
    from .h191_google_egress_candidate import (
        CandidateError, evaluate, public_preview_evidence,
    )
else:
    from h191_google_egress_candidate import (
        CandidateError, evaluate, public_preview_evidence,
    )

HOST = "vps1777112993"
USER = "hermes-gsc"
TABLE = "hermes_gsc_egress"
SCHEMA = "hermes-h191-google-egress-installed-v1"
UNIT = "hermes-gsc-readonly.service"
TIMER = "hermes-gsc-readonly.timer"
GUARD = "hermes-gsc-egress-guard.service"
DEPLOY_SHA = Path("/var/lib/hermes-main-deploy/last-success.sha")
POLICY = Path("/etc/hermes-gsc/google-egress-policy.json")
DROPIN = Path("/etc/systemd/system/hermes-gsc-readonly.service.d/90-google-only.conf")
GUARD_FILE = Path("/etc/systemd/system/hermes-gsc-egress-guard.service")
LOCK = Path("/run/lock/hermes-h191-google-egress.lock")
SOURCE = Path("/opt/hermes-agent-owner/scripts/h191_gsc_egress_guard.py")
MAX_POLICY_BYTES = 16_384
SYSTEMD_TIMEOUT = 8


class GuardError(Exception):
    """Safe, secret-free failure code."""


def _command(parts: list[str], *, stdin: str | None = None, timeout: int = 12):
    try:
        return subprocess.run(
            parts, input=stdin, text=True, capture_output=True,
            check=False, timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise GuardError("host_tool_unavailable") from None


def _run(parts: list[str], *, stdin: str | None = None, timeout: int = 12) -> str:
    result = _command(parts, stdin=stdin, timeout=timeout)
    if result.returncode:
        raise GuardError("host_command_failed")
    return result.stdout.strip()


def _sha() -> str:
    try:
        value = DEPLOY_SHA.read_text(encoding="ascii").strip()
    except OSError:
        raise GuardError("deployed_release_unavailable") from None
    if not re.fullmatch(r"[a-f0-9]{40}", value):
        raise GuardError("deployed_release_invalid")
    return value


def _identity() -> tuple[int, int]:
    if os.geteuid() != 0:
        raise GuardError("root_required")
    if socket.gethostname().split(".")[0] != HOST:
        raise GuardError("wrong_host")
    try:
        user = pwd.getpwnam(USER)
    except KeyError:
        raise GuardError("service_identity_missing") from None
    if user.pw_uid <= 0 or user.pw_gid <= 0:
        raise GuardError("service_identity_invalid")
    source = Path(__file__).resolve()
    current = Path("/opt/hermes-agent-owner/releases") / (
        "main-" + _sha()
    ) / "scripts/h191_gsc_egress_guard.py"
    if not current.is_file() or source not in (current, SOURCE.resolve()):
        raise GuardError("source_not_current_release")
    try:
        if SOURCE.is_symlink() or SOURCE.read_bytes() != current.read_bytes():
            raise GuardError("active_source_not_current_release")
        for p in (current, SOURCE):
            if p.stat().st_uid != 0 or p.is_symlink():
                raise GuardError("source_not_root_owned")
    except OSError:
        raise GuardError("source_verification_unavailable") from None
    return user.pw_uid, user.pw_gid


def _key_metadata(uid: int, gid: int) -> None:
    # Never open or parse credential bytes, even in diagnostics.
    path = Path("/etc/hermes-gsc/service-account.json")
    try:
        m = path.lstat()
    except OSError:
        raise GuardError("credential_metadata_missing") from None
    if (not stat.S_ISREG(m.st_mode) or m.st_uid != uid
            or m.st_gid != gid or stat.S_IMODE(m.st_mode) != 0o400
            or m.st_nlink != 1 or not 64 <= m.st_size <= 32_768):
        raise GuardError("credential_metadata_unsafe")


def _unit_state(install: bool) -> None:
    for name in (UNIT, TIMER):
        if _run(["systemctl", "show", "-P", "ActiveState", name],
                timeout=SYSTEMD_TIMEOUT) != "inactive":
            raise GuardError("gsc_unit_not_inactive")
        if install and _run(["systemctl", "is-enabled", name],
                            timeout=SYSTEMD_TIMEOUT) != "disabled":
            raise GuardError("gsc_unit_not_disabled")


def _pin_addresses(pins: tuple[str, ...]) -> tuple[list[str], list[str]]:
    if not isinstance(pins, tuple) or not 1 <= len(pins) <= 32:
        raise GuardError("pins_invalid")
    v4: set[str] = set()
    v6: set[str] = set()
    for pin in pins:
        try:
            value = ipaddress.ip_interface(pin)
        except (ValueError, TypeError):
            raise GuardError("pin_invalid") from None
        if (not value.ip.is_global or value.network.prefixlen !=
                (32 if value.version == 4 else 128)):
            raise GuardError("pin_not_exact_public_host")
        (v4 if value.version == 4 else v6).add(str(value.ip))
    if len(v4) + len(v6) != len(pins):
        raise GuardError("duplicate_pin")
    return sorted(v4), sorted(v6)


def nft_program(pins: tuple[str, ...], uid: int) -> str:
    """Create a new isolated table, then allow exact targets, otherwise drop UID."""
    v4, v6 = _pin_addresses(pins)
    if not isinstance(uid, int) or isinstance(uid, bool) or uid < 1:
        raise GuardError("uid_invalid")
    lines = [f"create table inet {TABLE}"]
    if v4:
        lines.append(
            f"add set inet {TABLE} google_v4 {{ type ipv4_addr; "
            f"elements = {{ {', '.join(v4)} }}; }}"
        )
    if v6:
        lines.append(
            f"add set inet {TABLE} google_v6 {{ type ipv6_addr; "
            f"elements = {{ {', '.join(v6)} }}; }}"
        )
    lines.extend([
        f"add chain inet {TABLE} outbound {{ type filter hook output "
        "priority -110; policy accept; }",
        f"add rule inet {TABLE} outbound meta skuid {uid} "
        "ip daddr 127.0.0.53 udp dport 53 accept",
        f"add rule inet {TABLE} outbound meta skuid {uid} "
        "ip daddr 127.0.0.53 tcp dport 53 accept",
    ])
    if v4:
        lines.append(f"add rule inet {TABLE} outbound meta skuid {uid} "
                     "ip daddr @google_v4 tcp dport 443 accept")
    if v6:
        lines.append(f"add rule inet {TABLE} outbound meta skuid {uid} "
                     "ip6 daddr @google_v6 tcp dport 443 accept")
    lines.append(f"add rule inet {TABLE} outbound meta skuid {uid} drop")
    return "\n".join(lines) + "\n"


def _match(proto: str, key: str, value: str | int) -> dict:
    left = ({"meta": {"key": key}} if proto == "meta"
            else {"payload": {"protocol": proto, "field": key}})
    return {"match": {"op": "==", "left": left, "right": value}}


def nft_is_exact(payload: object, pins: tuple[str, ...], uid: int) -> bool:
    """Reject unknown tables, chains, rules, destinations or privileges."""
    if type(payload) is not dict or type(payload.get("nftables")) is not list:
        return False
    v4, v6 = _pin_addresses(pins)
    nodes = []
    for item in payload["nftables"]:
        if type(item) is not dict or len(item) != 1:
            return False
        kind, value = next(iter(item.items()))
        if kind == "metainfo":
            continue
        if kind not in ("table", "set", "chain", "rule") or type(value) is not dict:
            return False
        nodes.append((kind, value))
    tables = [x for k, x in nodes if k == "table"]
    sets = [x for k, x in nodes if k == "set"]
    chains = [x for k, x in nodes if k == "chain"]
    rules = [x for k, x in nodes if k == "rule"]
    if (len(tables) != 1 or len(chains) != 1
            or len(sets) != bool(v4) + bool(v6)
            or len(rules) != 3 + bool(v4) + bool(v6)):
        return False
    if tables[0].get("family") != "inet" or tables[0].get("name") != TABLE:
        return False
    chain = chains[0]
    if (chain.get("family"), chain.get("table"), chain.get("name"),
            chain.get("hook"), chain.get("prio"), chain.get("policy"),
            chain.get("type")) != (
            "inet", TABLE, "outbound", "output", -110, "accept", "filter"):
        return False
    expected_sets = {}
    if v4:
        expected_sets["google_v4"] = ("ipv4_addr", v4)
    if v6:
        expected_sets["google_v6"] = ("ipv6_addr", v6)
    for item in sets:
        name = item.get("name")
        if name not in expected_sets or item.get("family") != "inet" or item.get("table") != TABLE:
            return False
        kind, expected_ips = expected_sets.pop(name)
        elems = item.get("elem")
        if (item.get("type") != kind or type(elems) is not list
                or len(elems) != len(expected_ips)
                or set(elems) != set(expected_ips)):
            return False
        if item.get("flags") or item.get("timeout") or item.get("policy"):
            return False
    if expected_sets:
        return False
    uid_match = _match("meta", "skuid", uid)
    expected_rules = [
        [uid_match, _match("ip", "daddr", "127.0.0.53"),
         _match("udp", "dport", 53), {"accept": None}],
        [uid_match, _match("ip", "daddr", "127.0.0.53"),
         _match("tcp", "dport", 53), {"accept": None}],
    ]
    if v4:
        expected_rules.append([uid_match, _match("ip", "daddr", "@google_v4"),
                               _match("tcp", "dport", 443), {"accept": None}])
    if v6:
        expected_rules.append([uid_match, _match("ip6", "daddr", "@google_v6"),
                               _match("tcp", "dport", 443), {"accept": None}])
    expected_rules.append([uid_match, {"drop": None}])
    if any(r.get("family") != "inet" or r.get("table") != TABLE
           or r.get("chain") != "outbound" for r in rules):
        return False
    return [r.get("expr") for r in rules] == expected_rules


def _nft_state(pins: tuple[str, ...], uid: int) -> str:
    result = _command(["nft", "-j", "list", "table", "inet", TABLE])
    if result.returncode:
        tables = _run(["nft", "list", "tables"])
        if f"table inet {TABLE}" in tables.splitlines():
            raise GuardError("nft_inspection_failed")
        return "MISSING"
    try:
        value = json.loads(result.stdout)
    except ValueError:
        raise GuardError("nft_json_unreadable") from None
    if not nft_is_exact(value, pins, uid):
        raise GuardError("nft_existing_table_drift")
    return "EXACT"


def _nft_create(pins: tuple[str, ...], uid: int) -> None:
    if _nft_state(pins, uid) != "MISSING":
        raise GuardError("nft_table_already_present")
    program = nft_program(pins, uid)
    _run(["nft", "-c", "-f", "-"], stdin=program)
    _run(["nft", "-f", "-"], stdin=program)
    if _nft_state(pins, uid) != "EXACT":
        raise GuardError("nft_postinstall_mismatch")


def dropin_text(pins: tuple[str, ...]) -> str:
    _pin_addresses(pins)
    return (
        "# H191 guarded Google-only egress. Requires root nft guard before GSC.\n"
        "[Unit]\n"
        f"Requires={GUARD}\n"
        f"After={GUARD}\n\n"
        "[Service]\n"
        "PrivateNetwork=no\n"
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n"
        "IPAddressAllow=localhost\n"
        + "".join(f"IPAddressAllow={pin}\n" for pin in pins)
    )


def guard_unit_text() -> str:
    return (
        "[Unit]\n"
        "Description=Hermes H191 UID-only nftables Google egress guard\n"
        f"Before={UNIT}\n"
        "Wants=network-online.target\n"
        "After=network-online.target\n\n"
        "[Service]\n"
        "Type=oneshot\n"
        "ExecStart=/usr/bin/python3 -I -B "
        "/opt/hermes-agent-owner/scripts/h191_gsc_egress_guard.py --ensure\n"
        "RemainAfterExit=no\n"
        "NoNewPrivileges=yes\n"
        "PrivateNetwork=no\n"
        "ProtectSystem=strict\n"
        "ProtectHome=yes\n"
        "PrivateTmp=yes\n"
        "PrivateDevices=yes\n"
        "ProtectKernelTunables=yes\n"
        "ProtectKernelModules=yes\n"
        "ProtectControlGroups=yes\n"
        "CapabilityBoundingSet=CAP_NET_ADMIN\n"
        "AmbientCapabilities=\n"
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK\n"
        "MemoryMax=96M\n"
        "TasksMax=20\n"
        "RuntimeMaxSec=35\n"
        "TimeoutStartSec=40s\n"
    )


def _store_text(path: Path, data: str, mode: int) -> None:
    # No overwrite (including symlinks). Root-only directories checked separately.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError:
        raise GuardError("policy_file_install_denied") from None


def _read_root_file(path: Path, mode: int, maxbytes: int) -> str:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or stat.S_IMODE(info.st_mode) != mode
                    or not 1 <= info.st_size <= maxbytes or info.st_nlink != 1):
                raise GuardError("guard_file_unsafe")
            raw = stream.read(maxbytes + 1)
        return raw.decode("utf-8", "strict")
    except GuardError:
        raise
    except (OSError, UnicodeError):
        raise GuardError("guard_file_unavailable") from None


def _pins_record(pins: tuple[str, ...], uid: int, gid: int) -> str:
    return json.dumps({
        "schema": SCHEMA, "host": HOST, "installer_release": _sha(),
        "uid": uid, "gid": gid, "pins": list(pins),
    }, sort_keys=True, separators=(",", ":")) + "\n"


def _read_record(uid: int, gid: int) -> tuple[str, ...]:
    raw = _read_root_file(POLICY, 0o600, MAX_POLICY_BYTES)
    try:
        obj = json.loads(raw)
    except ValueError:
        raise GuardError("guard_record_invalid") from None
    if type(obj) is not dict or set(obj) != {
        "schema", "host", "installer_release", "uid", "gid", "pins",
    } or obj["schema"] != SCHEMA or obj["host"] != HOST or (
        type(obj["uid"]) is not int or obj["uid"] != uid
    ) or (type(obj["gid"]) is not int or obj["gid"] != gid):
        raise GuardError("guard_record_identity_mismatch")
    if not re.fullmatch(r"[a-f0-9]{40}", str(obj["installer_release"])):
        raise GuardError("guard_record_release_invalid")
    if type(obj["pins"]) is not list or not all(type(x) is str for x in obj["pins"]):
        raise GuardError("guard_record_pins_invalid")
    pins = tuple(obj["pins"])
    _pin_addresses(pins)
    return pins


def _verify_files(pins: tuple[str, ...]) -> None:
    if _read_root_file(DROPIN, 0o644, 8192) != dropin_text(pins):
        raise GuardError("systemd_dropin_drift")
    if _read_root_file(GUARD_FILE, 0o644, 8192) != guard_unit_text():
        raise GuardError("guard_unit_drift")


def _current_pins(uid: int) -> tuple[str, ...]:
    try:
        evidence = public_preview_evidence()
        return evaluate(evidence, uid=uid)
    except CandidateError:
        raise GuardError("provider_dns_evidence_unverified") from None


def _lock():
    try:
        descriptor = os.open(
            LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600,
        )
        meta = os.fstat(descriptor)
        if meta.st_uid != 0 or not stat.S_ISREG(meta.st_mode) or stat.S_IMODE(meta.st_mode) != 0o600:
            raise GuardError("lock_unsafe")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return descriptor
    except (OSError, BlockingIOError):
        raise GuardError("lock_unavailable") from None


def install(uid: int, gid: int) -> None:
    _unit_state(install=True)
    _key_metadata(uid, gid)
    if (POLICY.exists() or POLICY.is_symlink() or
            DROPIN.exists() or DROPIN.is_symlink() or
            GUARD_FILE.exists() or GUARD_FILE.is_symlink()):
        raise GuardError("preexisting_policy_files")
    if _run(["systemctl", "show", "-P", "DropInPaths", UNIT]):
        raise GuardError("unreviewed_existing_service_dropins")
    pins = _current_pins(uid)
    _nft_create(pins, uid)  # Drop all other hermes-gsc traffic BEFORE widening unit.
    folder = DROPIN.parent
    if folder.is_symlink():
        raise GuardError("dropin_directory_symlink")
    folder.mkdir(mode=0o755, exist_ok=True)
    if folder.stat().st_uid != 0 or stat.S_IMODE(folder.stat().st_mode) != 0o755:
        raise GuardError("dropin_directory_unsafe")
    _store_text(POLICY, _pins_record(pins, uid, gid), 0o600)
    _store_text(GUARD_FILE, guard_unit_text(), 0o644)
    _store_text(DROPIN, dropin_text(pins), 0o644)
    _run(["systemctl", "daemon-reload"], timeout=18)
    _verify_files(pins)
    if _nft_state(pins, uid) != "EXACT":
        raise GuardError("guard_postinstall_invalid")
    _unit_state(install=True)
    if _run(["systemctl", "show", "-P", "PrivateNetwork", UNIT]) != "no":
        raise GuardError("network_namespace_override_invalid")


def check(uid: int, gid: int, *, ensure: bool) -> None:
    _key_metadata(uid, gid)
    pins = _read_record(uid, gid)
    _verify_files(pins)
    if ensure:
        # Old pins are safe only when currently observed DNS is a subset.
        current = set(_current_pins(uid))
        if not current.issubset(pins):
            raise GuardError("google_ip_rotation_requires_review")
        if _nft_state(pins, uid) == "MISSING":
            _nft_create(pins, uid)  # Reboot: recreate guard before starting GSC.
    if _nft_state(pins, uid) != "EXACT":
        raise GuardError("network_guard_not_enforced")



def rollback(uid: int, gid: int) -> None:
    """Owner-only exact-state rollback. Restore DENY_ALL before deleting nft."""
    _unit_state(install=True)
    pins = _read_record(uid, gid)
    _verify_files(pins)
    state = _nft_state(pins, uid)
    if state not in ("EXACT", "MISSING"):
        raise GuardError("nft_rollback_state_untrusted")
    # A symlink or unexpected file cannot be removed as if owned by this tool.
    for path in (DROPIN, GUARD_FILE, POLICY):
        if not path.is_file() or path.is_symlink():
            raise GuardError("rollback_file_untrusted")
    # Keep restrictive nft OUTPUT chain while restoring GSC systemd DENY_ALL.
    DROPIN.unlink()
    GUARD_FILE.unlink()
    POLICY.unlink()
    _run(["systemctl", "daemon-reload"], timeout=18)
    if _run(["systemctl", "show", "-P", "PrivateNetwork", UNIT]) != "yes":
        raise GuardError("rollback_denied_network_state_unverified")
    families = _run(["systemctl", "show", "-P", "RestrictAddressFamilies", UNIT])
    if "AF_UNIX" not in families or "AF_INET" in families:
        raise GuardError("rollback_address_family_unverified")
    _unit_state(install=True)
    if state == "EXACT":
        _run(["nft", "delete", "table", "inet", TABLE])
        if _nft_state(pins, uid) != "MISSING":
            raise GuardError("rollback_nft_table_still_present")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    a = parser.add_mutually_exclusive_group(required=True)
    a.add_argument("--plan", action="store_true")
    a.add_argument("--install", action="store_true")
    a.add_argument("--check", action="store_true")
    a.add_argument("--ensure", action="store_true")
    a.add_argument("--rollback", action="store_true")
    parser.add_argument("--confirm-owner-network-change", action="store_true")
    args = parser.parse_args(argv)
    try:
        uid, gid = _identity()
        if args.plan:
            if args.confirm_owner_network_change:
                raise GuardError("unexpected_owner_confirmation_for_plan")
            _unit_state(install=True)
            _key_metadata(uid, gid)
            pins = _current_pins(uid)
            if _nft_state(pins, uid) != "MISSING":
                raise GuardError("preexisting_guard_table")
            _run(["nft", "-c", "-f", "-"], stdin=nft_program(pins, uid))
            print("H191_GUARD_PLAN=PASS_NO_MUTATION")
            return 0
        if args.confirm_owner_network_change != (args.install or args.rollback):
            raise GuardError("owner_approval_required_or_unexpected")
        fd = _lock()
        try:
            if args.install:
                install(uid, gid)
                print("H191_GUARD_INSTALLED=PASS")
                print("H191_GSC_SERVICE=INACTIVE_DISABLED")
                print("H191_GSC_TIMER=INACTIVE_DISABLED")
            elif args.rollback:
                rollback(uid, gid)
                print("H191_GUARD_ROLLBACK=PASS")
            else:
                check(uid, gid, ensure=args.ensure)
                print("H191_GUARD_" + ("ENSURE" if args.ensure else "CHECK") + "=PASS")
            print("H191_GOOGLE_OAUTH=NOT_RUN")
            return 0
        finally:
            os.close(fd)
    except GuardError as exc:
        print("H191_GUARD=HOLD REASON=" + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
