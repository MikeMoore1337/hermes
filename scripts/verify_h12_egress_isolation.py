"""Immutable offline Docker IPv4/IPv6/metadata egress denial evidence.

Default NO_EXECUTION. Explicit --execute runs a pinned *already cached* image
with --network none, no mounts, no secrets, nonroot, all capabilities dropped.
It cannot prove a future selectively allowlisted network namespace policy.
"""
from __future__ import annotations

import argparse
import json

from .bounded_subprocess import BoundedProcessError, run_bounded
from .verify_v0222_immutable import IMAGE, image_identity

SCHEMA = "hermes-h12-network-none-os-negative-v2"
REQUIRED = frozenset({
    "nonroot", "no_effective_caps", "only_loopback_interface",
    "no_ipv4_default_route", "no_usable_ipv6_default_route",
    "metadata_ipv4_denied", "private_ipv4_denied",
    "documentation_ipv4_denied", "documentation_ipv6_denied",
})
PROBE = r"""
import errno
import json
import os
import socket
from pathlib import Path

def read(path):
    try:
        return Path(path).read_text(encoding="ascii")
    except (OSError, UnicodeError):
        return ""

def only_loopback():
    lines = read("/proc/net/dev").splitlines()[2:]
    names = {line.split(":", 1)[0].strip()
             for line in lines if ":" in line}
    return names == {"lo"}

def no_v4_default():
    try:
        rows = Path("/proc/net/route").read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError):
        return False
    if not rows or rows[0].split()[:2] != ["Iface", "Destination"]:
        return False
    for row in rows[1:]:
        cols = row.split()
        if (len(cols) < 8 or len(cols[1]) != 8
                or any(c not in "0123456789abcdefABCDEF" for c in cols[1])):
            return False
        if cols[1] == "00000000":
            return False
    return True

def no_usable_v6_default():
    try:
        rows = Path("/proc/net/ipv6_route").read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError):
        return False
    for row in rows:
        cols = row.split()
        if (len(cols) < 10 or len(cols[0]) != 32 or len(cols[1]) != 2
                or len(cols[8]) != 8
                or any(c not in "0123456789abcdefABCDEF"
                       for c in cols[0] + cols[1] + cols[8])):
            return False
        # Linux network-none often installs ::/0 with RTF_REJECT=0x200.
        # A REJECT route is NOT a usable default route. Any default
        # route without this explicit reject bit fails closed.
        if cols[0] == "0" * 32 and cols[1] == "00":
            if not int(cols[8], 16) & 0x200:
                return False
    return True

DENIED = {errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ENETDOWN,
          errno.EADDRNOTAVAIL, errno.EAFNOSUPPORT}
def socket_denied(family, address):
    sock = None
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(0.4)
        error = sock.connect_ex((address, 443))
        return error in DENIED
    except OSError as exc:
        return exc.errno in DENIED
    finally:
        if sock is not None:
            sock.close()

status = read("/proc/self/status")
caps = [line.split(":", 1)[1].strip()
        for line in status.splitlines() if line.startswith("CapEff:")]
checks = {
    "nonroot": os.geteuid() == 65534 and os.getegid() == 65534,
    "no_effective_caps": len(caps) == 1 and int(caps[0], 16) == 0,
    "only_loopback_interface": only_loopback(),
    "no_ipv4_default_route": no_v4_default(),
    "no_usable_ipv6_default_route": no_usable_v6_default(),
    "metadata_ipv4_denied": socket_denied(socket.AF_INET, "169.254.169.254"),
    "private_ipv4_denied": socket_denied(socket.AF_INET, "10.0.0.1"),
    "documentation_ipv4_denied": socket_denied(socket.AF_INET, "192.0.2.1"),
    "documentation_ipv6_denied": socket_denied(socket.AF_INET6, "2001:db8::1"),
}
print(json.dumps({"schema": "hermes-h12-network-none-os-negative-v2",
                  "checks": checks}, sort_keys=True))
"""


class EgressProbeDenied(ValueError):
    """Stable reason only; no host environment or child output in errors."""


def commands() -> tuple[list[str], list[str]]:
    inspect = ["docker", "image", "inspect", IMAGE, "--format",
               "{{json .RepoDigests}}|{{.Architecture}}"]
    run = [
        "docker", "run", "--rm", "--pull=never",
        "--platform", "linux/amd64", "--network", "none",
        "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--user", "65534:65534",
        "--cpus", "0.5", "--memory", "256m", "--memory-swap", "256m",
        "--pids-limit", "25", "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=16m",
        "--env", "HOME=/tmp",
        "--entrypoint", "/opt/hermes/.venv/bin/python",
        IMAGE, "-B", "-c", PROBE,
    ]
    return inspect, run


def evaluate(raw: bytes) -> dict[str, object]:
    def no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result = {}
        for name, value in pairs:
            if name in result:
                raise EgressProbeDenied("duplicate_field")
            result[name] = value
        return result

    try:
        packet = json.loads(raw, object_pairs_hook=no_duplicate_keys)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise EgressProbeDenied("malformed_probe") from None
    if (type(packet) is not dict or set(packet) != {"schema", "checks"}
            or packet["schema"] != SCHEMA or type(packet["checks"]) is not dict
            or set(packet["checks"]) != REQUIRED
            or any(type(value) is not bool for value in packet["checks"].values())):
        raise EgressProbeDenied("schema_or_checks_invalid")
    failed = sorted(k for k, v in packet["checks"].items() if v is not True)
    return {
        "status": "OFFLINE_NETWORK_NONE_OS_DENIALS_PASS" if not failed
                  else "OFFLINE_NETWORK_NONE_OS_DENIALS_FAIL",
        "checks_passed": len(REQUIRED) - len(failed),
        "checks_total": len(REQUIRED),
        "failed_checks": failed,
        "network_namespace_selective_allowlist_verified": False,
        "global_firewall_verified": False,
        "ipv4_ipv6_egress_for_network_none_verified": not failed,
        "real_public_https_verified": False,
        "metadata_http_invoked": False,
        "docker_image_unmodified": True,
        "resident_agent_allowed": False,
        "statejnik_live_network_allowed": False,
    }


def observe() -> dict[str, object]:
    inspect, run = commands()
    try:
        identity = run_bounded(inspect, timeout=12, stdout_limit=4096,
                               stderr_limit=2048)
        if not image_identity(identity.stdout):
            raise EgressProbeDenied("image_digest_mismatch")
        probe = run_bounded(run, timeout=30, stdout_limit=4096,
                            stderr_limit=4096)
        return evaluate(probe.stdout)
    except (OSError, BoundedProcessError, EgressProbeDenied):
        return {"status": "OFFLINE_EGRESS_EVIDENCE_UNAVAILABLE",
                "resident_agent_allowed": False,
                "statejnik_live_network_allowed": False}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    result = observe() if args.execute else {
        "status": "NOT_EXECUTED", "resident_agent_allowed": False,
        "statejnik_live_network_allowed": False}
    print(json.dumps(result, sort_keys=True))
    return 0 if not args.execute or result["status"] == "OFFLINE_NETWORK_NONE_OS_DENIALS_PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
