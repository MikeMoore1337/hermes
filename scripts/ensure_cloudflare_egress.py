"""Idempotent Hermes-only nft/Docker bridge guard. Never changes YFC firewall.

On mismatch: refuse to modify the existing network/rules. Creates missing
resources only if ownership and exact boundaries can be established.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from typing import Any

TABLE = "hermes_agent_isolation"
NETWORK = "hermes-agent-isolated"
BRIDGE = "br-hcf-agent"
SUBNET = "172.29.250.0/28"
GATEWAY = "172.29.250.1"
AGENT = "172.29.250.2"
PORT = 18573

NFT_RULESET = """add table inet hermes_agent_isolation
add chain inet hermes_agent_isolation input { type filter hook input priority -110; policy accept; }
add rule inet hermes_agent_isolation input iifname "br-hcf-agent" ip saddr 172.29.250.2 ip daddr 172.29.250.1 tcp dport 18573 accept
add rule inet hermes_agent_isolation input iifname "br-hcf-agent" drop
add chain inet hermes_agent_isolation forward { type filter hook forward priority -110; policy accept; }
add rule inet hermes_agent_isolation forward iifname "br-hcf-agent" drop
"""


class GuardError(Exception):
    """Controlled rejection message without identifiers or secret data."""


def process(args: list[str], *, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            args, input=stdin, text=True, capture_output=True, timeout=12, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GuardError("local_tool_unavailable") from exc


def match_eq(proto: str, field: str, value: str | int) -> dict[str, Any]:
    """Represent one exact nft match expression (not free-form substring)."""
    left: dict[str, Any]
    if proto == "meta":
        left = {"meta": {"key": field}}
    else:
        left = {"payload": {"protocol": proto, "field": field}}
    return {"match": {"op": "==", "left": left, "right": value}}


def rules_are_exact(payload: dict[str, Any]) -> bool:
    """Validate complete nft table, chains, hooks and exactly three rules."""
    rows = payload.get("nftables")
    if not isinstance(rows, list):
        return False
    items = [next(iter(x.items())) for x in rows if isinstance(x, dict) and
             set(x) not in ({"metainfo"},) and len(x) == 1]
    if len(items) != 6:
        return False
    tables = [v for kind, v in items if kind == "table"]
    chains = [v for kind, v in items if kind == "chain"]
    rules = [v for kind, v in items if kind == "rule"]
    if len(tables) != 1 or len(chains) != 2 or len(rules) != 3:
        return False
    if tables[0].get("family") != "inet" or tables[0].get("name") != TABLE:
        return False
    if {(c.get("name"), c.get("hook"), c.get("prio"), c.get("policy"), c.get("type"))
            for c in chains} != {
                ("input", "input", -110, "accept", "filter"),
                ("forward", "forward", -110, "accept", "filter"),
            }:
        return False
    if any(r.get("table") != TABLE or r.get("family") != "inet" for r in rules):
        return False
    input_accept = [
        match_eq("meta", "iifname", BRIDGE),
        match_eq("ip", "saddr", AGENT),
        match_eq("ip", "daddr", GATEWAY),
        match_eq("tcp", "dport", PORT),
        {"accept": None},
    ]
    input_deny = [match_eq("meta", "iifname", BRIDGE), {"drop": None}]
    actual = [(r.get("chain"), r.get("expr")) for r in rules]
    return actual == [
        ("input", input_accept),
        ("input", input_deny),
        ("forward", input_deny),
    ]


def network_is_exact(payload: list[dict[str, Any]]) -> bool:
    """Never accept an external/renamed Docker network under a familiar name."""
    if not isinstance(payload, list) or len(payload) != 1:
        return False
    net = payload[0]
    ipam = net.get("IPAM") or {}
    return (
        net.get("Name") == NETWORK
        and net.get("Driver") == "bridge"
        and net.get("Internal") is True
        and net.get("EnableIPv6") is False
        and (net.get("Options") or {}).get("com.docker.network.bridge.name") == BRIDGE
        and ipam.get("Config") == [{"Subnet": SUBNET, "Gateway": GATEWAY}]
        and net.get("Attachable") is False
        and net.get("Ingress") is False
    )


def get_nft() -> tuple[bool, bool]:
    response = process(["nft", "-j", "list", "table", "inet", TABLE])
    if response.returncode != 0:
        # Distinguish missing from unreadable/corrupt command failure.
        tables = process(["nft", "list", "tables"])
        if tables.returncode != 0:
            raise GuardError("nft_inspection_failed")
        if f"table inet {TABLE}" in tables.stdout:
            raise GuardError("nft_inspection_failed")
        return False, False
    try:
        return True, rules_are_exact(json.loads(response.stdout))
    except (ValueError, TypeError):
        return True, False


def get_network() -> tuple[bool, bool]:
    response = process(["docker", "network", "inspect", NETWORK])
    if response.returncode != 0:
        # Check daemon health rather than interpreting ANY failure as absence.
        if process(["docker", "info", "--format", "{{.ServerVersion}}"]).returncode != 0:
            raise GuardError("docker_unavailable")
        return False, False
    try:
        return True, network_is_exact(json.loads(response.stdout))
    except (ValueError, TypeError):
        return True, False


def ensure(*, mutate: bool) -> str:
    """Install missing nft before bridge creation; on drift, refuse ALL writes."""
    if os.geteuid() != 0:
        raise GuardError("root_required")
    nft_exists, nft_correct = get_nft()
    net_exists, net_correct = get_network()
    if (nft_exists and not nft_correct) or (net_exists and not net_correct):
        raise GuardError("existing_isolation_drift")
    if not mutate:
        if not nft_exists or not net_exists:
            raise GuardError("isolation_missing")
        return "verified"
    if not nft_exists:
        result = process(["nft", "-f", "-"], stdin=NFT_RULESET)
        if result.returncode != 0:
            raise GuardError("firewall_create_failed")
        nft_exists, nft_correct = get_nft()
        if not (nft_exists and nft_correct):
            raise GuardError("firewall_verification_failed")
    if not net_exists:
        # The internal bridge must never be created before the firewall exists.
        current = process(["ip", "-4", "route", "show", SUBNET])
        if current.returncode != 0 or current.stdout.strip():
            raise GuardError("private_subnet_collision")
        create = process([
            "docker", "network", "create", "--driver", "bridge", "--internal",
            "--subnet", SUBNET, "--gateway", GATEWAY,
            "--opt", f"com.docker.network.bridge.name={BRIDGE}", NETWORK
        ])
        if create.returncode != 0:
            raise GuardError("network_create_failed")
    final_net, good_net = get_network()
    final_nft, good_nft = get_nft()
    if not (final_net and good_net and final_nft and good_nft):
        raise GuardError("isolation_postcheck_failed")
    return "verified"


def main() -> int:
    arg = argparse.ArgumentParser()
    group = arg.add_mutually_exclusive_group(required=True)
    group.add_argument("--ensure", action="store_true")
    group.add_argument("--check", action="store_true")
    parsed = arg.parse_args()
    try:
        result = ensure(mutate=parsed.ensure)
    except GuardError as exc:
        print(json.dumps({"status": "rejected", "reason": str(exc)}))
        return 1
    print(json.dumps({"status": result, "changed": None}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
