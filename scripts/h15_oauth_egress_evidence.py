"""Offline, fail-closed validation of candidate GitHub OAuth egress host addresses.

INPUT MUST BE REVIEWED: /meta ranges + actual DNS from a trusted, same-time
capture. Never reads credentials, performs DNS or HTTP, changes systemd, or
claims to prove cgroup enforcement.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path

SOURCE = "https://api.github.com/meta"
HOST_TO_RANGE = {"github.com": "web", "api.github.com": "api"}
MAX_AGE_SECONDS = 900
MAX_ADDRS_PER_HOST = 8


class EgressEvidenceError(ValueError):
    pass


def plan(evidence: dict, *, now: datetime | None = None) -> tuple[str, ...]:
    if not isinstance(evidence, dict) or set(evidence) != {
        "source", "captured_at", "ranges", "resolved"
    }:
        raise EgressEvidenceError("Evidence shape not trusted")
    if evidence["source"] != SOURCE:
        raise EgressEvidenceError("Unexpected evidence source")
    try:
        timestamp = datetime.fromisoformat(evidence["captured_at"].replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise EgressEvidenceError("Malformed capture timestamp") from exc
    if timestamp.tzinfo is None:
        raise EgressEvidenceError("Timezone required")
    reference = now if now is not None else datetime.now(timezone.utc)
    delta = (reference.astimezone(timezone.utc) - timestamp.astimezone(timezone.utc)).total_seconds()
    if delta < -120 or delta > MAX_AGE_SECONDS:
        raise EgressEvidenceError("Stale or future evidence")
    networks, resolved = evidence["ranges"], evidence["resolved"]
    if not isinstance(networks, dict) or not isinstance(resolved, dict):
        raise EgressEvidenceError("Invalid range/resolution containers")
    if set(resolved) != set(HOST_TO_RANGE):
        raise EgressEvidenceError("Missing/extra hostname in DNS")
    host_pins = set()
    for hostname, bucket in HOST_TO_RANGE.items():
        cidrs = networks.get(bucket)
        addresses = resolved[hostname]
        if not isinstance(cidrs, list) or not cidrs or len(cidrs) > 300 or not all(isinstance(c, str) for c in cidrs):
            raise EgressEvidenceError("Invalid metadata ranges")
        if not isinstance(addresses, list) or not 1 <= len(addresses) <= MAX_ADDRS_PER_HOST:
            raise EgressEvidenceError("Invalid DNS result count")
        try:
            networks_for_host = [ipaddress.ip_network(c, strict=True) for c in cidrs]
        except ValueError as exc:
            raise EgressEvidenceError("Invalid provider CIDR") from exc
        for provider_range in networks_for_host:
            if provider_range.version == 4 and provider_range.prefixlen < 8:
                raise EgressEvidenceError("Overbroad provider IPv4 range")
            if provider_range.version == 6 and provider_range.prefixlen < 32:
                raise EgressEvidenceError("Overbroad provider IPv6 range")
        for text in addresses:
            try:
                address = ipaddress.ip_address(text)
            except ValueError as exc:
                raise EgressEvidenceError("Invalid DNS address") from exc
            if not address.is_global:
                raise EgressEvidenceError("Non-global address")
            if not any(address in n for n in networks_for_host):
                raise EgressEvidenceError("DNS address not in published range")
            host_pins.add(str(address) + ("/32" if address.version == 4 else "/128"))
    if not host_pins or len(host_pins) > 2 * MAX_ADDRS_PER_HOST:
        raise EgressEvidenceError("Invalid pin collection")
    # Printing lines does NOT authorize changing any unit.
    return tuple("IPAddressAllow=" + x for x in sorted(host_pins))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path, help="Owner-reviewed local JSON evidence")
    args = parser.parse_args()
    if args.evidence.stat().st_size > 150_000:
        parser.error("Oversize evidence")
    try:
        result = plan(json.loads(args.evidence.read_text(encoding="utf-8")))
    except (EgressEvidenceError, ValueError) as exc:
        parser.error(str(exc))
    print("# CANDIDATE ONLY / OWNER REVIEW REQUIRED / NOT A NETWORK ENFORCEMENT PROOF")
    print("# Do not apply to live systemd; first prove isolation, denied hosts and TLS.")
    for entry in result:
        print(entry)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
