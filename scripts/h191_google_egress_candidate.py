"""H-24/#191 Google-only egress *candidate*, not an installer or live gate.

Live preview fetches ONLY the two official, public Google IP-range documents
and performs DNS lookups for two hard-coded Google API hostnames. Never reads
credentials, sends OAuth, runs nft/systemctl or writes a file. No --apply mode.

The resulting policy is NOT authoritative until independently reviewed and
verified on the production host. It is intentionally insufficient to activate
the existing DENY_ALL GSC service.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

HOST = "vps1777112993"
GOOG_URL = "https://www.gstatic.com/ipranges/goog.json"
CLOUD_URL = "https://www.gstatic.com/ipranges/cloud.json"
TARGETS = ("oauth2.googleapis.com", "www.googleapis.com")
SCHEMA = "hermes-h191-google-egress-candidate-v1"
MAX_AGE_SECONDS = 900
MAX_PREFIXES = 4096
MAX_PER_HOST = 16
MAX_JSON_BYTES = 1_500_000
DNS_STUB = "127.0.0.53"
NFT_TABLE = "hermes_gsc_candidate"
# Default reported OS UID is an *input*. Owner must confirm it on VPS again.
MAX_UID = 2**32 - 2


class CandidateError(ValueError):
    """Only safe error codes, never raw DNS/provider data."""


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    out: dict[str, object] = {}
    for k, v in pairs:
        if k in out:
            raise CandidateError("duplicate_json_field")
        out[k] = v
    return out


def _no_json_constant(_value: str) -> None:
    raise CandidateError("nonstandard_json_constant")


def _decode(raw: bytes) -> dict:
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_JSON_BYTES:
        raise CandidateError("metadata_size_invalid")
    try:
        value = json.loads(
            raw.decode("utf-8", "strict"), object_pairs_hook=_unique_pairs,
            parse_constant=_no_json_constant,
        )
    except CandidateError:
        raise
    except (ValueError, UnicodeError, RecursionError):
        raise CandidateError("metadata_json_invalid") from None
    if type(value) is not dict:
        raise CandidateError("metadata_json_invalid")
    return value


def _networks(document: object, *, limit: int = MAX_PREFIXES) -> tuple:
    if type(document) is not dict or type(document.get("prefixes")) is not list:
        raise CandidateError("provider_ranges_invalid")
    rows = document["prefixes"]
    if not 1 <= len(rows) <= limit:
        raise CandidateError("provider_ranges_size_invalid")
    parsed = []
    for row in rows:
        if type(row) is not dict:
            raise CandidateError("provider_prefix_invalid")
        keys = ("ipv4Prefix", "ipv6Prefix")
        present = [key for key in keys if key in row]
        if len(present) != 1 or type(row[present[0]]) is not str:
            raise CandidateError("provider_prefix_invalid")
        try:
            block = ipaddress.ip_network(row[present[0]], strict=True)
        except ValueError:
            raise CandidateError("provider_prefix_invalid") from None
        if block.version != (4 if present[0] == "ipv4Prefix" else 6):
            raise CandidateError("provider_prefix_family_invalid")
        if block.prefixlen < (8 if block.version == 4 else 24):
            raise CandidateError("provider_prefix_too_broad")
        parsed.append(block)
    return tuple(parsed)


def _timestamp(text: object) -> datetime:
    if type(text) is not str or len(text) > 40:
        raise CandidateError("timestamp_invalid")
    try:
        point = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise CandidateError("timestamp_invalid") from None
    if point.tzinfo is None:
        raise CandidateError("timezone_required")
    return point.astimezone(timezone.utc)


def evaluate(evidence: object, *, uid: int, now: datetime | None = None) -> tuple[str, ...]:
    """Return only verified /32-/128 public host pins from fresh evidence."""
    if type(uid) is not int or not 1 <= uid <= MAX_UID:
        raise CandidateError("uid_invalid")
    if type(evidence) is not dict or set(evidence) != {
        "schema", "host", "captured_at", "sources", "goog",
        "cloud", "resolved", "dns_nameservers",
    }:
        raise CandidateError("evidence_shape_invalid")
    if evidence["schema"] != SCHEMA or evidence["host"] != HOST:
        raise CandidateError("evidence_identity_invalid")
    if evidence["sources"] != {"goog": GOOG_URL, "cloud": CLOUD_URL}:
        raise CandidateError("evidence_source_invalid")
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise CandidateError("timezone_required")
    delta = (current.astimezone(timezone.utc) - _timestamp(
        evidence["captured_at"]
    )).total_seconds()
    if not -120 <= delta <= MAX_AGE_SECONDS:
        raise CandidateError("evidence_expired")
    if evidence["dns_nameservers"] != [DNS_STUB]:
        raise CandidateError("dns_stub_not_verified")
    ranges_goog = _networks(evidence["goog"])
    ranges_cloud = _networks(evidence["cloud"])
    resolved = evidence["resolved"]
    if type(resolved) is not dict or set(resolved) != set(TARGETS):
        raise CandidateError("unexpected_google_hosts")
    pins: set[str] = set()
    for host in TARGETS:
        ips = resolved[host]
        if type(ips) is not list or not 1 <= len(ips) <= MAX_PER_HOST:
            raise CandidateError("dns_result_count_invalid")
        for value in ips:
            if type(value) is not str or len(value) > 45:
                raise CandidateError("dns_address_invalid")
            try:
                addr = ipaddress.ip_address(value)
            except ValueError:
                raise CandidateError("dns_address_invalid") from None
            if not addr.is_global:
                raise CandidateError("dns_address_not_public")
            if not any(addr in net for net in ranges_goog):
                raise CandidateError("dns_address_not_in_google_ranges")
            if any(addr in net for net in ranges_cloud):
                raise CandidateError("dns_address_in_cloud_customer_ranges")
            pins.add(f"{addr}/{32 if addr.version == 4 else 128}")
    if not pins or len(pins) > 2 * MAX_PER_HOST:
        raise CandidateError("dns_pins_invalid")
    return tuple(sorted(pins, key=lambda pin: (
        ipaddress.ip_interface(pin).version,
        int(ipaddress.ip_interface(pin).ip),
    )))


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _fetch_public_ranges(url: str) -> dict:
    if url not in (GOOG_URL, CLOUD_URL):
        raise CandidateError("unapproved_public_source")
    request = Request(url, headers={"Accept": "application/json",
                                    "User-Agent": "Hermes-H191-Public-Range-Preview/1"})
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    try:
        with opener.open(request, timeout=8) as response:
            if response.status != 200:
                raise CandidateError("provider_http_failed")
            body = response.read(MAX_JSON_BYTES + 1)
        return _decode(body)
    except CandidateError:
        raise
    except Exception:
        raise CandidateError("provider_metadata_unavailable") from None


def _dns_nameservers() -> list[str]:
    try:
        value = Path("/etc/resolv.conf").read_text(encoding="utf-8")
    except OSError:
        raise CandidateError("resolver_config_unavailable") from None
    rows = []
    for line in value.splitlines():
        parts = line.split("#", 1)[0].split()
        if len(parts) == 2 and parts[0] == "nameserver":
            rows.append(parts[1])
    return rows


def public_preview_evidence() -> dict:
    """Public GET and DNS only, no Google OAuth or GSC private resources."""
    if socket.gethostname().split(".")[0] != HOST:
        raise CandidateError("wrong_host")
    sources = {"goog": GOOG_URL, "cloud": CLOUD_URL}
    result: dict = {
        "schema": SCHEMA, "host": HOST,
        "sources": sources,
        "goog": _fetch_public_ranges(GOOG_URL),
        "cloud": _fetch_public_ranges(CLOUD_URL),
        "resolved": {},
        "dns_nameservers": _dns_nameservers(),
    }
    for host in TARGETS:
        try:
            rows = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        except OSError:
            raise CandidateError("dns_lookup_failed") from None
        result["resolved"][host] = sorted({row[4][0] for row in rows})
    result["captured_at"] = datetime.now(timezone.utc).isoformat()
    return result


def render_candidate(pins: tuple[str, ...], *, uid: int) -> str:
    """Print REVIEW-ONLY systemd/nft snippets; never apply either one."""
    if type(uid) is not int or not 1 <= uid <= MAX_UID:
        raise CandidateError("uid_invalid")
    networks = []
    for text in pins:
        try:
            interface = ipaddress.ip_interface(text)
        except ValueError:
            raise CandidateError("pin_invalid") from None
        if not interface.ip.is_global or interface.network.prefixlen != (
            32 if interface.version == 4 else 128
        ):
            raise CandidateError("pin_not_exact_public_host")
        networks.append(interface)
    if not 1 <= len(set(networks)) <= 2 * MAX_PER_HOST:
        raise CandidateError("pin_count_invalid")
    ipv4 = sorted({str(x.ip) for x in networks if x.version == 4})
    ipv6 = sorted({str(x.ip) for x in networks if x.version == 6})
    lines = [
        "H191_EGRESS_PLAN=CANDIDATE_ONLY",
        "H191_NETWORK_CHANGED=NO",
        "H191_SECRET_ACCESSED=NO",
        "H191_OAUTH_RUN=NO",
        "H191_TIMER_ENABLED=NO",
        "# SYSTEMD DROP-IN CANDIDATE - NOT INSTALLED",
        "# Requires a separately reviewed root-owned nft guard/persistence unit",
        "# and observed on-host negative tests before any live OAuth.",
        "[Unit]",
        "Requires=hermes-gsc-egress-guard.service",
        "After=hermes-gsc-egress-guard.service",
        "[Service]",
        "PrivateNetwork=no",
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
        "IPAddressAllow=localhost",
    ]
    lines.extend(f"IPAddressAllow={x}" for x in pins)
    lines.extend([
        "# NFTABLES CANDIDATE - NOT APPLIED",
        f"table inet {NFT_TABLE} {{",
    ])
    if ipv4:
        lines.append("    set google_v4 { type ipv4_addr; elements = { " +
                     ", ".join(ipv4) + " }; }")
    if ipv6:
        lines.append("    set google_v6 { type ipv6_addr; elements = { " +
                     ", ".join(ipv6) + " }; }")
    lines.extend([
        "    chain outbound {",
        "        type filter hook output priority -110; policy accept;",
        f"        meta skuid {uid} ip daddr {DNS_STUB} udp dport 53 accept",
        f"        meta skuid {uid} ip daddr {DNS_STUB} tcp dport 53 accept",
    ])
    if ipv4:
        lines.append(
            f"        meta skuid {uid} ip daddr @google_v4 tcp dport 443 accept"
        )
    if ipv6:
        lines.append(
            f"        meta skuid {uid} ip6 daddr @google_v6 tcp dport 443 accept"
        )
    lines.extend([
        f"        meta skuid {uid} drop",
        "    }",
        "}",
        "# NOT APPLICABLE AS-IS: missing independently verified nft guard,",
        "# runtime IP refresh, reboot persistence and negative network tests.",
    ])
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preview", action="store_true", required=True)
    parser.add_argument("--uid", type=int, required=True)
    args = parser.parse_args()
    try:
        candidate = public_preview_evidence()
        pins = evaluate(candidate, uid=args.uid)
        result = render_candidate(pins, uid=args.uid)
    except CandidateError as exc:
        print("H191_EGRESS_PLAN=HOLD REASON=" + str(exc))
        return 2
    print(result, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
