"""H-16 optional public HTTP reference probes, never part of required CI.

Only two source-controlled, owner-approved public references may be queried.
Requests are direct, pinned TLS, HEAD only, no redirects or response bodies.
No crawling, arbitrary URLs, secrets, auth, cookies, proxies or retries.
"""
from __future__ import annotations

import argparse
import http.client
import ipaddress
import json
import socket
import ssl
from typing import Any, Callable

# Explicit public endpoints already cited by Hermes documentation.
PROBES = {
    "crossref-public-doi": ("api.crossref.org",
                            "/works/10.1038%2Fs41586-020-2649-2"),
    "europe-pmc-public-docs": ("europepmc.org", "/RestfulWebService"),
}
TIMEOUT_SECONDS = 4
MAX_PROBES = 2


class PublicProbeDenied(ValueError):
    """Use only fixed sanitized failure reasons; never raw network errors."""


def public_address(host: str) -> str:
    if host not in {pair[0] for pair in PROBES.values()}:
        raise PublicProbeDenied("host_not_allowlisted")
    try:
        records = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        addresses = sorted({r[4][0] for r in records
                            if r[0] in (socket.AF_INET, socket.AF_INET6)})
        parsed = [ipaddress.ip_address(x) for x in addresses]
    except (OSError, ValueError):
        raise PublicProbeDenied("dns_unavailable") from None
    if not parsed or any(not ip.is_global for ip in parsed):
        raise PublicProbeDenied("nonpublic_address")
    ipv4 = [ip for ip in parsed if ip.version == 4]
    return str(sorted(ipv4 or parsed, key=int)[0])


class PinnedTLS(http.client.HTTPSConnection):
    def __init__(self, host: str, ip: str):
        super().__init__(host, timeout=TIMEOUT_SECONDS,
                         context=ssl.create_default_context())
        self.ip = ip

    def connect(self) -> None:
        sock = socket.create_connection((self.ip, 443), timeout=TIMEOUT_SECONDS)
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise


def request_one(name: str) -> int:
    if name not in PROBES:
        raise PublicProbeDenied("probe_not_allowlisted")
    host, path = PROBES[name]
    client = PinnedTLS(host, public_address(host))
    try:
        client.request("HEAD", path, headers={
            "Host": host, "User-Agent": "HermesLinkAudit/0.1 (public HEAD only)",
            "Accept": "*/*", "Accept-Encoding": "identity", "Connection": "close",
        })
        response = client.getresponse()
        return response.status
    except (OSError, TimeoutError, http.client.HTTPException):
        raise PublicProbeDenied("network_or_timeout") from None
    finally:
        client.close()


def classify(status: object) -> str:
    if type(status) is not int or not 100 <= status <= 599:
        return "UNKNOWN"
    if 200 <= status < 300:
        return "HEALTHY"
    if status in (404, 410):
        return "BROKEN"
    if status in (301, 302, 303, 307, 308):
        return "REDIRECT_UNFOLLOWED"
    # 401/403/429/5xx are not proof of a broken URL.
    return "UNKNOWN"


def audit(runner: Callable[[str], int] = request_one) -> dict[str, Any]:
    results = []
    for name in PROBES:
        try:
            state = classify(runner(name))
        except PublicProbeDenied:
            state = "UNKNOWN"
        results.append({"reference": name, "state": state})
    return {
        "status": ("REVIEW" if any(x["state"] == "BROKEN" for x in results)
                   else "UNKNOWN" if any(x["state"] != "HEALTHY" for x in results)
                   else "OK"),
        "probes_attempted": len(results),
        "results": results,
        "network_bounded": True,
        "redirections_followed": False,
        "private_targets_requested": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Optional bounded public HEAD check")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"status": "NOT_EXECUTED"}))
        return 0
    result = audit()
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "OK" else 2


if __name__ == "__main__":
    raise SystemExit(main())
