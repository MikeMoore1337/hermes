"""Owner-operated, read-only #295 production acceptance report.

Runs on Hermes VPS with the ordinary hermes-control Unix identity. Reads only
existing sanitized snapshots and probes loopback auth; never writes files,
loads API credentials, or makes provider network calls.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from control_center.provider_registry import registry


HOST = "hermes.mikemoore.top"
PROVIDER_IDS = ("cloudflare_workers_ai", "codex", "desktop_commander", "github_api")
STATUSES = frozenset({"ok", "low", "exhausted", "throttled", "auth_required",
                       "stale", "unknown", "not_connected"})


def local_http(path: str, *, port: int = 9133, transport=urlopen) -> int | None:
    """Never pass cookies, tokens or Authorization to the local service."""
    if path not in ("/healthz", "/api/providers/registry"):
        raise ValueError("invalid_endpoint")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("invalid_port")
    request = Request("http://127.0.0.1:" + str(port) + path,
                      headers={"Host": HOST}, method="GET")
    try:
        with transport(request, timeout=3) as response:
            return int(response.status)
    except HTTPError as exc:
        return int(exc.code)
    except (URLError, TimeoutError, OSError):
        return None


def assess(snapshot: dict, *, health_code: int | None,
           denied_code: int | None) -> dict:
    """Report source availability, never specific quota values or paths."""
    report = {"schema": 1, "scope": "local_production_readback",
              "health": "ok" if health_code == 200 else "unavailable",
              "unauthenticated_registry": "denied" if denied_code == 401
                                       else "unverified",
              "providers": []}
    rows = snapshot.get("providers") if isinstance(snapshot, dict) else None
    if not isinstance(rows, list) or len(rows) != len(PROVIDER_IDS):
        raise ValueError("provider_registry_contract")
    if snapshot.get("schema") != 1 or snapshot.get("read_only") is not True:
        raise ValueError("provider_registry_contract")
    ids = [item.get("id") for item in rows if isinstance(item, dict)]
    if ids != list(PROVIDER_IDS):
        raise ValueError("provider_registry_contract")
    for row in rows:
        status = row.get("status")
        if status not in STATUSES:
            raise ValueError("provider_status")
        windows = row.get("windows")
        if not isinstance(windows, list) or len(windows) > 48:
            raise ValueError("provider_windows")
        # Count is safe provenance. Snapshot timestamps remain within
        # authenticated registry; no account usage is emitted to stdout.
        report["providers"].append({
            "id": row["id"], "status": status,
            "windows_observed": len(windows),
            "source_kind": row.get("source_kind") if row.get("source_kind") in (
                "unknown", "official_api", "local_meter", "estimated", "manual"
                ) else "unknown"
        })
    return report


def main() -> int:
    try:
        report = assess(registry(),
                        health_code=local_http("/healthz"),
                        denied_code=local_http("/api/providers/registry"))
    except (ValueError, OSError, TypeError, KeyError):
        print(json.dumps({"schema": 1, "scope": "local_production_readback",
                          "status": "source_unavailable"}))
        return 2
    print(json.dumps(report, separators=(",", ":"), ensure_ascii=True))
    # Do not fail merely because the owner has not yet provisioned an
    # optional Billing Read / GitHub quota token.
    return 0 if report["health"] == "ok" and (
        report["unauthenticated_registry"] == "denied") else 1


if __name__ == "__main__":
    sys.exit(main())
