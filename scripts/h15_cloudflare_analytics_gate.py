"""Owner-only admission gate for H-15 daily Cloudflare advisory source.

This gate never performs a provider HTTP request, prints secrets, or treats a
historical adaptive estimate as Free quota usage. Billing collector is separate.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os

from scripts import h15_cloudflare_analytics_probe as probe
from control_center import cloudflare_analytics_history as history


def credentials_ready() -> bool:
    try:
        probe.load_credentials()
        return True
    except (probe.PreflightError, OSError):
        return False


def observed(*, now: dt.datetime | None = None) -> bool:
    now = now or dt.datetime.now(dt.timezone.utc)
    data = history.read(now=now)
    if data["status"] != "historical_estimate":
        return False
    # Explicit prior completed UTC-day evidence, not just any old
    # historical response; never validate today's quota using yesterday.
    yesterday = (now.astimezone(dt.timezone.utc).date() -
                 dt.timedelta(days=1)).isoformat()
    return any(row["day"] == yesterday for row in data["days"])


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Cloudflare advisory source gate")
    p.add_argument("--gate", choices=("status", "credentials", "observed"),
                   default="status")
    args = p.parse_args(argv)
    if os.geteuid() != 0:
        print("CLOUDFLARE_ADVISORY_GATE=ROOT_REQUIRED")
        return 2
    credentials = credentials_ready()
    sample = observed() if credentials and args.gate != "credentials" else False
    print(json.dumps({
        "provider": "cloudflare_analytics_advisory",
        "credentials": "READY_METADATA_ONLY" if credentials else "MISSING_OR_UNSAFE",
        "source": "FRESH_ARCHIVE" if sample else "NOT_VERIFIED",
        "quota_remaining": "UNKNOWN",
    }, sort_keys=True))
    if args.gate == "credentials":
        return 0 if credentials else 2
    if args.gate == "observed":
        return 0 if credentials and sample else 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
