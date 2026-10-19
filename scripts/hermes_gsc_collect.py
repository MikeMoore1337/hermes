"""One-shot, read-only GSC collector. Requires separately authorized credentials."""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from marketing.gsc_direct import GscRuntimeError, live_run, request_plan


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Hermes bounded read-only GSC collector")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--credentials", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if args.dry_run:
        if args.credentials is not None or args.output is not None:
            parser.error("--dry-run does not read or accept credentials/output")
        now = datetime.now(tz=ZoneInfo("America/Los_Angeles")).date()
        start, end, plan = request_plan(as_of=now)
        print(json.dumps({
            "status": "DRY_RUN_NO_NETWORK", "property": "sc-domain:your-fitness-coach.ru",
            "scope": "webmasters.readonly", "period_start": start, "period_end": end,
            "requests_per_run": len(plan), "publication_allowed": False,
            "credentials_accessed": False,
        }, sort_keys=True))
        return 0
    if args.credentials is None or args.output is None:
        parser.error("--credentials and --output are both required")
    try:
        result = live_run(credentials_path=args.credentials, output_path=args.output)
    except GscRuntimeError as exc:
        print(json.dumps({"status": "BLOCKED", "reason": str(exc)}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
