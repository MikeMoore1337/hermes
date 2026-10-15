"""Run one bounded private main CI read and persist only fixed outcome signal.

Does not call Telegram or Ops Watch. Unknown access failures leave prior
durable state intact; unattended timer performs at most one GET per tick.
"""
from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime

from qa_advisor.ci_snapshot import SnapshotRefused, inspect_once
from qa_advisor.github_public import GithubPublicError
from qa_advisor.signal_store import SignalError, from_ci, store


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Hermes owner CI read-only one-shot monitor")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"status": "NOT_EXECUTED"}))
        return 0
    try:
        current = inspect_once()
        receipt = store(from_ci(current, now=datetime.now(UTC)))
    except (GithubPublicError, SnapshotRefused, SignalError, OSError, TimeoutError):
        print(json.dumps({"status": "UNKNOWN", "reason": "ci_read_or_store_unavailable"}))
        return 2
    # No token, SHA, raw text, full URL or HTTP body.
    print(json.dumps({
        "status": "STORED" if receipt == "STORED_SAFE_CI_SIGNAL" else "PRESERVED",
        "signal": current["status"], "outbound_notifications": 0,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
