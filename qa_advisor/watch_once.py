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
from qa_advisor import github_observe_feed as observe_feed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Hermes owner CI read-only one-shot monitor")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--observe-feed", action="store_true",
                        help="Read one additional fixed Actions workflow metadata window")
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
    # The extra read is isolated: an unavailable observer cannot erase or
    # convert the existing CI result into a false recovery.
    feed_status = "DISABLED"
    if args.observe_feed:
        try:
            receipt_feed = observe_feed.poll(now=datetime.now(UTC))
            observe_feed.save(receipt_feed)
            feed_status = "STORED"
        except (observe_feed.FeedRefused, GithubPublicError, SignalError,
                OSError, TimeoutError, ValueError):
            feed_status = "UNAVAILABLE"
    # No token, SHA, raw text, full URL or HTTP body.
    print(json.dumps({
        "status": "STORED" if receipt == "STORED_SAFE_CI_SIGNAL" else "PRESERVED",
        "signal": current["status"], "outbound_notifications": 0,
        "github_observe_feed": feed_status,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
