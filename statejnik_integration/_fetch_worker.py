"""Isolated single-purpose H12 fetch worker; NEVER register as a Hermes tool.

Runs only under supervisor.run_bounded with a parent kill timer.
All inputs are public, allowlisted HTML URLs; no tokens or credentials.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# -I isolated Python mode does not implicitly import application source.
# The installed immutable Hermes source tree supplies only these modules.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from statejnik_integration.html_review import HtmlReviewDenied, candidate_fetch_one
from statejnik_integration.network_boundary import NetworkDenied, target


def main(args: list[str]) -> int:
    if len(args) not in range(2, 10):
        print('{"status":"DENIED"}')
        return 2
    url, *hosts = args
    try:
        allowed = frozenset(hosts)
        if len(allowed) != len(hosts):
            raise NetworkDenied("duplicate_hosts")
        parsed = target(url, allowed)
        if "?" in url or not parsed.path:
            raise NetworkDenied("query_denied")
        result = candidate_fetch_one(
            url, allowed_hosts=allowed, network_authorized=True
        )
    except (HtmlReviewDenied, NetworkDenied, OSError, ValueError):
        print('{"status":"DENIED"}')
        return 2
    # No HTML body, cookies, credentials or full article text in stdout.
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
