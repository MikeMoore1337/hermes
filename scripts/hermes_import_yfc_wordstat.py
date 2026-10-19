"""Bounded stdin-only CLI for the pinned historical YFC Wordstat snapshot."""
from __future__ import annotations

import argparse
import json
import sys

from marketing.seo_research import SeoResearchDenied
from marketing.yfc_wordstat_import import MAX_CSV_BYTES, import_yfc_wordstat


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Import existing YFC Wordstat data offline")
    parser.add_argument("--query", required=True)
    parser.add_argument("--as-of", required=True, help="Evaluation date YYYY-MM-DD")
    args = parser.parse_args(argv)
    try:
        raw = sys.stdin.buffer.read(MAX_CSV_BYTES + 1)
        result = import_yfc_wordstat(raw, selected_query=args.query, as_of=args.as_of)
    except SeoResearchDenied as exc:
        print(json.dumps({"status": "REJECTED", "reason": str(exc)}))
        return 2
    print(json.dumps(result, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
