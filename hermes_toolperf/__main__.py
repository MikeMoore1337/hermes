"""Print a reproducible in-memory baseline/candidate comparison; no model calls."""
from __future__ import annotations

import argparse
import json
import os
import sys

from .core import ToolperfError, markdown, run


def main(argv=None):
    p = argparse.ArgumentParser(prog="python -m hermes_toolperf")
    p.add_argument("--sha", default=os.environ.get("GITHUB_SHA"))
    p.add_argument("--format", choices=("markdown", "json"), default="markdown")
    args = p.parse_args(argv)
    try:
        report = run(sha=args.sha)
    except (ToolperfError, ValueError, TypeError):
        print("toolperf_error: invalid_fixture_or_sha", file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    else:
        print(markdown(report), end="")
    return 0 if report["candidate_passed"] == report["task_count"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
