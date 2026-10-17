"""Command-line interface for offline Hermes Agent Benchmark."""
import argparse
import json
import os
from pathlib import Path
import sys

from .core import BenchmarkError, compare, load_cases, run, save


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m hermes_benchmark")
    commands = parser.add_subparsers(dest="command", required=True)
    start = commands.add_parser("run")
    start.add_argument("--output", type=Path, default=Path("benchmark-report"))
    start.add_argument("--sha", default=os.environ.get("GITHUB_SHA"))
    start.add_argument("--case", action="append", dest="cases")
    check = commands.add_parser("validate")
    diff = commands.add_parser("compare")
    diff.add_argument("before", type=Path)
    diff.add_argument("after", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "validate":
            print("validated {} pinned offline fixtures".format(len(load_cases())))
            return 0
        if args.command == "compare":
            prior = json.loads(args.before.read_text(encoding="utf-8"))
            current = json.loads(args.after.read_text(encoding="utf-8"))
            result = compare(prior, current)
            print(json.dumps(result, sort_keys=True, indent=2))
            return 1 if result["regressions"] else 0
        report = run(selected=set(args.cases) if args.cases else None, sha=args.sha)
        save(report, args.output)
        print("Hermes synthetic benchmark: {} passed / {} total; {} failed, {} unverified, {} infra_failure, {} not_run".format(
            report["passed"], report["task_count"], report["failed"],
            report["unverified"], report["infra_failure"], report["not_run"]))
        return 0 if not (report["failed"] or report["unverified"] or
                         report["infra_failure"]) else 1
    except (BenchmarkError, OSError, ValueError, KeyError, TypeError):
        # Sanitized message only: never echo raw content from failed reports.
        print("benchmark_error: invalid_input_or_environment", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
