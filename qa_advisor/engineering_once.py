"""Operator-triggered engineering sweep; no scheduler, no background agent.

Only explicitly selected public sources and local lockfile are observed.
Failures reduce coverage and never overwrite a good feed when all fail.
"""
from __future__ import annotations

import argparse
from datetime import UTC, datetime
import json
from pathlib import Path

from qa_advisor.engineering_feed import (
    EngineeringFeedRefused, build, save,
)
from qa_advisor.engineering_public import (
    PublicGithub, SourceUnavailable, release_snapshot, merge_snapshot,
    radar_snapshot,
)
from qa_advisor.deppilot_registry import (
    RegistryUnavailable, candidates_for,
)
from qa_advisor.deppilot import _file, MAX_LOCK_BYTES, DepPilotRefused

REPOS = (
    "MikeMoore1337/hermes",
    "MikeMoore1337/ai-development-toolkit",
    "MikeMoore1337/your-fitness-coach",
)


def collect(*, repo: str, source_repo: str | None = None,
            lockfile: Path | None = None,
            runtime: str | None = None, packages: list[str] | None = None,
            now: datetime | None = None, github_client=None, registry_client=None) -> dict:
    """Collect independently; never turn partial network success into full GO."""
    if repo not in REPOS:
        raise EngineeringFeedRefused("repo_not_allowlisted")
    if ((lockfile is None and (runtime is not None or packages))
            or (lockfile is not None and (runtime is None or not packages))):
        raise EngineeringFeedRefused("lockfile_options_missing")
    if source_repo is not None:
        from qa_advisor.opensource_radar import _repo as validate_slug
        try:
            validate_slug(source_repo)
        except ValueError:
            raise EngineeringFeedRefused("source_repo_invalid") from None
    instant = now if now is not None else datetime.now(UTC)
    if type(instant) is not datetime or instant.tzinfo is None:
        raise EngineeringFeedRefused("clock_invalid")
    # Share one bounded public GitHub request budget for this whole sweep.
    # One module cannot silently create a fresh unlimited transport budget.
    if github_client is None:
        github_client = PublicGithub()
    results: dict = {}
    for key, operation in (
        ("release_guard", lambda: release_snapshot(
            repo, stage="RELEASE", client=github_client, now=instant)),
        ("merge_control", lambda: merge_snapshot(
            repo, client=github_client, now=instant)),
    ):
        try:
            results[key] = operation()
        except (SourceUnavailable, ValueError, TimeoutError):
            pass
    if source_repo is not None:
        try:
            results["opensource_radar"] = radar_snapshot(
                source_repo, repo, client=github_client, now=instant)
        except (SourceUnavailable, ValueError, TimeoutError):
            pass
    if lockfile is not None:
        if runtime is None or not packages:
            raise EngineeringFeedRefused("lockfile_options_missing")
        try:
            raw = _file(lockfile, limit=MAX_LOCK_BYTES)
            results["deppilot"] = candidates_for(
                lockfile.name, raw, repo=repo, runtime=runtime,
                packages=packages, source=registry_client, now=instant,
            )
        except (DepPilotRefused, RegistryUnavailable, ValueError, OSError, TimeoutError):
            pass
    elif runtime is not None or packages:
        raise EngineeringFeedRefused("lockfile_options_missing")
    if not results:
        raise EngineeringFeedRefused("no_available_source_results")
    return build(results, now=instant.astimezone(UTC))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Opt-in Engineering Control sweep")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--save", action="store_true")
    parser.add_argument("--repository", choices=REPOS, default="MikeMoore1337/hermes")
    parser.add_argument("--source")
    parser.add_argument("--lockfile", type=Path)
    parser.add_argument("--runtime")
    parser.add_argument("--package", action="append")
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"status": "NOT_EXECUTED"}))
        return 0
    try:
        packet = collect(
            repo=args.repository, source_repo=args.source,
            lockfile=args.lockfile, runtime=args.runtime, packages=args.package,
        )
        if args.save:
            save(packet)
    except (EngineeringFeedRefused, OSError, ValueError):
        print(json.dumps({
            "status": "INCONCLUSIVE", "reason": "engineering_source_unavailable",
            "state_written": False, "owner_approval": "NOT_GRANTED",
            "execution_authorized": False,
        }))
        return 2
    print(json.dumps(packet, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
