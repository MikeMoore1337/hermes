"""H-01: verify *source commit* CI separately from a published Docker image.

The exact upstream source commit passed key tests, but its image-specific
release integration steps were skipped. Neither fact is source-image
provenance, full SBOM or permission for resident model runtime.
"""
from __future__ import annotations

import argparse
import json
from collections.abc import Callable
from typing import Any

from .verify_upstream_release_ci import (
    ROOT, ReleaseCIDenied, get_public,
)

RUN_ID = 38644080305
SOURCE_SHA = "297552a9d646119871391d202509822cd86330df"
EXPECTED_TOTAL = 40
MANDATORY = (
    "Python tests / Run tests (1/2)",
    "Python tests / Run tests (2/2)",
    "Python lints / ruff enforcement (blocking)",
    "Remote terminal backends / SSH + Docker backends (real sshd, real daemon)",
    "Rust tests / cargo test (bootstrap installer)",
    "JS & TS checks / JS & TS checks",
    "OS-specific tests / Windows-only tests",
    "OS-specific tests / macOS-only tests (1/2)",
    "OS-specific tests / macOS-only tests (2/2)",
    "All required checks pass (v2)",
)
NOT_RUN = (
    "Supply-chain scan",
    "Python tests / e2e",
    "Desktop core E2E",
)


def review(
    *,
    fetcher: Callable[[str], dict[str, Any]] = get_public,
) -> dict[str, object]:
    head = fetcher(f"{ROOT}{RUN_ID}")
    if (type(head) is not dict or type(head.get("id")) is not int
            or head["id"] != RUN_ID or head.get("head_sha") != SOURCE_SHA
            or head.get("name") != "CI" or head.get("event") != "push"
            or head.get("status") != "completed"
            or head.get("conclusion") != "success"):
        raise ReleaseCIDenied("source_ci_run_identity_invalid")

    response = fetcher(f"{ROOT}{RUN_ID}/jobs?per_page=100&page=1")
    if (type(response) is not dict
            or type(response.get("total_count")) is not int
            or response["total_count"] != EXPECTED_TOTAL
            or type(response.get("jobs")) is not list
            or len(response["jobs"]) != EXPECTED_TOTAL):
        raise ReleaseCIDenied("source_ci_jobs_incomplete")
    names: dict[str, str] = {}
    ids: set[int] = set()
    for job in response["jobs"]:
        if (type(job) is not dict
                or type(job.get("id")) is not int or job["id"] <= 0
                or type(job.get("name")) is not str
                or len(job["name"]) > 230
                or job.get("conclusion") not in (
                    "success", "skipped", "failure", "cancelled"
                ) or job["id"] in ids or job["name"] in names):
            raise ReleaseCIDenied("source_ci_job_invalid")
        ids.add(job["id"])
        names[job["name"]] = job["conclusion"]
    if not all(name in names for name in MANDATORY + NOT_RUN):
        raise ReleaseCIDenied("source_ci_required_job_missing")

    successes = {name: names[name] for name in MANDATORY}
    skipped = {name: names[name] for name in NOT_RUN}
    all_successful = all(result == "success" for result in successes.values())
    any_required_skipped = any(result != "success" for result in skipped.values())

    return {
        "schema": "hermes-upstream-source-ci-evidence-v1",
        "source_sha": SOURCE_SHA,
        "source_ci_run_id": RUN_ID,
        "source_ci_run_result": "success",
        "selected_core_checks": successes,
        "selected_optional_checks": skipped,
        "selected_core_checks_passed": all_successful,
        "selected_optional_checks_not_all_run": any_required_skipped,
        "source_code_ci_observed": all_successful,
        "release_docker_integration_tests_verified": False,
        "image_source_parity_verified": False,
        "complete_sbom_verified": False,
        "supplier_attestation_verified": False,
        "resident_agent_allowed": False,
        "status": (
            "SOURCE_CORE_CI_PASS_IMAGE_UNVERIFIED"
            if all_successful else "SOURCE_CORE_CI_INCOMPLETE"
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="One exact official source CI read-only audit")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"status": "NOT_EXECUTED", "resident_agent_allowed": False}))
        return 0
    try:
        observed = review()
    except ReleaseCIDenied:
        print(json.dumps({"status": "UNKNOWN", "resident_agent_allowed": False}))
        return 2
    print(json.dumps(observed, sort_keys=True))
    # Observing source tests is evidence only; never allow model runtime.
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
