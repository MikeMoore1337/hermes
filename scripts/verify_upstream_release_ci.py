"""H-01: evidence-only check of upstream Docker release test *steps*.

A green release/publish run is not evidence that its integration tests ran.
Queries are read-only, public GitHub API, fixed releases and fixed run IDs,
with no user token or host secret. This module can NEVER enable the agent.
"""
from __future__ import annotations

import argparse
import http.client
import json
import re
from typing import Any, Callable

HOST = "api.github.com"
ROOT = "/repos/NousResearch/hermes-agent/actions/runs/"
RELEASES: dict[str, tuple[int, str, str]] = {
    "v0.21.7": (38199200509, "71d34bad1045610252eda02ee79549436896e784", "rc.15-v0.21.7"),
    "v0.22.0": (38491090442, "e06df9c2eae6901f4c88f464e0ae6e753c0428b8", "rc.3-v0.22.0"),
    "v0.22.1": (38646275925, "297552a9d646119871391d202509822cd86330df", "rc.5-v0.22.1"),
}
MAX_BODY = 2_097_152
MAX_PAGES = 4
PAGE_SIZE = 100
MAX_JOBS = 350
SHA = re.compile(r"[a-f0-9]{40}\Z")
VARIANTS = ("slim/amd64", "slim/arm64", "desktop/amd64", "desktop/arm64")


class ReleaseCIDenied(ValueError):
    """Fixed error code; never echo upstream-controlled payloads."""


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, val in pairs:
        if key in result:
            raise ReleaseCIDenied("upstream_duplicate_json_key")
        result[key] = val
    return result


def decode(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_BODY:
        raise ReleaseCIDenied("public_api_response_invalid")
    try:
        value = json.loads(raw, object_pairs_hook=_no_duplicates)
    except ReleaseCIDenied:
        raise
    except (ValueError, UnicodeError):
        raise ReleaseCIDenied("public_api_json_invalid") from None
    if type(value) is not dict:
        raise ReleaseCIDenied("public_api_schema_invalid")
    return value


def get_public(path: str) -> dict[str, Any]:
    # Never accept URLs/paths from the caller. The only consumers below
    # construct exact routes from pinned integer run IDs.
    if not re.fullmatch(
        r"/repos/NousResearch/hermes-agent/actions/runs/\d+"
        r"(?:/jobs\?per_page=100&page=[1-4])?", path,
    ):
        raise ReleaseCIDenied("public_api_route_denied")
    connection = http.client.HTTPSConnection(HOST, timeout=8)
    try:
        connection.request(
            "GET", path,
            headers={"Accept": "application/vnd.github+json",
                     "Accept-Encoding": "identity",
                     "User-Agent": "HermesReleaseCIInspector/1.0",
                     "X-GitHub-Api-Version": "2022-11-28",
                     "Connection": "close"},
        )
        response = connection.getresponse()
        if response.status != 200:  # No redirect, no retry/fallback.
            raise ReleaseCIDenied("public_api_unavailable")
        mime = response.getheader("Content-Type", "").lower()
        if not (mime.startswith("application/json")
                or mime.startswith("application/vnd.github+json")):
            raise ReleaseCIDenied("public_api_content_type_invalid")
        if response.getheader("Content-Encoding", "identity").lower() != "identity":
            raise ReleaseCIDenied("public_api_encoding_invalid")
        return decode(response.read(MAX_BODY + 1))
    except (OSError, TimeoutError, http.client.HTTPException):
        raise ReleaseCIDenied("public_api_network_error") from None
    finally:
        connection.close()


def review(
    release: str,
    *,
    fetcher: Callable[[str], dict[str, Any]] = get_public,
) -> dict[str, object]:
    if type(release) is not str or release not in RELEASES:
        raise ReleaseCIDenied("release_not_allowlisted")
    run_id, sha, claim = RELEASES[release]
    head = fetcher(f"{ROOT}{run_id}")
    if (type(head) is not dict or head.get("id") != run_id
            or type(head.get("id")) is not int
            or head.get("head_sha") != sha
            or SHA.fullmatch(sha) is None
            or head.get("name") != f"Stable release {claim}"
            or head.get("event") != "workflow_dispatch"
            or head.get("conclusion") != "success"
            or head.get("status") != "completed"):
        raise ReleaseCIDenied("release_run_identity_invalid")
    jobs: list[dict[str, Any]] = []
    job_ids: set[int] = set()
    total: int | None = None
    for page in range(1, MAX_PAGES + 1):
        response = fetcher(f"{ROOT}{run_id}/jobs?per_page={PAGE_SIZE}&page={page}")
        if type(response) is not dict:
            raise ReleaseCIDenied("release_jobs_schema_invalid")
        count, batch = response.get("total_count"), response.get("jobs")
        if (type(count) is not int or not 1 <= count <= MAX_JOBS
                or type(batch) is not list or not 0 < len(batch) <= PAGE_SIZE):
            raise ReleaseCIDenied("release_jobs_page_invalid")
        if total is not None and count != total:
            raise ReleaseCIDenied("release_jobs_total_changed")
        total = count
        for job in batch:
            if (type(job) is not dict or type(job.get("id")) is not int
                    or job["id"] in job_ids or type(job.get("name")) is not str
                    or len(job["name"]) > 230):
                raise ReleaseCIDenied("release_job_invalid")
            job_ids.add(job["id"])
            jobs.append(job)
        if len(jobs) >= total:
            break
    if total is None or len(jobs) != total:
        raise ReleaseCIDenied("release_jobs_incomplete")

    def unique_job(name: str) -> dict[str, Any]:
        found = [job for job in jobs if job["name"] == name]
        if len(found) != 1:
            raise ReleaseCIDenied("release_required_job_missing_or_ambiguous")
        return found[0]

    def unique_step(job: dict[str, Any], name: str) -> str:
        steps = job.get("steps")
        if type(steps) is not list or len(steps) > 75:
            raise ReleaseCIDenied("release_job_steps_missing")
        selected = [step for step in steps
                    if type(step) is dict and step.get("name") == name]
        if len(selected) != 1 or selected[0].get("conclusion") not in (
                "success", "skipped", "failure", "cancelled", None):
            raise ReleaseCIDenied("release_test_step_missing")
        return str(selected[0]["conclusion"])

    ci_job = unique_job("Full CI pipeline")
    ci = ci_job.get("conclusion")
    if ci not in ("success", "skipped", "failure", "cancelled"):
        raise ReleaseCIDenied("release_ci_conclusion_invalid")
    docker_checks: dict[str, str] = {}
    docker_identity: dict[str, str] = {}
    for variant in VARIANTS:
        job = unique_job(f"Docker build and tests / Build and test image ({variant})")
        if job.get("conclusion") != "success":
            raise ReleaseCIDenied("release_docker_build_not_successful")
        docker_checks[variant] = unique_step(job, "Run docker integration tests")
        docker_identity[variant] = unique_step(job, "Verify release image identity")
    if unique_job("All release acceptance checks pass").get("conclusion") != "success":
        raise ReleaseCIDenied("release_acceptance_not_successful")
    published = unique_job(
        "Publish tested Docker image / Assemble versioned manifest and digest receipt"
    )
    if published.get("conclusion") != "success":
        raise ReleaseCIDenied("release_manifest_not_published")
    all_tests = ci == "success" and all(
        result == "success" for result in docker_checks.values()
    )
    skipped = ci == "skipped" or any(
        result == "skipped" for result in docker_checks.values()
    )
    return {
        "schema": "hermes-upstream-release-ci-evidence-v1",
        "release": release,
        "source_commit": sha,
        "official_workflow_run_id": run_id,
        "official_run_conclusion": "success",
        "full_ci_job_conclusion": ci,
        "docker_integrations": docker_checks,
        "docker_image_identity_checks": docker_identity,
        "release_jobs_observed": len(jobs),
        "tests_fully_executed_for_release": all_tests,
        "any_required_tests_skipped": skipped,
        "status": "UPSTREAM_REQUIRED_TESTS_SKIPPED" if skipped else (
            "UPSTREAM_TESTS_REPORTED_PASS_UNATTESTED" if all_tests
            else "UPSTREAM_TESTS_FAILED_OR_UNCERTAIN"
        ),
        "signed_build_attestation_verified": False,
        "complete_sbom_verified": False,
        "resident_agent_allowed": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evidence-only public GitHub release CI check")
    parser.add_argument("--release", choices=sorted(RELEASES), default="v0.22.1")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"status": "NOT_EXECUTED", "resident_agent_allowed": False}))
        return 0
    try:
        report = review(args.release)
    except ReleaseCIDenied:
        print(json.dumps({"status": "UNKNOWN", "resident_agent_allowed": False}))
        return 2
    print(json.dumps(report, sort_keys=True))
    # Do not allow this public untrusted observation to authorize the model.
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
