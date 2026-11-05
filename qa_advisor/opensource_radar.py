"""OpenSource Radar: source-bound, offline candidate-policy precheck.

Never fetch GitHub, execute third-party code, infer absence of CVEs from
missing reports, or authorize license use/deployment.
"""
from __future__ import annotations

import argparse
from datetime import UTC, datetime, timedelta
import json
import os
from pathlib import Path
import re
import stat
from typing import Any

SCHEMA = "hermes-ossradar-evidence-v1"
REPORT_SCHEMA = "hermes-ossradar-review-v1"
TARGETS = frozenset({
    "MikeMoore1337/hermes", "MikeMoore1337/ai-development-toolkit",
    "MikeMoore1337/your-fitness-coach",
})
REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")
LICENCES = frozenset({
    "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC",
    "MPL-2.0", "LGPL-3.0-only", "GPL-3.0-only", "GPL-3.0-or-later",
    "AGPL-3.0-only", "AGPL-3.0-or-later", "UNKNOWN",
})
COPYLEFT = frozenset({
    "MPL-2.0", "LGPL-3.0-only", "GPL-3.0-only",
    "GPL-3.0-or-later", "AGPL-3.0-only", "AGPL-3.0-or-later",
})
MAX_AGE = timedelta(hours=1)
STALENESS = timedelta(days=540)
SKEW = timedelta(minutes=2)
MAX_BYTES = 16384


class RadarRefused(ValueError):
    """Sanitized fixed codes; never echo raw fetched README or credentials."""


def _shape(raw: Any, keys: set[str], code: str) -> dict:
    if type(raw) is not dict or set(raw) != keys:
        raise RadarRefused(code)
    return raw


def _utc(raw: Any, *, nullable: bool = False) -> datetime | None:
    if nullable and raw is None:
        return None
    if type(raw) is not str or not 1 <= len(raw) <= 40:
        raise RadarRefused("timestamp_invalid")
    try:
        stamp = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        raise RadarRefused("timestamp_invalid") from None
    if stamp.tzinfo is None or stamp.utcoffset() != timedelta(0):
        raise RadarRefused("timestamp_invalid")
    return stamp.astimezone(UTC)


def _repo(value: Any) -> str:
    if (type(value) is not str or REPO.fullmatch(value) is None
            or any(part in ("", ".", "..") for part in value.split("/"))
            or value.endswith(".git")):
        raise RadarRefused("source_repo_invalid")
    return value


def assess(raw: Any, *, now: datetime | None = None) -> dict:
    data = _shape(raw, {
        "schema", "source_repo", "target_repo", "observed_at",
        "commit_sha", "default_branch", "is_archived", "is_fork",
        "pushed_at", "last_release_at", "license_spdx",
        "advisory_signal", "compatibility_signal",
    }, "evidence_shape_invalid")
    if data["schema"] != SCHEMA:
        raise RadarRefused("schema_invalid")
    source = _repo(data["source_repo"])
    if type(data["target_repo"]) is not str or data["target_repo"] not in TARGETS:
        raise RadarRefused("target_scope_invalid")
    branch = data["default_branch"]
    if (type(branch) is not str or not 1 <= len(branch) <= 80
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", branch)
            or any(p in ("", ".", "..") for p in branch.split("/"))):
        raise RadarRefused("branch_invalid")
    commit = data["commit_sha"]
    if commit is not None and (type(commit) is not str or SHA.fullmatch(commit) is None):
        raise RadarRefused("source_sha_invalid")
    if type(data["is_archived"]) is not bool or type(data["is_fork"]) is not bool:
        raise RadarRefused("repo_flags_invalid")
    licence = data["license_spdx"]
    if type(licence) is not str or licence not in LICENCES:
        raise RadarRefused("license_invalid")
    if (type(data["advisory_signal"]) is not str
            or data["advisory_signal"] not in ("REPORTED", "NONE_OBSERVED", "UNKNOWN")
            or type(data["compatibility_signal"]) is not str
            or data["compatibility_signal"] not in ("COMPATIBLE", "INCOMPATIBLE", "UNKNOWN")):
        raise RadarRefused("signals_invalid")
    observed = _utc(data["observed_at"])
    pushed = _utc(data["pushed_at"], nullable=True)
    release = _utc(data["last_release_at"], nullable=True)
    checked = now if now is not None else datetime.now(UTC)
    if type(checked) is not datetime or checked.tzinfo is None or checked.utcoffset() != timedelta(0):
        raise RadarRefused("clock_invalid")
    checked = checked.astimezone(UTC)
    flags: set[str] = set()
    holds: set[str] = set()
    rejects: set[str] = set()
    if observed > checked + SKEW or checked - observed > MAX_AGE:
        flags.add("snapshot_stale_or_future")
    if commit is None:
        flags.add("exact_source_sha_missing")
    if pushed is None:
        flags.add("maintenance_unknown")
    elif pushed > checked + SKEW:
        flags.add("push_date_future")
    elif checked - pushed > STALENESS:
        flags.add("maintenance_stale")
    if release is None:
        flags.add("release_history_unknown")
    elif release > checked + SKEW:
        flags.add("release_date_future")
    elif checked - release > STALENESS:
        flags.add("release_history_stale")
    if data["is_archived"]:
        holds.add("repository_archived")
    if data["is_fork"]:
        flags.add("upstream_fork_provenance_review")
    if licence == "UNKNOWN":
        holds.add("license_not_verified")
    elif licence in COPYLEFT:
        holds.add("copyleft_obligations_review")
    if licence.startswith("AGPL") and data["target_repo"] == "MikeMoore1337/your-fitness-coach":
        holds.add("yfc_agpl_integration_hold")
    if data["advisory_signal"] == "REPORTED":
        holds.add("reported_security_findings_review")
    elif data["advisory_signal"] in ("UNKNOWN", "NONE_OBSERVED"):
        flags.add("security_not_verified")
    if data["compatibility_signal"] == "INCOMPATIBLE":
        rejects.add("reported_target_incompatibility")
    elif data["compatibility_signal"] == "UNKNOWN":
        flags.add("target_compatibility_unknown")
    status = (
        "REJECT_RECOMMENDED" if rejects
        else "HOLD_FOR_REVIEW" if holds
        else "NEEDS_REVIEW" if flags
        else "PILOT_REVIEW"
    )
    url = f"https://github.com/{source}"
    return {
        "schema": REPORT_SCHEMA,
        "status": status,
        "source_repo": source,
        "target_repo": data["target_repo"],
        "checked_at": checked.isoformat().replace("+00:00", "Z"),
        "source_url": url,
        "commit_url": f"{url}/commit/{commit}" if commit is not None else None,
        "license_spdx_claimed": licence,
        "reasons": sorted(flags | holds | rejects),
        "source_verified": False,
        "license_verified": False,
        "security_scan": "NOT_RUN",
        "compatibility_verified": False,
        "source_executed": False,
        "install_authorized": False,
        "owner_approval": "NOT_GRANTED",
        "recommendation_only": True,
    }


def _read(path: Path) -> Any:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or not 2 <= info.st_size <= MAX_BYTES:
                raise RadarRefused("file_invalid")
            data = os.read(fd, MAX_BYTES + 1)
        finally:
            os.close(fd)
        if len(data) > MAX_BYTES:
            raise RadarRefused("file_invalid")
        return json.loads(data)
    except RadarRefused:
        raise
    except (OSError, ValueError, UnicodeError, RecursionError):
        raise RadarRefused("file_unavailable_or_invalid") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline OSS integration review, no network/installs")
    parser.add_argument("--input", type=Path)
    args = parser.parse_args(argv)
    if args.input is None:
        print(json.dumps({"status": "NOT_EXECUTED"}))
        return 0
    try:
        result = assess(_read(args.input))
    except RadarRefused as exc:
        print(json.dumps({"status": "REFUSED", "reason": str(exc)}))
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] == "PILOT_REVIEW" else 2


if __name__ == "__main__":
    raise SystemExit(main())
