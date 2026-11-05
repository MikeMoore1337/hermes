"""DepPilot: offline, read-only uv/npm lockfile update candidate planning.

No registry lookups, installs, writes, automatic PRs or vulnerability claims.
Candidate versions/engine ranges are externally supplied and UNVERIFIED.
"""
from __future__ import annotations

import argparse
from datetime import UTC, datetime, timedelta
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tomllib
from typing import Any

SCHEMA = "hermes-deppilot-candidates-v1"
REPORT_SCHEMA = "hermes-deppilot-plan-v1"
REPOS = frozenset({
    "MikeMoore1337/hermes", "MikeMoore1337/your-fitness-coach",
    "MikeMoore1337/ai-development-toolkit",
})
LOCKS = {"uv.lock": "pypi", "package-lock.json": "npm"}
MAX_LOCK_BYTES = 8_000_000
MAX_CANDIDATE_BYTES = 65_536
MAX_PACKAGES = 12_000
MAX_CANDIDATES = 120
MAX_AGE = timedelta(days=7)
SKEW = timedelta(minutes=2)
HEX = re.compile(r"[0-9a-f]{64}\Z")
VERSION = re.compile(r"(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){0,2}\Z")
NAME = re.compile(r"(?:@[A-Za-z0-9._-]+/)?[A-Za-z0-9][A-Za-z0-9._-]{0,90}\Z")


class DepPilotRefused(ValueError):
    """Fixed refusal codes only, never leak manifest content or paths."""


def _shape(value: Any, keys: set[str], code: str) -> dict:
    if type(value) is not dict or set(value) != keys:
        raise DepPilotRefused(code)
    return value


def _version(value: Any) -> tuple[int, int, int] | None:
    if type(value) is not str or len(value) > 40 or VERSION.fullmatch(value) is None:
        return None
    parts = [int(x) for x in value.split(".")]
    if any(x > 10**9 for x in parts):
        return None
    return tuple((parts + [0, 0])[:3])


def _name(value: Any, ecosystem: str) -> str:
    if type(value) is not str or NAME.fullmatch(value) is None:
        raise DepPilotRefused("package_name_invalid")
    # Both pip and npm package names are treated case-insensitively only
    # for this plan; no guessed aliases between ecosystems.
    return value.lower().replace("_", "-") if ecosystem == "pypi" else value.lower()


def _utc(value: Any) -> datetime:
    if type(value) is not str or len(value) > 40:
        raise DepPilotRefused("timestamp_invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise DepPilotRefused("timestamp_invalid") from None
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise DepPilotRefused("timestamp_invalid")
    return parsed.astimezone(UTC)


def _file(path: Path, *, limit: int) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or not 2 <= info.st_size <= limit:
                raise DepPilotRefused("file_invalid")
            content = os.read(fd, limit + 1)
        finally:
            os.close(fd)
    except DepPilotRefused:
        raise
    except OSError:
        raise DepPilotRefused("file_unavailable") from None
    if len(content) > limit:
        raise DepPilotRefused("file_invalid")
    return content


def _parse_lock(name: str, raw: bytes) -> tuple[str, dict[str, set[str]]]:
    if name not in LOCKS:
        raise DepPilotRefused("unsupported_lockfile")
    try:
        if name == "uv.lock":
            data = tomllib.loads(raw.decode("utf-8"))
            items = data["package"]
            if type(items) is not list or len(items) > MAX_PACKAGES:
                raise ValueError()
            parsed = []
            for item in items:
                if type(item) is not dict:
                    raise ValueError()
                parsed.append((_name(item.get("name"), LOCKS[name]), item.get("version")))
        else:
            data = json.loads(raw)
            if (type(data) is not dict or data.get("lockfileVersion") not in (2, 3)
                    or type(data.get("packages")) is not dict):
                raise ValueError()
            items = data["packages"]
            if len(items) > MAX_PACKAGES + 1:
                raise ValueError()
            parsed = []
            for key, record in items.items():
                if key == "":
                    continue
                if type(key) is not str or not key.startswith("node_modules/"):
                    raise ValueError()
                # Nested dependencies can occur under repeated node_modules.
                tail = key.rsplit("/node_modules/", 1)[-1]
                tail = tail.removeprefix("node_modules/")
                if type(record) is not dict:
                    raise ValueError()
                parsed.append((_name(tail, LOCKS[name]), record.get("version")))
    except (ValueError, TypeError, KeyError, UnicodeError, tomllib.TOMLDecodeError, RecursionError):
        raise DepPilotRefused("lockfile_invalid") from None
    inventory: dict[str, set[str]] = {}
    for package_name, version in parsed:
        if type(version) is not str or not 1 <= len(version) <= 80:
            raise DepPilotRefused("lockfile_invalid")
        inventory.setdefault(package_name, set()).add(version)
    return LOCKS[name], inventory


def _candidate(item: Any, ecosystem: str) -> dict:
    item = _shape(item, {
        "ecosystem", "name", "candidate_version",
        "min_runtime", "max_runtime_exclusive",
    }, "candidate_shape_invalid")
    if type(item["ecosystem"]) is not str or item["ecosystem"] != ecosystem:
        raise DepPilotRefused("candidate_ecosystem_invalid")
    name = _name(item["name"], ecosystem)
    candidate_version = item["candidate_version"]
    if type(candidate_version) is not str or not 1 <= len(candidate_version) <= 80:
        raise DepPilotRefused("candidate_version_invalid")
    for key in ("min_runtime", "max_runtime_exclusive"):
        if item[key] is not None and _version(item[key]) is None:
            raise DepPilotRefused("runtime_constraint_invalid")
    return {**item, "name": name}


def _change(old: str, new: str) -> str:
    before, after = _version(old), _version(new)
    if before is None or after is None:
        return "UNORDERED"
    if after < before:
        return "DOWNGRADE"
    if after == before:
        return "NO_CHANGE"
    if after[0] != before[0]:
        return "MAJOR"
    if after[1] != before[1]:
        return "MINOR"
    return "PATCH"


def _runtime(candidate: dict, current: str | None) -> str:
    if current is None or _version(current) is None:
        return "UNKNOWN"
    minimum, maximum = candidate["min_runtime"], candidate["max_runtime_exclusive"]
    if minimum is None and maximum is None:
        return "UNKNOWN"
    actual = _version(current)
    if minimum is not None and actual < _version(minimum):
        return "UNSUPPORTED"
    if maximum is not None and actual >= _version(maximum):
        return "UNSUPPORTED"
    # A single bound does not guarantee compatibility with unspecified
    # metadata; signal bounded consistency only.
    return "SUPPORTED_BY_SUPPLIED_RANGE"


def plan(lock_name: str, lock_raw: bytes, metadata: Any, *, now: datetime | None = None) -> dict:
    if type(lock_raw) is not bytes or not 2 <= len(lock_raw) <= MAX_LOCK_BYTES:
        raise DepPilotRefused("lockfile_invalid")
    ecosystem, inventory = _parse_lock(lock_name, lock_raw)
    meta = _shape(metadata, {
        "schema", "repo", "lock_sha256", "observed_at", "runtime_version", "candidates",
    }, "metadata_shape_invalid")
    if meta["schema"] != SCHEMA or type(meta["repo"]) is not str or meta["repo"] not in REPOS:
        raise DepPilotRefused("metadata_scope_invalid")
    if (type(meta["lock_sha256"]) is not str or HEX.fullmatch(meta["lock_sha256"]) is None
            or hashlib.sha256(lock_raw).hexdigest() != meta["lock_sha256"]):
        raise DepPilotRefused("lock_hash_mismatch")
    timestamp = _utc(meta["observed_at"])
    checked = now if now is not None else datetime.now(UTC)
    if type(checked) is not datetime or checked.tzinfo is None or checked.utcoffset() != timedelta(0):
        raise DepPilotRefused("clock_invalid")
    checked = checked.astimezone(UTC)
    runtime = meta["runtime_version"]
    if runtime is not None and _version(runtime) is None:
        raise DepPilotRefused("runtime_version_invalid")
    items = meta["candidates"]
    if type(items) is not list or len(items) > MAX_CANDIDATES:
        raise DepPilotRefused("candidates_invalid")
    candidates = [_candidate(item, ecosystem) for item in items]
    names = [item["name"] for item in candidates]
    if len(set(names)) != len(names):
        raise DepPilotRefused("candidate_duplicate")
    reasons = set()
    if not candidates:
        reasons.add("candidate_list_empty")
    if checked - timestamp > MAX_AGE or timestamp > checked + SKEW:
        reasons.add("candidate_metadata_stale_or_future")
    findings = []
    for candidate in sorted(candidates, key=lambda x: x["name"]):
        installed = sorted(inventory.get(candidate["name"], ()))
        if len(installed) != 1:
            classification = "MISSING" if not installed else "MULTIPLE_INSTALLED"
            support = "UNKNOWN"
            reasons.add("installed_version_inconclusive")
        else:
            classification = _change(installed[0], candidate["candidate_version"])
            support = _runtime(candidate, runtime)
            if classification == "UNORDERED" or support == "UNKNOWN":
                reasons.add("candidate_compatibility_unknown")
            if classification == "DOWNGRADE" or support == "UNSUPPORTED":
                reasons.add("candidate_requires_review")
        findings.append({
            "ecosystem": ecosystem,
            "name": candidate["name"],
            "installed_versions": installed,
            "candidate_version": candidate["candidate_version"],
            "change": classification,
            "runtime_support": support,
            "tests_required": [
                "lockfile_regeneration", "unit_regression",
                "integration_regression", "runtime_compatibility",
            ] if classification not in ("NO_CHANGE", "MISSING") else [],
        })
    status = "INCONCLUSIVE" if reasons else "REVIEW_REQUIRED" if any(
        item["change"] != "NO_CHANGE" for item in findings
    ) else "NO_CHANGES_IN_SUPPLIED_CANDIDATES"
    return {
        "schema": REPORT_SCHEMA, "status": status,
        "repo": meta["repo"], "ecosystem": ecosystem,
        "lock_sha256": meta["lock_sha256"],
        "checked_at": checked.isoformat().replace("+00:00", "Z"),
        "inventory_count": len(inventory),
        "findings": findings, "reasons": sorted(reasons),
        "candidate_source_verified": False,
        "latest_versions_verified": False,
        "dependency_constraints_verified": False,
        "vulnerability_scan": "NOT_RUN",
        "tests_executed": False,
        "changes_written": False,
        "pull_requests_created": False,
        "production_authorized": False,
        "recommendation_only": True,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline lockfile candidate analysis, no installs/network")
    parser.add_argument("--lockfile", type=Path)
    parser.add_argument("--candidates", type=Path)
    args = parser.parse_args(argv)
    if args.lockfile is None and args.candidates is None:
        print(json.dumps({"status": "NOT_EXECUTED"}))
        return 0
    if args.lockfile is None or args.candidates is None:
        print(json.dumps({"status": "REFUSED", "reason": "both_inputs_required"}))
        return 2
    try:
        raw = _file(args.lockfile, limit=MAX_LOCK_BYTES)
        meta = json.loads(_file(args.candidates, limit=MAX_CANDIDATE_BYTES))
        result = plan(args.lockfile.name, raw, meta)
    except DepPilotRefused as exc:
        print(json.dumps({"status": "REFUSED", "reason": str(exc)}))
        return 2
    except (ValueError, UnicodeError, RecursionError):
        print(json.dumps({"status": "REFUSED", "reason": "candidates_json_invalid"}))
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] == "NO_CHANGES_IN_SUPPLIED_CANDIDATES" else 2


if __name__ == "__main__":
    raise SystemExit(main())
