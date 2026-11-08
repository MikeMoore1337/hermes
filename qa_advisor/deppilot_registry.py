"""Opt-in public PyPI/npm metadata for offline DepPilot planning.

No package installs, credentials, proxies, redirects, retries, lockfile writes,
new subscriptions or automatic PRs. Registry metadata is not a compatibility
guarantee; source manifest constraints and integration tests remain required.
"""
from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from qa_advisor.deppilot import (
    _file, _name, _parse_lock, _version, DepPilotRefused,
    LOCKS, REPOS, MAX_LOCK_BYTES, plan,
)
from qa_advisor.github_public import public_opener

MAX_PACKAGES = 8
MAX_CALLS = 8
MAX_HTTP = 2_000_000
BOUNDS = re.compile(r"\s*(>=|<)\s*([0-9]+(?:\.[0-9]+){0,2})\s*\Z")


class RegistryUnavailable(ValueError):
    """Fixed error codes; never include package metadata, URL or credentials."""


def _bounded_name(value: str, ecosystem: str) -> str:
    try:
        return _name(value, ecosystem)
    except DepPilotRefused:
        raise RegistryUnavailable("invalid_package_name") from None


def _runtime_bounds(spec: Any) -> tuple[str | None, str | None]:
    """Conservative subset of PyPI/node specifiers. Unknown syntax stays UNKNOWN."""
    if type(spec) is not str or not 1 <= len(spec) <= 160:
        return None, None
    minimum = None
    maximum = None
    parts = spec.split(",")
    if not 1 <= len(parts) <= 6:
        return None, None
    for part in parts:
        match = BOUNDS.fullmatch(part)
        if not match:
            return None, None
        bound = match.group(2)
        if _version(bound) is None:
            return None, None
        value = ".".join(str(v) for v in _version(bound))
        if match.group(1) == ">=":
            if minimum is None or _version(value) > _version(minimum):
                minimum = value
        else:
            if maximum is None or _version(value) < _version(maximum):
                maximum = value
    if minimum is not None and maximum is not None and _version(minimum) >= _version(maximum):
        return None, None
    return minimum, maximum


class PublicRegistry:
    """Only documented, exact public metadata hosts, never arbitrary URLs."""

    def __init__(self, *, opener=None):
        self._opener = opener if opener is not None else public_opener()
        self.calls = 0

    def get(self, ecosystem: str, name: str) -> dict:
        name = _bounded_name(name, ecosystem)
        if ecosystem not in ("pypi", "npm"):
            raise RegistryUnavailable("ecosystem_invalid")
        if self.calls >= MAX_CALLS:
            raise RegistryUnavailable("request_budget_exceeded")
        self.calls += 1
        safe = urllib.parse.quote(name, safe="")
        uri = (f"https://pypi.org/pypi/{safe}/json" if ecosystem == "pypi"
               else f"https://registry.npmjs.org/{safe}/latest")
        req = urllib.request.Request(uri, method="GET", headers={
            "Accept": "application/json",
            "User-Agent": "Hermes-DepPilot-Readonly/1.0",
        })
        try:
            with self._opener.open(req, timeout=6) as reply:
                if reply.status != 200:
                    raise RegistryUnavailable("registry_unavailable")
                raw = reply.read(MAX_HTTP + 1)
        except urllib.error.HTTPError as exc:
            code = "registry_missing" if exc.code == 404 else (
                "registry_forbidden_or_limited" if exc.code in (401, 403, 429)
                else "registry_unavailable")
            raise RegistryUnavailable(code) from None
        except (OSError, TimeoutError, urllib.error.URLError):
            raise RegistryUnavailable("registry_network_unavailable") from None
        if len(raw) > MAX_HTTP:
            raise RegistryUnavailable("registry_response_oversized")
        try:
            data = json.loads(raw)
        except (ValueError, UnicodeError, RecursionError):
            raise RegistryUnavailable("registry_json_invalid") from None
        if type(data) is not dict:
            raise RegistryUnavailable("registry_shape_invalid")
        return data


def candidates_for(lock_name: str, lock_raw: bytes, *,
                   repo: str, runtime: str,
                   packages: list[str], source=None, now: datetime | None = None) -> dict:
    """Parse the actual lock, fetch only chosen packages, then run offline plan."""
    if type(repo) is not str or repo not in REPOS:
        raise RegistryUnavailable("target_repo_invalid")
    if type(runtime) is not str or _version(runtime) is None:
        raise RegistryUnavailable("runtime_invalid")
    if type(packages) is not list or not 1 <= len(packages) <= MAX_PACKAGES:
        raise RegistryUnavailable("package_window_invalid")
    if type(lock_raw) is not bytes or not 2 <= len(lock_raw) <= MAX_LOCK_BYTES:
        raise RegistryUnavailable("lockfile_invalid")
    try:
        ecosystem, installed = _parse_lock(lock_name, lock_raw)
    except DepPilotRefused:
        raise RegistryUnavailable("lockfile_invalid") from None
    names = [_bounded_name(item, ecosystem) for item in packages]
    if len(set(names)) != len(names) or any(name not in installed for name in names):
        raise RegistryUnavailable("selected_package_invalid")
    fetch = source if source is not None else PublicRegistry()
    metadata = []
    for name in sorted(names):
        response = fetch.get(ecosystem, name)
        if ecosystem == "pypi":
            info = response.get("info")
            if type(info) is not dict or info.get("yanked") is True:
                raise RegistryUnavailable("pypi_metadata_invalid")
            official_name = info.get("name")
            candidate_version = info.get("version")
            spec = info.get("requires_python")
        else:
            official_name = response.get("name")
            candidate_version = response.get("version")
            engines = response.get("engines")
            spec = engines.get("node") if type(engines) is dict else None
        if (type(official_name) is not str or _bounded_name(official_name, ecosystem) != name
                or type(candidate_version) is not str or not 1 <= len(candidate_version) <= 80):
            raise RegistryUnavailable("registry_identity_invalid")
        minimum, maximum = _runtime_bounds(spec)
        metadata.append({
            "ecosystem": ecosystem, "name": name,
            "candidate_version": candidate_version,
            "min_runtime": minimum,
            "max_runtime_exclusive": maximum,
        })
    stamp = now if now is not None else datetime.now(UTC)
    if type(stamp) is not datetime or stamp.tzinfo is None or stamp.utcoffset() is None:
        raise RegistryUnavailable("clock_invalid")
    spec = {
        "schema": "hermes-deppilot-candidates-v1",
        "repo": repo,
        "lock_sha256": hashlib.sha256(lock_raw).hexdigest(),
        "observed_at": stamp.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "runtime_version": runtime,
        "candidates": metadata,
    }
    result = plan(lock_name, lock_raw, spec, now=stamp.astimezone(UTC))
    # A bounded candidate list is not all dependencies and registry claims
    # do not establish manifest constraints, transitive safety or runtime GO.
    result["inventory_coverage"] = "SELECTED_PACKAGES_ONLY"
    result["source_transport"] = "PUBLIC_REGISTRY_READONLY"
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Opt-in public registry candidate precheck")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--lockfile", type=Path)
    parser.add_argument("--repository", choices=sorted(REPOS))
    parser.add_argument("--runtime")
    parser.add_argument("--package", action="append")
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"status": "NOT_EXECUTED"}))
        return 0
    try:
        if (args.lockfile is None or args.repository is None or args.runtime is None
                or args.package is None):
            raise RegistryUnavailable("arguments_invalid")
        raw = _file(args.lockfile, limit=MAX_LOCK_BYTES)
        result = candidates_for(
            args.lockfile.name, raw, repo=args.repository, runtime=args.runtime,
            packages=args.package,
        )
    except (DepPilotRefused, RegistryUnavailable):
        print(json.dumps({"status": "INCONCLUSIVE", "reason": "registry_or_evidence_unavailable",
                          "changes_written": False, "production_authorized": False}))
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
