"""Read a pinned ORIGINAL Harness2 task summary without executing a model.

No source execution, log import, database write, or credibility upgrade. The JSON
is untrusted external metadata, NOT measured Hermes quality or independent evidence.
"""
from __future__ import annotations

import hashlib
import json
import re
import stat
import subprocess
import sys
from pathlib import Path

PIN = "1cfe254e8d25b15f37048c3730134686abe60335"
ORIGIN = "https://github.com/google-research/harness2.git"
LIMIT = 128 * 1024
IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
STATUSES = frozenset({"running", "ok", "partial", "skipped", "base-failed"})


class UpstreamRejected(ValueError):
    """Fail without echoing untrusted source text or private paths."""


def parse_summary(raw: bytes) -> dict:
    if len(raw) > LIMIT:
        raise UpstreamRejected("FILE_TOO_LARGE")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise UpstreamRejected("MALFORMED_JSON") from exc
    fields = {"task_id", "domain", "k", "seed", "status", "base", "modes", "selections", "errors"}
    if type(data) is not dict or set(data) != fields:
        raise UpstreamRejected("UNSUPPORTED_UPSTREAM_SUMMARY_SCHEMA")
    task, domain, status = data["task_id"], data["domain"], data["status"]
    if (type(task) is not str or not IDENT.fullmatch(task)
            or type(domain) is not str or not IDENT.fullmatch(domain)
            or type(status) is not str or status not in STATUSES
            or type(data["k"]) is not int or not 1 <= data["k"] <= 100
            or (data["seed"] is not None and type(data["seed"]) is not int)
            or type(data["modes"]) is not dict
            or not set(data["modes"]).issubset({"agg", "seq"})
            or type(data["selections"]) is not dict
            or not set(data["selections"]).issubset({"agg", "seq"})
            or type(data["base"]) is not list
            or type(data["errors"]) is not list):
        raise UpstreamRejected("INVALID_UPSTREAM_FIELDS")
    return {
        "schema_version": 1,
        "source": "original-harness2-task-summary",
        "upstream_sha": PIN,
        "source_file_sha256": hashlib.sha256(raw).hexdigest(),
        "claimed_task_id": task,
        "claimed_domain": domain,
        "claimed_status": status,
        "budget_k": data["k"],
        "available_modes": sorted(data["modes"]),
        "native_execution_observed": False,
        "model_efficacy_verified": False,
        "owner_approved": False,
        "source_file_verified_as_genuine": False,
        "review_status": "SOURCE_METADATA_ONLY",
    }


def read_external_summary(relative: str, *, home: Path | None = None) -> dict:
    # Never expose an option for an arbitrary project or private-vault root.
    root = (home or Path.home()) / ".local/share/ai-development-toolkit" / ("harness2-" + PIN)
    source = root / "source"
    if source.is_symlink() or not source.is_dir() or root.is_symlink():
        raise UpstreamRejected("PINNED_SOURCE_NOT_INSTALLED")
    try:
        rev = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"],
                             capture_output=True, text=True, timeout=5, check=False)
        origin = subprocess.run(["git", "-C", str(source), "remote", "get-url", "origin"],
                                capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise UpstreamRejected("UPSTREAM_IDENTITY_UNAVAILABLE") from exc
    if rev.returncode or rev.stdout.strip() != PIN or origin.returncode or origin.stdout.strip() != ORIGIN:
        raise UpstreamRejected("UPSTREAM_IDENTITY_MISMATCH")
    if (not isinstance(relative, str) or "\\" in relative or relative.startswith("/")
            or not relative.startswith("runs/")):
        raise UpstreamRejected("UNSAFE_RELATIVE_PATH")
    parts = relative.split("/")
    if (len(parts) < 3 or any(x in {"", ".", ".."} for x in parts)
            or parts[-1] != "summary.json"):
        raise UpstreamRejected("UNSUPPORTED_ARTIFACT_PATH")
    target = source
    for part in parts:
        target = target / part
        if target.is_symlink():
            raise UpstreamRejected("SYMLINK_NOT_ALLOWED")
    if not target.is_file() or not target.resolve().is_relative_to(source.resolve()):
        raise UpstreamRejected("ARTIFACT_NOT_FOUND")
    info = target.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > LIMIT:
        raise UpstreamRejected("UNSAFE_ARTIFACT")
    with target.open("rb") as stream:
        raw = stream.read(LIMIT + 1)
    return parse_summary(raw)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python3 scripts/harness2_upstream_manifest.py runs/.../summary.json", file=sys.stderr)
        return 2
    try:
        report = read_external_summary(sys.argv[1])
    except (OSError, UpstreamRejected) as exc:
        # No untrusted file bodies, passwords or absolute paths in error messages.
        print(f"HARNESS2_SUMMARY_REJECTED: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
