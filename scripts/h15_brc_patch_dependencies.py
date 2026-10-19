#!/usr/bin/env python3
"""Apply narrowly reviewed dependency overrides to a disposable pinned BRC checkout.

No package installation or network access. CI regenerates pnpm-lock.yaml, then
performs full OAuth/MCP/native-device and image-scanner regressions. Never edits
the owner's VPS or the upstream repository.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import re
import sys

from scripts.h15_remote_commander_candidate_audit import AuditError, UPSTREAM_SHA

WORKSPACE = "pnpm-workspace.yaml"
ORIGINAL = """packages:
  - 'packages/*'
allowBuilds:
  puppeteer: false
  sharp: true
"""
PATCHED = ORIGINAL + """overrides:
  '@modelcontextprotocol/sdk': 1.31.0
  proxy-addr: 2.0.8
  undici: 6.28.1
  sharp: 0.35.5
  'brace-expansion@^1.0.0': 1.1.21
  'brace-expansion@^2.0.0': 2.1.7
  'brace-expansion@^5.0.0': 5.0.12
"""
EXPECTED_VERSIONS = {
    "@modelcontextprotocol/sdk": "1.31.0",
    "proxy-addr": "2.0.8",
    "undici": "6.28.1",
    "sharp": "0.35.5",
}
BRACE_FIXED = ("1.1.21", "2.1.7", "5.0.12")
BRACE_OLD = ("1.1.18", "2.1.4", "5.0.9")


def apply(root: Path) -> dict[str, object]:
    if root.is_symlink() or not root.is_dir():
        raise AuditError("invalid_source_directory")
    try:
        sha = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True, check=True, text=True, timeout=5,
        ).stdout.strip()
    except (OSError, subprocess.TimeoutExpired, subprocess.CalledProcessError) as exc:
        raise AuditError("unverified_upstream_checkout") from exc
    if sha != UPSTREAM_SHA:
        raise AuditError("wrong_upstream_revision")
    target = root / WORKSPACE
    if target.is_symlink() or not target.is_file():
        raise AuditError("unsafe_pnpm_workspace")
    current = target.read_text(encoding="utf-8")
    if current != ORIGINAL:
        raise AuditError("unreviewed_dependency_configuration")
    target.write_text(PATCHED, encoding="utf-8")
    return {
        "source_revision": UPSTREAM_SHA,
        "status": "DISPOSABLE_SOURCE_PATCHED",
        "packages": EXPECTED_VERSIONS,
        "package_install_executed": False,
        "production_approved": False,
    }


def validate_lock(root: Path) -> None:
    """Verify pnpm lock regeneration and exact vulnerable version retirement."""
    lock = root / "pnpm-lock.yaml"
    if lock.is_symlink() or not lock.is_file():
        raise AuditError("unsafe_pnpm_lockfile")
    raw = lock.read_text(encoding="utf-8")
    if not 3000 < len(raw) < 2_000_000:
        raise AuditError("unexpected_lockfile_length")
    # pnpm YAML quotes scoped package keys (e.g. '@scope/name@1.31.0':)
    # while unscoped keys can remain bare (proxy-addr@2.0.8:).
    def has_key(name: str, version: str) -> bool:
        key = re.escape(name + "@" + version)
        return re.search(r"(?m)^  ['\\\"]?" + key + r"['\\\"]?:", raw) is not None

    for key, version in EXPECTED_VERSIONS.items():
        if not has_key(key, version):
            raise AuditError("fixed_version_absent")
    for version in BRACE_FIXED:
        if not has_key("brace-expansion", version):
            raise AuditError("fixed_brace_expansion_branch_absent")
    for key, old in (
        ("@modelcontextprotocol/sdk", "1.30.0"),
        ("proxy-addr", "2.0.7"),
        ("undici", "6.28.0"),
        ("sharp", "0.34.5"),
        *(("brace-expansion", version) for version in BRACE_OLD),
    ):
        if has_key(key, old):
            raise AuditError("vulnerable_version_remains")
    if (root / WORKSPACE).read_text(encoding="utf-8") != PATCHED:
        raise AuditError("dependency_override_missing")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--check-lock", action="store_true")
    args = parser.parse_args()
    try:
        if args.check_lock:
            validate_lock(args.source_dir)
            print("H15_BRC_DEPENDENCY_LOCK=FIXED_VERSIONS_PINNED")
        else:
            apply(args.source_dir)
            print("H15_BRC_DISPOSABLE_OVERRIDES=APPLIED")
        print("H15_BRC_UPSTREAM_REVISION=" + UPSTREAM_SHA)
        print("H15_BRC_PRODUCTION_APPROVED=NO")
    except AuditError as exc:
        # AuditError reasons are fixed control-plane codes, never user input.
        print("H15_BRC_DEPENDENCY_PATCH=REJECTED_" + str(exc), file=sys.stderr)
        return 2
    except (OSError, UnicodeError):
        print("H15_BRC_DEPENDENCY_PATCH=REJECTED_IO", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
