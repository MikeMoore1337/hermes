#!/usr/bin/env python3
"""Offline, fail-closed source provenance and risk inventory for H-15 #297.

This performs NO network access, installation, pairing or remote execution.
It is deliberately not an approval to activate a third-party agent.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys

UPSTREAM_SHA = "cbe511702dd0147650353c29ac6ab1decd8afda1"
UPSTREAM_URL = "https://github.com/shahidx0x/better-remote-commander"
REQUIRED = (
    "LICENSE",
    "NOTICE",
    "package.json",
    "pnpm-lock.yaml",
    "packages/relay/src/app.ts",
    "packages/relay/src/mcp/invoke.ts",
    "packages/agent/src/cli.ts",
    "packages/agent/src/dispatcher.ts",
    "packages/agent/src/core/config-manager.ts",
    "packages/agent/src/core/tools/improved-process-tools.ts",
)
TOOL_MARKERS = {
    "remote_shell": "start_process:",
    "interactive_process": "interact_with_process:",
    "file_read": "read_file:",
    "file_write": "write_file:",
    "editable_policy": "set_config_value:",
}


class AuditError(ValueError):
    pass


def safe_read(root: Path, name: str) -> str:
    target = root
    for part in Path(name).parts:
        target = target / part
        if target.is_symlink():
            raise AuditError("symlink_in_candidate")
    if not target.is_file() or target.stat().st_size > 5_000_000:
        raise AuditError("candidate_file_missing_or_oversize")
    try:
        return target.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise AuditError("candidate_file_unreadable") from exc


def evaluate(root: Path, *, sha: str = UPSTREAM_SHA) -> dict[str, object]:
    if sha != UPSTREAM_SHA:
        raise AuditError("unreviewed_upstream_sha")
    if root.is_symlink() or not root.is_dir():
        raise AuditError("candidate_root_invalid")
    try:
        head = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True, timeout=4,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise AuditError("unverified_git_checkout") from exc
    if head != sha:
        raise AuditError("upstream_revision_mismatch")

    files = {name: safe_read(root, name) for name in REQUIRED}
    pkg = json.loads(files["package.json"])
    if pkg.get("license") != "MIT" or pkg.get("packageManager") != "pnpm@11.24.0":
        raise AuditError("upstream_license_or_lock_toolchain_changed")
    if "MIT License" not in files["LICENSE"] or "Desktop Commander" not in files["NOTICE"]:
        raise AuditError("license_notice_missing")
    if "StreamableHTTPServerTransport" not in files["packages/relay/src/app.ts"]:
        raise AuditError("streamable_http_not_verified")
    if "mcpAuthRouter" not in files["packages/relay/src/app.ts"]:
        raise AuditError("oauth_not_verified")
    if "store.audit(" not in files["packages/relay/src/mcp/invoke.ts"]:
        raise AuditError("audit_path_not_verified")
    dispatcher = files["packages/agent/src/dispatcher.ts"]
    markers = {key: marker in dispatcher for key, marker in TOOL_MARKERS.items()}
    if not all(markers.values()):
        raise AuditError("expected_remote_tool_missing")
    manager = files["packages/agent/src/core/config-manager.ts"]
    shell = files["packages/agent/src/core/tools/improved-process-tools.ts"]
    risks = {
        "mcp_can_change_agent_policy": markers["editable_policy"],
        "remote_shell_can_access_beyond_file_allowlist": (
            "startProcess" in shell and "allowedDirectories" in manager
        ),
        "agent_default_allowed_directories_empty": "allowedDirectories: []" in manager,
        "remote_terminal_has_node_execution_path": "executeNodeCode" in shell,
    }
    if not all(risks.values()):
        # If upstream semantics change, require an independent review, never
        # infer that a missing risk marker makes the release production-safe.
        raise AuditError("candidate_risk_signatures_changed_review_required")
    return {
        "status": "SOURCE_PIN_VERIFIED",
        "upstream": UPSTREAM_URL,
        "sha": sha,
        "license": "MIT",
        "mcp": "STREAMABLE_HTTP_OAUTH",
        "tool_categories": sorted(markers),
        "security_findings": risks,
        "live_execution": "DENIED",
        "production_ready": False,
        "next_gate": "OS_SANDBOX_AND_NEGATIVE_E2E_REQUIRED",
        "provider_tool_call_quota": "NO_VENDOR_RELAY",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--sha", default=UPSTREAM_SHA)
    args = parser.parse_args()
    try:
        report = evaluate(args.source_dir, sha=args.sha)
    except (AuditError, OSError, ValueError) as exc:
        reason = str(exc) if type(exc) is AuditError else type(exc).__name__
        print(json.dumps({"status": "REJECTED", "reason": reason}), file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
