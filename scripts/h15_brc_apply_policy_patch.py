#!/usr/bin/env python3
"""Hermes hardening of pinned BRC: remove unsafe remotely callable tools.

Source-only operation on a disposable exact-SHA checkout. It does NOT enable
a remote command agent. OS sandbox is STILL REQUIRED before live operation.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from scripts.h15_remote_commander_candidate_audit import (
    AuditError, UPSTREAM_SHA, evaluate,
)

RELATIVE = Path("packages/agent/src/dispatcher.ts")
EDIT_RELATIVE = Path("packages/agent/src/core/tools/edit.ts")
DENIED_HANDLERS = {
    # Never expose remote config or historical tool arguments, which can
    # reveal policy internals or secret-bearing command prompts.
    "get_config": "  get_config: () => getConfig(),",
    "set_config_value": "  set_config_value: (a) => setConfigValue(a),",
    "get_recent_tool_calls": (
        "  get_recent_tool_calls: (a) => handlers.handleGetRecentToolCalls(a),"
    ),
    # The original encrypted transfer uses external tmpfiles.org hosting.
    "prepare_file_transfer": (
        "  prepare_file_transfer: (a) => handlers.handlePrepareFileTransfer(a),"
    ),
    "send_file_transfer": (
        "  send_file_transfer: (a) => handlers.handleSendFileTransfer(a),"
    ),
    "receive_file_transfer": (
        "  receive_file_transfer: (a) => handlers.handleReceiveFileTransfer(a),"
    ),
}
DENIED_TOOLS = tuple(DENIED_HANDLERS)
REMOTE_URL_DENIED = "HERMES_REMOTE_URL_FETCH_DENIED"
REMOTE_POLICY_DENIED = "HERMES_MCP_TOOL_DISABLED_BY_OWNER_POLICY"


def edit_conflict_errors(raw: str) -> str:
    """Keep the pinned no-write conflict branch, but report its MCP failure."""
    marker = "    if (count > 0 && count !== expectedReplacements) {"
    if raw.count(marker) != 1:
        raise AuditError("unreviewed_edit_conflict_branch")
    start = raw.index(marker)
    end = raw.find("\n    }", start)
    branch = raw[start:end] if end != -1 else ""
    if branch.count("        return {\n") != 1 or "isError" in branch:
        raise AuditError("unreviewed_edit_conflict_branch")
    changed = branch.replace("        return {\n", "        return {\n            isError: true,\n", 1)
    return raw[:start] + changed + raw[end:]


def apply(root: Path, *, sha: str = UPSTREAM_SHA) -> dict[str, object]:
    # Checks immutable source revision, license/NOTICE and all known risks.
    evaluate(root, sha=sha)
    path = root / RELATIVE
    edit_path = root / EDIT_RELATIVE
    if path.is_symlink() or not path.is_file():
        raise AuditError("unsafe_dispatcher")
    if edit_path.is_symlink() or not edit_path.is_file():
        raise AuditError("unsafe_edit_handler")
    raw = path.read_text(encoding="utf-8")
    old_import = "import { getConfig, setConfigValue } from './core/tools/config.js';"
    new_import = ""
    old_read = "  read_file: (a) => handlers.handleReadFile(a),"
    new_read = (
        "  read_file: (a) => a.isUrl === true\n"
        "    ? Promise.resolve({ isError: true, content: [{ type: 'text', "
        "text: '" + REMOTE_URL_DENIED + "' }] })\n"
        "    : handlers.handleReadFile(a),"
    )
    replacements = [(old_import, new_import), (old_read, new_read)]
    for tool, line in DENIED_HANDLERS.items():
        if raw.count(line) != 1:
            raise AuditError("hardened_handler_pattern_missing")
        replacements.append((line, ""))

    # Check ALL patterns before modifying even a single file.
    for old, new in replacements:
        if raw.count(old) != 1 or (new and new in raw):
            raise AuditError("unreviewed_dispatcher_change")

    updated = raw
    for old, new in replacements:
        updated = updated.replace(old, new)
    if any(("  " + tool + ":") in updated for tool in DENIED_TOOLS):
        raise AuditError("denied_handler_still_exposed")
    if updated == raw:
        raise AuditError("patch_has_no_effect")
    # Agent dispatcher is the authority: listTools only exports actual
    # handlers. Unknown MCP calls fail rather than deferring to a fallback.
    if "if (!handler) {" not in updated or "t.name in TOOL_HANDLERS" not in updated:
        raise AuditError("dispatcher_fallback_unreviewed")
    updated_edit = edit_conflict_errors(edit_path.read_text(encoding="utf-8"))
    path.write_text(updated, encoding="utf-8")
    edit_path.write_text(updated_edit, encoding="utf-8")
    return {
        "source_sha": sha,
        "status": "PATCHED_DISPOSABLE_SOURCE",
        "blocked_tools": list(DENIED_TOOLS),
        "external_url_read": "DENIED",
        "live_execution": "DENIED",
        "production_ready": False,
        "next_gate": "OS_SANDBOX_AND_NEGATIVE_E2E_REQUIRED",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--sha", default=UPSTREAM_SHA)
    args = parser.parse_args()
    try:
        result = apply(args.source_dir, sha=args.sha)
    except (AuditError, OSError, ValueError) as exc:
        reason = str(exc) if type(exc) is AuditError else type(exc).__name__
        print(json.dumps({"status": "REJECTED", "reason": reason}), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
