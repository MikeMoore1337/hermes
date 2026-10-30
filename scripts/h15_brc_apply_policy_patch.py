#!/usr/bin/env python3
"""Hermes hardening of pinned BRC: remove unsafe remotely callable tools.

Source-only operation on a disposable exact-SHA checkout. It does NOT enable
a remote command agent. OS sandbox is STILL REQUIRED before live operation.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

from scripts.h15_remote_commander_candidate_audit import (
    AuditError, UPSTREAM_SHA, evaluate,
)

RELATIVE = Path("packages/agent/src/dispatcher.ts")
EDIT_RELATIVE = Path("packages/agent/src/core/tools/edit.ts")
FILESYSTEM_RELATIVE = Path("packages/agent/src/core/tools/filesystem.ts")
TERMINAL_RELATIVE = Path("packages/agent/src/core/terminal-manager.ts")
TYPES_RELATIVE = Path("packages/agent/src/core/types.ts")
PROCESS_TOOLS_RELATIVE = Path("packages/agent/src/core/tools/improved-process-tools.ts")
SEARCH_RELATIVE = Path("packages/agent/src/core/search-manager.ts")
SEARCH_HANDLERS_RELATIVE = Path("packages/agent/src/core/handlers/search-handlers.ts")
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
FILE_MUTATIONS = ("write_file", "write_pdf", "create_directory", "move_file", "edit_block")


def guard_file_mutations(raw: str) -> str:
    """Fail concurrent MCP mutations closed within one agent dispatcher."""
    states = list(re.finditer(r"(?m)^let cachedDefs(?:: ToolDefinition\[\] \| null)? = null;$", raw))
    entries = list(re.finditer(r"(?m)^([ ]+)try \{\n([ ]+)const result = \(await handler\(args \?\? \{\}\)\)(?: as ToolResult)?;", raw))
    if (len(states) != 1 or len(entries) != 1 or "HERMES_FILE_MUTATION_BUSY" in raw
            or any(len(re.findall(rf"(?m)^[ \t]+{name}:[ \t]*\(", raw)) != 1 for name in FILE_MUTATIONS)):
        raise AuditError("unreviewed_file_mutation_dispatcher")
    state, entry = states[0], entries[0]
    indent, inner = entry.groups()
    error = "return { content: [{ type: 'text', text: `Error in ${name}: ${message}` }], isError: true };"
    tail = inner + error + "\n" + indent + "}\n}"
    if raw.count(tail) != 1:
        raise AuditError("unreviewed_file_mutation_dispatcher")
    declaration = ("const h454FileMutations = new Set([" + ", ".join(repr(name) for name in FILE_MUTATIONS) + "]);\n"
                   "let h454FileMutationBusy = false;\n")
    guard = (indent + "const h454Mutation = h454FileMutations.has(name);\n"
             + indent + "if (h454Mutation && h454FileMutationBusy) {\n"
             + inner + "void usageTracker.trackFailure(name);\n"
             + inner + "return { content: [{ type: 'text', text: 'HERMES_FILE_MUTATION_BUSY: "
             "another file mutation is in progress; retry after it completes.' }], isError: true };\n"
             + indent + "}\n" + indent + "if (h454Mutation) h454FileMutationBusy = true;\n")
    finish = (inner + error + "\n" + indent + "} finally {\n"
              + inner + "if (h454Mutation) h454FileMutationBusy = false;\n" + indent + "}\n}")
    raw = raw[:state.start()] + declaration + raw[state.start():]
    entry = re.search(r"(?m)^([ ]+)try \{\n([ ]+)const result = \(await handler\(args \?\? \{\}\)\)(?: as ToolResult)?;", raw)
    if entry is None:
        raise AuditError("unreviewed_file_mutation_dispatcher")
    return raw[:entry.start()] + guard + raw[entry.start():].replace(tail, finish, 1)


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


def search_timeout_errors(manager: str, handlers: str) -> tuple[str, str]:
    """Preserve partial results without presenting a timed-out search as complete."""
    changes = (
        ("        if (!session.isComplete && !session.process.killed) {\n"
         "          session.process.kill('SIGTERM');",
         "        if (!session.isComplete && !session.process.killed) {\n"
         "          session.isError = true;\n"
         "          session.wasIncomplete = true;\n"
         "          session.error = 'HERMES_SEARCH_TIMEOUT: results are incomplete; narrow the path or increase timeout_ms.';\n"
         "          session.process.kill('SIGTERM');"),
        ("      if (session.totalMatches > 0) {\n        session.isError = false;",
         "      if (session.totalMatches > 0 && !session.wasIncomplete) {\n        session.isError = false;"),
    )
    for old, new in changes:
        if manager.count(old) != 1:
            raise AuditError("unreviewed_search_timeout_branch")
        manager = manager.replace(old, new, 1)

    markers = ("export async function handleStartSearch(",
               "export async function handleGetMoreSearchResults(",
               "export async function handleStopSearch(")
    if any(handlers.count(marker) != 1 for marker in markers):
        raise AuditError("unreviewed_search_timeout_handlers")
    first, second, third = (handlers.index(marker) for marker in markers)
    parts = [handlers[:first], handlers[first:second], handlers[second:third], handlers[third:]]
    for index, value, running in ((1, "result", "RUNNING"), (2, "results", "IN PROGRESS")):
        changes = (
            (f"{value}.isComplete ? 'COMPLETED' : '{running}'",
             f"{value}.isError ? 'INCOMPLETE' : {value}.isComplete ? 'COMPLETED' : '{running}'"),
            ("      output += `\\n✅ Search completed.`;",
             f"      output += {value}.isError\n"
             "        ? `\\n⚠️ Search incomplete. Results may be partial; narrow the path or increase timeout_ms.`\n"
             "        : `\\n✅ Search completed.`;"),
            ('      content: [{ type: "text", text: output }],',
             f'      isError: {value}.isError,\n      content: [{{ type: "text", text: output }}],'),
        )
        for old, new in changes:
            if parts[index].count(old) != 1:
                raise AuditError("unreviewed_search_timeout_handlers")
            parts[index] = parts[index].replace(old, new, 1)
    old = "      if (results.wasIncomplete) {"
    if parts[2].count(old) != 1:
        raise AuditError("unreviewed_search_timeout_handlers")
    parts[2] = parts[2].replace(old, "      if (results.wasIncomplete && !results.isError) {", 1)
    return manager, "".join(parts)


def unknown_birthtime(raw: str) -> str:
    """Do not present an ambiguous Unix-epoch birthtime as a known date."""
    field = "        created: fileInfo.created ?? fallbackInfo.created,\n"
    marker = "    // Add type-specific metadata from file handler\n"
    if (raw.count(field) != 1 or raw.count(marker) != 1 or raw.index(field) > raw.index(marker)
            or "unavailable_or_epoch" in raw):
        raise AuditError("unreviewed_file_info_birthtime")
    change = ("    if (info.created instanceof Date && info.created.getTime() === 0) {\n"
              "        info.created = null;\n"
              "        info.createdStatus = 'unavailable_or_epoch';\n"
              "    }\n\n")
    return raw.replace(marker, change + marker, 1)


def safe_termination(manager: str, tools: str) -> tuple[str, str]:
    """Keep escalation bound to its session and expose unsuccessful requests."""
    start, end = "forceTerminate(pid", "listActiveSessions()"
    if manager.count(start) != 1 or manager.count(end) != 1:
        raise AuditError("unreviewed_terminal_termination")
    first, last = manager.index(start), manager.index(end)
    if first >= last:
        raise AuditError("unreviewed_terminal_termination")
    branch = manager[first:last]
    initial = r"(?m)^([ ]*)session\.process\.kill\('SIGINT'\);$"
    initial_matches = list(re.finditer(initial, branch))
    if len(initial_matches) != 1:
        raise AuditError("unreviewed_terminal_termination")
    match = initial_matches[0]
    indent = match.group(1)
    replacement = (indent + "if (!session.process.kill('SIGINT')) {\n"
                   + indent + "  return false;\n" + indent + "}")
    branch = branch[:match.start()] + replacement + branch[match.end():]
    pattern = r"(?m)^([ ]*)if \(this\.sessions\.has\(pid\)\) \{\n([ ]*)session\.process\.kill\('SIGKILL'\);\n\1\}"
    matches = list(re.finditer(pattern, branch))
    if len(matches) != 1:
        raise AuditError("unreviewed_terminal_termination")
    match = matches[0]
    indent, inner = match.groups()
    replacement = (indent + "if (this.sessions.get(pid) === session) {\n"
                   + inner + "try { if (!session.process.kill('SIGKILL')) console.error('HERMES_TERMINATION_ESCALATION_FAILED'); }\n"
                   + inner + "catch { console.error('HERMES_TERMINATION_ESCALATION_FAILED'); }\n"
                   + indent + "}")
    branch = branch[:match.start()] + replacement + branch[match.end():]
    manager = manager[:first] + branch + manager[last:]

    first_marker, last_marker = "export async function forceTerminate(", "export async function listSessions("
    if tools.count(first_marker) != 1 or tools.count(last_marker) != 1:
        raise AuditError("unreviewed_terminal_termination")
    first, last = tools.index(first_marker), tools.index(last_marker)
    if first >= last:
        raise AuditError("unreviewed_terminal_termination")
    branch = tools[first:last]
    pattern = r"(?m)^([ ]*)const success = terminalManager\.forceTerminate\(pid\);\n\1return \{\n"
    matches = list(re.finditer(pattern, branch))
    old = "No active session found for PID ${pid}"
    success = "Successfully initiated termination of session ${pid}"
    if (len(matches) != 1 or branch.count(old) != 1 or branch.count(success) != 1
            or "isError: !success" in branch):
        raise AuditError("unreviewed_terminal_termination")
    match = matches[0]
    indent = match.group(1)
    branch = (branch[:match.end()] + indent + indent + "isError: !success,\n" + branch[match.end():])
    branch = branch.replace(old, "No active session or unable to initiate termination for PID ${pid}", 1)
    branch = branch.replace(success, success + ". Only the tracked process is signaled; descendants may remain.", 1)
    return manager, tools[:first] + branch + tools[last:]


def bounded_timing(manager: str, tools: str, types: str) -> tuple[str, str, str]:
    """Bound verbose event details and stop collecting after the start response."""
    cap = "const MAX_WAIT_OUTPUT_CHARS = 2 * 1024 * 1024;"
    manager_events = "const outputEvents: OutputEvent[] = [];"
    manager_record = "if (collectTiming) {\n          outputEvents.push({"
    manager_match = "if (collectTiming && outputEvents.length > 0) {"
    tool_import = "import { terminalManager, MAX_BUFFERED_OUTPUT_CHARS } from '../terminal-manager.js';"
    tool_events = "const outputEvents: any[] = [];"
    tool_record = "if (verbose_timing) {\n              outputEvents.push({"
    tool_match = "if (verbose_timing && outputEvents.length > 0) {"
    result = "outputEvents: outputEvents.length > 0 ? outputEvents : undefined"
    formatter = "  if (timing.outputEvents && timing.outputEvents.length > 0) {"
    title = "Output Events (${timing.outputEvents.length} total):"
    type_field = "  outputEvents?: OutputEvent[];"
    if (manager.count(cap) != 1 or manager.count(manager_events) != 1 or
            manager.count(manager_record) != 2 or manager.count(manager_match) != 1 or
            manager.count("source: 'stdout',") != 1 or manager.count("source: 'stderr',") != 1 or
            manager.count(result) != 1 or tools.count(tool_import) != 1 or
            tools.count(tool_events) != 1 or tools.count(tool_record) != 1 or
            tools.count("source: 'periodic_poll',") != 1 or tools.count(tool_match) != 1 or
            tools.count(result) != 1 or tools.count(formatter) != 1 or tools.count(title) != 1 or
            types.count(type_field) != 1 or "MAX_HERMES_TIMING_EVENTS" in manager or
            "outputEventsTruncated" in manager or "outputEventsTruncated" in tools or
            "outputEventsTruncated" in types):
        raise AuditError("unreviewed_timing_events")
    manager = manager.replace(cap, "export const MAX_HERMES_TIMING_EVENTS = 128;\n" + cap, 1)
    manager = manager.replace(manager_events, manager_events + "\n    let outputEventsTruncated = false;", 1)
    manager = manager.replace(manager_record,
        "if (collectTiming && !resolved) {\n"
        "          if (outputEvents.length >= MAX_HERMES_TIMING_EVENTS) { outputEventsTruncated = true; }\n"
        "          else outputEvents.push({", 2)
    manager = manager.replace(manager_match,
        "if (collectTiming && !resolved && !outputEventsTruncated && outputEvents.length > 0) {", 1)
    manager = manager.replace(result, result + ",\n            outputEventsTruncated", 1)
    tools = tools.replace(tool_import,
        "import { terminalManager, MAX_BUFFERED_OUTPUT_CHARS, MAX_HERMES_TIMING_EVENTS } from '../terminal-manager.js';", 1)
    tools = tools.replace(tool_events, tool_events + "\n  let outputEventsTruncated = false;", 1)
    tools = tools.replace(tool_record,
        "if (verbose_timing) {\n"
        "              if (outputEvents.length >= MAX_HERMES_TIMING_EVENTS) { outputEventsTruncated = true; }\n"
        "              else outputEvents.push({", 1)
    tools = tools.replace(tool_match,
        "if (verbose_timing && !outputEventsTruncated && outputEvents.length > 0) {", 1)
    tools = tools.replace(result, result + ",\n        outputEventsTruncated", 1)
    tools = tools.replace(formatter,
        "  if (timing.outputEventsTruncated) {\n"
        "    msg += `\\n  HERMES_TIMING_EVENTS_TRUNCATED: first ${MAX_HERMES_TIMING_EVENTS} events recorded.\\n`;\n"
        "  }\n" + formatter, 1)
    tools = tools.replace(title, "Output Events (${timing.outputEvents.length} recorded):", 1)
    types = types.replace(type_field, type_field + "\n  outputEventsTruncated?: boolean;", 1)
    return manager, tools, types


def apply(root: Path, *, sha: str = UPSTREAM_SHA) -> dict[str, object]:
    # Checks immutable source revision, license/NOTICE and all known risks.
    evaluate(root, sha=sha)
    path = root / RELATIVE
    edit_path = root / EDIT_RELATIVE
    filesystem_path = root / FILESYSTEM_RELATIVE
    terminal_path = root / TERMINAL_RELATIVE
    types_path = root / TYPES_RELATIVE
    process_tools_path = root / PROCESS_TOOLS_RELATIVE
    search_path = root / SEARCH_RELATIVE
    search_handlers_path = root / SEARCH_HANDLERS_RELATIVE
    if path.is_symlink() or not path.is_file():
        raise AuditError("unsafe_dispatcher")
    if edit_path.is_symlink() or not edit_path.is_file():
        raise AuditError("unsafe_edit_handler")
    if filesystem_path.is_symlink() or not filesystem_path.is_file():
        raise AuditError("unsafe_filesystem_handler")
    if any(p.is_symlink() or not p.is_file() for p in (terminal_path, process_tools_path, types_path)):
        raise AuditError("unsafe_terminal_handler")
    if any(p.is_symlink() or not p.is_file() for p in (search_path, search_handlers_path)):
        raise AuditError("unsafe_search_handler")
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
    updated = guard_file_mutations(updated)
    updated_edit = edit_conflict_errors(edit_path.read_text(encoding="utf-8"))
    updated_filesystem = unknown_birthtime(filesystem_path.read_text(encoding="utf-8"))
    updated_terminal, updated_process_tools = safe_termination(
        terminal_path.read_text(encoding="utf-8"), process_tools_path.read_text(encoding="utf-8"))
    updated_terminal, updated_process_tools, updated_types = bounded_timing(
        updated_terminal, updated_process_tools, types_path.read_text(encoding="utf-8"))
    updated_search, updated_search_handlers = search_timeout_errors(
        search_path.read_text(encoding="utf-8"), search_handlers_path.read_text(encoding="utf-8"))
    path.write_text(updated, encoding="utf-8")
    edit_path.write_text(updated_edit, encoding="utf-8")
    filesystem_path.write_text(updated_filesystem, encoding="utf-8")
    terminal_path.write_text(updated_terminal, encoding="utf-8")
    types_path.write_text(updated_types, encoding="utf-8")
    process_tools_path.write_text(updated_process_tools, encoding="utf-8")
    search_path.write_text(updated_search, encoding="utf-8")
    search_handlers_path.write_text(updated_search_handlers, encoding="utf-8")
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
