#!/usr/bin/env python3
"""Pin and harden both BRC relay advertisement and invocation paths (#371).

An untrusted agent can advertise or send back any tool name. Even when the
honest agent removes dangerous handlers, the relay must independently reject
unapproved operations and read_file(isUrl=true). Tests are sandbox-only.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from scripts.h15_remote_commander_candidate_audit import (
    AuditError, UPSTREAM_SHA, evaluate,
)

SERVER = Path("packages/relay/src/mcp/server.ts")
INVOKE = Path("packages/relay/src/mcp/invoke.ts")
POLICY = Path("packages/relay/src/mcp/hermes-policy.ts")
SERVER_IMPORT = "import { invokeTool, listUserDevices, type InvokeContext } from './invoke.js';"
SERVER_LIST = (
    "  for (const d of online) for (const t of hub.get(d.deviceId)?.tools ?? []) "
    "if (!merged.has(t.name)) merged.set(t.name, { ...t, "
    "inputSchema: withDeviceId(t.inputSchema) });"
)
INVOKE_MARKER = "  const args = { ...(rawArgs ?? {}) };"
CATALOG = Path("packages/relay/src/mcp/hermes-tool-catalog.ts")
STATIC_LIST_MARKER = (
    "    const { online, tools } = liveTools(hub, store, ctx.userId);\n"
    "    return { tools: [{ ...LIST_DEVICES_TOOL, description: `${LIST_DEVICES_TOOL.description} ${online} device(s) currently online.` }, ...tools] };"
)
STATIC_LIST_REPLACEMENT = (
    "    const { online } = liveTools(hub, store, ctx.userId);\n"
    "    return { tools: [{ ...LIST_DEVICES_TOOL, description: `${LIST_DEVICES_TOOL.description} ${online} device(s) currently online.` },\n"
    "      ...pinnedToolCatalog().map(t => ({ ...t, inputSchema: withDeviceId(t.inputSchema) }))] };"
)
CATALOG_SOURCE = "/* Static MCP tool advertisement for ChatGPT custom connectors.\n * Import only the reviewed, compiled BRC agent tool SCHEMA module; never\n * import the agent dispatcher or execute agent handlers on the relay.\n * This catalog is independent of agent online state, so an OAuth connection\n * made before pairing can discover the same operations after pairing.\n * Actual calls still require the relay's immutable allowlist, owner/device\n * authorization, an online non-paused agent, and its OS sandbox.\n */\nimport { isPermittedRemoteTool } from './hermes-policy.js';\n\ntype CatalogTool = {\n  name: string;\n  description: string;\n  inputSchema: unknown;\n  annotations?: Record<string, unknown>;\n};\n\nconst compiledAgentSchema = new URL('../../../agent/dist/core/tool-definitions.js', import.meta.url);\nconst schemaModule = await import(compiledAgentSchema.href) as {\n  buildToolDefinitions?: () => CatalogTool[];\n};\nif (typeof schemaModule.buildToolDefinitions !== 'function') {\n  throw Error('HERMES_PINNED_AGENT_SCHEMA_UNAVAILABLE');\n}\nconst definitions = schemaModule.buildToolDefinitions();\nif (!Array.isArray(definitions)) throw Error('HERMES_PINNED_AGENT_SCHEMA_INVALID');\nconst selected = definitions.filter(t => isPermittedRemoteTool(t.name, {}));\nconst names = new Set(selected.map(t => t.name));\nif (names.size !== selected.length ||\n    !['read_file', 'write_file', 'start_process'].every(t => names.has(t))) {\n  throw Error('HERMES_PINNED_TOOL_CATALOG_MISSING_OR_DUPLICATE');\n}\nif (selected.some(t => !t.description || !t.inputSchema ||\n    typeof t.inputSchema !== 'object')) {\n  throw Error('HERMES_PINNED_TOOL_CATALOG_INVALID_SCHEMA');\n}\nconst catalog = selected.sort((a, b) => a.name.localeCompare(b.name));\n\nexport function pinnedToolCatalog(): CatalogTool[] {\n  return catalog;\n}\n"

POLICY_SOURCE = """/* Immutable Hermes MCP gateway policy. Do not remotely expose config or
 * history, unreviewed tools, external transfers, or URL reads. This filter
 * is not a replacement for the per-device OS shell/file sandbox.
 */
const ALLOWED = new Set([
  'start_process', 'read_process_output', 'interact_with_process',
  'force_terminate', 'list_sessions', 'list_processes', 'kill_process',
  'read_file', 'read_multiple_files', 'write_file', 'write_pdf',
  'create_directory', 'list_directory', 'move_file', 'get_file_info',
  'edit_block', 'start_search', 'get_more_search_results',
  'stop_search', 'list_searches',
]);

export function isPermittedRemoteTool(name: string, args: Record<string, unknown>): boolean {
  if (!ALLOWED.has(name)) return false;
  if (name === 'read_file' && args.isUrl === true) return false;
  return true;
}
"""


def apply(root: Path, *, sha: str = UPSTREAM_SHA) -> dict[str, object]:
    if sha != UPSTREAM_SHA:
        raise AuditError("unreviewed_upstream_sha")
    evaluate(root, sha=sha)
    locations = (SERVER, INVOKE, POLICY, CATALOG)
    for name in locations:
        path = root / name
        if path.is_symlink() or not path.parent.is_dir():
            raise AuditError("relay_policy_path_unsafe")
    if (root / POLICY).exists() or (root / CATALOG).exists():
        raise AuditError("policy_already_present")
    sp = root / SERVER
    ip = root / INVOKE
    if not sp.is_file() or not ip.is_file() or sp.stat().st_size > 100000 or ip.stat().st_size > 100000:
        raise AuditError("relay_source_invalid")
    server = sp.read_text(encoding="utf-8")
    invoke = ip.read_text(encoding="utf-8")
    if (server.count(SERVER_IMPORT) != 1 or server.count(SERVER_LIST) != 1
        or server.count(STATIC_LIST_MARKER) != 1 or invoke.count(INVOKE_MARKER) != 1):
        raise AuditError("relay_policy_source_changed")
    if "import { isPermittedRemoteTool }" in server + invoke:
        raise AuditError("relay_policy_already_patched")
    server = server.replace(
        SERVER_IMPORT, SERVER_IMPORT + "\nimport { isPermittedRemoteTool } from './hermes-policy.js';" \
        + "\nimport { pinnedToolCatalog } from './hermes-tool-catalog.js';"
    )
    server = server.replace(
        SERVER_LIST,
        SERVER_LIST.replace(
            "if (!merged.has(t.name))", "if (isPermittedRemoteTool(t.name, {}) && !merged.has(t.name))"
        ),
    )
    server = server.replace(STATIC_LIST_MARKER, STATIC_LIST_REPLACEMENT)
    invoke = invoke.replace(
        "import { createHash } from 'node:crypto';",
        "import { createHash } from 'node:crypto';\nimport { isPermittedRemoteTool } from './hermes-policy.js';",
    )
    invoke = invoke.replace(
        INVOKE_MARKER,
        INVOKE_MARKER + "\n  if (!isPermittedRemoteTool(tool, args)) {\n"
        "    return { ok: false, status: 403, message: 'HERMES_REMOTE_TOOL_DENIED' };\n  }",
    )
    if server == sp.read_text(encoding="utf-8") or invoke == ip.read_text(encoding="utf-8"):
        raise AuditError("relay_policy_no_effect")
    # Never accept a source change requiring an unreviewed write.
    (root / POLICY).write_text(POLICY_SOURCE, encoding="utf-8")
    (root / CATALOG).write_text(CATALOG_SOURCE, encoding="utf-8")
    sp.write_text(server, encoding="utf-8")
    ip.write_text(invoke, encoding="utf-8")
    return {
        "status": "GATEWAY_IMMUTABLE_ALLOWLIST_PATCHED",
        "advertisement_policy": "STABLE_PINNED_AGENT_SCHEMAS",
        "tool_discovery_before_device_pairing": "SUPPORTED",
        "invocation_policy": "ALLOWLIST",
        "external_url_reads": "DENIED",
        "production_ready": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--sha", default=UPSTREAM_SHA)
    args = parser.parse_args()
    try:
        output = apply(args.source_dir, sha=args.sha)
    except (AuditError, OSError, ValueError) as exc:
        reason = str(exc) if type(exc) is AuditError else type(exc).__name__
        print(json.dumps({"status": "REJECTED", "reason": reason}), file=sys.stderr)
        return 2
    print(json.dumps(output, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
