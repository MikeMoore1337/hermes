"""H15 #454: source-only patch for owner-scoped native READ tools on hardened BRC.

Apply ONLY after the existing pinned gateway and workspace router patches,
and ONLY in an isolated disposable checkout. No production activation.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

from scripts.h15_remote_commander_candidate_audit import UPSTREAM_SHA, AuditError, evaluate

MCP = Path("packages/relay/src/mcp")
IMPORT = "import { LIST_WORKSPACES_TOOL, RESOLVE_WORKSPACE_TOOL, listApprovedWorkspaces, resolveApprovedWorkspace } from './hermes-workspaces.js';"
LIST = ("      LIST_WORKSPACES_TOOL, RESOLVE_WORKSPACE_TOOL] };")
CALL = "    const out = await invokeTool(hub, store, ctx, name, args as Record<string, unknown> | undefined);"
NATIVE_IMPORT = "import { NATIVE_TOOLS, invokeOwnerNativeRead } from './hermes-native-read.js';"
NATIVE_CALL = """    if (name === 'native_file_read' || name === 'native_file_stat' || name === 'native_file_list') {
      // No generic deviceId dispatch, no shell grants, no unpaired host reads.
      return await invokeOwnerNativeRead(hub, store, ctx, name, args);
    }
"""
NATIVE_LIST = "      LIST_WORKSPACES_TOOL, RESOLVE_WORKSPACE_TOOL, ...NATIVE_TOOLS] };"

def apply(root: Path, *, sha: str = UPSTREAM_SHA) -> dict[str, object]:
    if sha != UPSTREAM_SHA:
        raise AuditError("unreviewed_upstream_sha")
    evaluate(root, sha=sha)
    server = root / MCP / "server.ts"
    target = root / MCP / "hermes-native-read.ts"
    dependencies = (MCP / "hermes-workspaces.ts", MCP / "hermes-policy.ts",
                    MCP / "hermes-tool-catalog.ts", MCP / "invoke.ts")
    template = Path(__file__).resolve().parents[1] / "deploy/h15/hermes-native-read.template.ts"
    for path in (server, target, *(root / x for x in dependencies), template):
        if path.is_symlink() or path.parent.is_symlink():
            raise AuditError("native_relay_source_symlink")
    if (not server.is_file() or server.stat().st_size > 120000
        or target.exists() or any(not (root / x).is_file() for x in dependencies)
        or not template.is_file() or template.stat().st_size > 20000):
        raise AuditError("native_relay_source_not_ready")
    original = server.read_text(encoding="utf-8")
    code = template.read_text(encoding="utf-8")
    if any(original.count(marker) != 1 for marker in (IMPORT, LIST, CALL)):
        raise AuditError("native_relay_marker_drift")
    if (NATIVE_IMPORT in original or NATIVE_CALL in original
        or "NATIVE_TOOLS" in original or "invokeOwnerNativeRead" in original
        or not all(s in code for s in
                   ("export const NATIVE_TOOLS", "export async function invokeOwnerNativeRead",
                    "eligibleDevice", "store.audit", "validatedResult", "timeoutMs: 8000"))
        or "start_process" in code or "write_file" in code):
        raise AuditError("native_relay_guard_missing")
    updated = (original.replace(IMPORT, IMPORT + "\n" + NATIVE_IMPORT)
               .replace(LIST, NATIVE_LIST)
               .replace(CALL, NATIVE_CALL + CALL))
    if updated == original or updated.count("return await invokeOwnerNativeRead(") != 1:
        raise AuditError("native_relay_patch_no_effect")
    # Template and all source preflight checks completed before any write.
    target.write_text(code, encoding="utf-8")
    server.write_text(updated, encoding="utf-8")
    return {"status": "DISPOSABLE_NATIVE_READ_RELAY_PATCHED",
            "tools": ["native_file_read", "native_file_stat", "native_file_list"],
            "owner_device_required": True, "native_host_execution": False,
            "production_activation": False}

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source-dir", required=True, type=Path)
    ap.add_argument("--sha", default=UPSTREAM_SHA)
    args = ap.parse_args()
    try:
        out = apply(args.source_dir, sha=args.sha)
    except (AuditError, OSError, UnicodeError, ValueError) as exc:
        print(f"NATIVE_RELAY_REFUSED={exc if isinstance(exc, AuditError) else type(exc).__name__}", file=sys.stderr)
        return 2
    print("H454_NATIVE_RELAY_SOURCE_ONLY=PASS")
    print(f"NATIVE_TOOLS={','.join(out['tools'])}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
