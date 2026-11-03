"""Patch an already-hardened pinned BRC relay, in a disposable checkout only (#454)."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
from scripts.h15_remote_commander_candidate_audit import UPSTREAM_SHA, AuditError, evaluate
from scripts.h15_workspace_router import load_registry, RouteDenied

BASE = Path("packages/relay/src/mcp")
IMP = "import { pinnedToolCatalog } from './hermes-tool-catalog.js';"
LIST = "      ...pinnedToolCatalog().map(t => ({ ...t, inputSchema: withDeviceId(t.inputSchema) }))] };"
CALL = "    const out = await invokeTool(hub, store, ctx, name, args as Record<string, unknown> | undefined);"
DEVICE_HELP = "Target device id (from list_devices). Required when more than one device is online; may be omitted when only one device is connected."
OLD_LIVE_DEVICES = "  const online = new Set(hub.list(userId).map((d) => d.deviceId));"
NEW_LIVE_DEVICES = "  const online = new Map(hub.list(userId).map((d) => [d.deviceId, d.lastSeen] as const));"
OLD_DEVICE_SEEN = "online: online.has(d.device_id), paused: !!d.paused, lastSeen: d.last_seen,"
NEW_DEVICE_SEEN = "online: online.has(d.device_id), paused: !!d.paused, lastSeen: online.get(d.device_id) ?? d.last_seen,"
WORKSPACE_DEVICE_HELP = ("Target device id (from list_devices). Optional for file operations on registered "
                         "project paths and their search sessions; otherwise required when multiple devices are online.")
NEWIMP = "import { LIST_WORKSPACES_TOOL, RESOLVE_WORKSPACE_TOOL, listApprovedWorkspaces, resolveApprovedWorkspace } from './hermes-workspaces.js';"
ROUTEIMP = "import { routeWorkspaceCall, prepareWorkspaceSearch, finishWorkspaceSearch } from './hermes-workspaces.js';"
NEWLIST = ("      ...pinnedToolCatalog().map(t => ({ ...t, inputSchema: withDeviceId(t.inputSchema) })),\n"
           "      LIST_WORKSPACES_TOOL, RESOLVE_WORKSPACE_TOOL] };")
NEWCALL = """    if (name === 'list_workspaces' || name === 'resolve_workspace') {
      // Owner-authenticated relay only; never dispatch these tools to an agent.
      const devices = listUserDevices(hub, store, ctx.userId);
      const result = name === 'list_workspaces'
        ? listApprovedWorkspaces(devices) : resolveApprovedWorkspace(args, devices);
      return { content: [{ type: 'text', text: JSON.stringify(result) }],
               isError: result.status === 'refused' };
    }
"""
ROUTECALL = """    const routeDevices = listUserDevices(hub, store, ctx.userId);
    const route = routeWorkspaceCall(name, args, routeDevices);
    if (route.status === 'refused')
      return { content: [{ type: 'text', text: `Workspace routing refused: ${route.reason}` }], isError: true };
    if (route.status === 'routed' && args) args.deviceId = route.deviceId;
    const search = prepareWorkspaceSearch(name, args, route, hub, routeDevices);
    if (search.status === 'refused')
      return { content: [{ type: 'text', text: `Search session refused: ${search.reason}` }], isError: true };
    if (search.status === 'follow' && args) {
      args.deviceId = search.deviceId;
      args.sessionId = search.nativeId;
    }
"""
ROUTERESULT = """
    if (out.ok) {
      const finished = finishWorkspaceSearch(out.result, search, hub);
      if (finished.status === 'refused')
        return { content: [{ type: 'text', text: `Search session unavailable: ${finished.reason}; check the device before retrying.` }], isError: true };
    }
"""

def apply(root: Path, registry: Path, sha: str = UPSTREAM_SHA) -> dict:
    if sha != UPSTREAM_SHA:
        raise AuditError("upstream_sha_mismatch")
    evaluate(root, sha=sha)
    try:
        cfg = load_registry(registry)
    except RouteDenied as exc:
        raise AuditError("unsafe_workspace_registry") from exc
    if cfg["workspace_root"] != "/workspace/projects":
        raise AuditError("unsafe_workspace_root")
    paths = [BASE / n for n in ("server.ts", "hermes-workspaces.ts",
                                "hermes-policy.ts", "hermes-tool-catalog.ts", "invoke.ts")]
    if any((root / p).is_symlink() or (root / p).parent.is_symlink() for p in paths):
        raise AuditError("symlink_relay_source")
    sp, mod, pol, cat, inv = [root / p for p in paths]
    if (not sp.is_file() or sp.stat().st_size > 100000 or mod.exists()
        or not pol.is_file() or not cat.is_file() or not inv.is_file() or inv.stat().st_size > 100000):
        raise AuditError("hardened_relay_missing")
    original = sp.read_text(encoding="utf-8")
    policy = pol.read_text(encoding="utf-8")
    invocation = inv.read_text(encoding="utf-8")
    if ("export function isPermittedRemoteTool" not in policy
        or "'list_workspaces'" in policy or "'resolve_workspace'" in policy):
        raise AuditError("remote_invocation_policy_unreviewed")
    if any(original.count(x) != 1 for x in (IMP, LIST, CALL, DEVICE_HELP)):
        raise AuditError("gateway_source_marker_drift")
    if invocation.count(OLD_LIVE_DEVICES) != 1 or invocation.count(OLD_DEVICE_SEEN) != 1:
        raise AuditError("device_presence_marker_drift")
    if "hermes-workspaces.js" in original:
        raise AuditError("already_patched")
    template_file = Path(__file__).resolve().parents[1] / "deploy/h15/hermes-workspaces.template.ts"
    if template_file.is_symlink() or not template_file.is_file() or template_file.stat().st_size > 20000:
        raise AuditError("unsafe_workspace_template")
    template = template_file.read_text(encoding="utf-8")
    if (template.count("__HERMES_CATALOG__") != 1 or template.count("__HERMES_DEVICE_NAME__") != 1
        or template.count("__HERMES_DEVICE_ID__") != 1):
        raise AuditError("workspace_template_drift")
    rows = [{"name": x["name"], "aliases": x["aliases"], "branch": x["branch"],
             "root": cfg["workspace_root"] + "/" + x["name"],
             "origin": "https://github.com/MikeMoore1337/" + x["repository"] + ".git"}
            for x in cfg["workspaces"]]
    code = template.replace("__HERMES_CATALOG__", json.dumps(rows, ensure_ascii=True))
    code = code.replace("__HERMES_DEVICE_NAME__", json.dumps(cfg["device_name"], ensure_ascii=True))
    code = code.replace("__HERMES_DEVICE_ID__", json.dumps(cfg["device_id"], ensure_ascii=True))
    patched = (original.replace(IMP, IMP + "\n" + NEWIMP + "\n" + ROUTEIMP)
               .replace(LIST, NEWLIST).replace(DEVICE_HELP, WORKSPACE_DEVICE_HELP)
               .replace(CALL, NEWCALL + ROUTECALL + CALL + ROUTERESULT))
    if (patched == original or patched.count("name === 'resolve_workspace'") != 1
        or patched.count("routeWorkspaceCall(name, args") != 1):
        raise AuditError("patch_failed")
    updated_invocation = invocation.replace(OLD_LIVE_DEVICES, NEW_LIVE_DEVICES).replace(OLD_DEVICE_SEEN, NEW_DEVICE_SEEN)
    mod.write_text(code, encoding="utf-8")
    sp.write_text(patched, encoding="utf-8")
    inv.write_text(updated_invocation, encoding="utf-8")
    return {"status": "DISPOSABLE_RELAY_PATCHED",
            "tools": ["list_workspaces", "resolve_workspace"],
            "live_deployment": False, "git_verified": False}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source-dir", required=True, type=Path)
    ap.add_argument("--registry", default=Path("deploy/h15/workspace-registry.json"), type=Path)
    ap.add_argument("--sha", default=UPSTREAM_SHA)
    a = ap.parse_args()
    try:
        out = apply(a.source_dir, a.registry, a.sha)
    except (AuditError, OSError, UnicodeError, ValueError) as exc:
        print(json.dumps({"status": "REJECTED", "reason": str(exc) if isinstance(exc, AuditError)
                          else type(exc).__name__}), file=sys.stderr)
        return 2
    print(json.dumps(out, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
