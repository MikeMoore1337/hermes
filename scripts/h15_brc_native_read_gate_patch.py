"""Fail-closed source patch for already approved/pinned H15 BRC relay (#454).

Never patch the live VPS. Only apply to a disposable verified upstream tree
after immutable gateway + owner-scoped workspace patchers. Activation still
requires separate owner approval and a pinned device token.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import json
import sys
from scripts.h15_remote_commander_candidate_audit import UPSTREAM_SHA, AuditError, evaluate

BASE = Path("packages/relay/src/mcp")
SERVER = BASE / "server.ts"
INVOKE = BASE / "invoke.ts"
MODULE = BASE / "hermes-native-read-gate.ts"
TEMPLATE = Path(__file__).resolve().parents[1] / "deploy/h15/hermes-native-read-gate.template.ts"

SERVER_IMPORT = ("import { LIST_WORKSPACES_TOOL, RESOLVE_WORKSPACE_TOOL, "
                 "listApprovedWorkspaces, resolveApprovedWorkspace } from './hermes-workspaces.js';")
SERVER_LIST = "      LIST_WORKSPACES_TOOL, RESOLVE_WORKSPACE_TOOL] };"
INVOKE_IMPORT = "import { isPermittedRemoteTool } from './hermes-policy.js';"
GATE = "  if (!isPermittedRemoteTool(tool, args)) {"
PAUSED_START = "  if (store.getDevice(deviceId)?.paused) return { ok: false, status: 423, message: "


def apply(root: Path, sha: str = UPSTREAM_SHA) -> dict:
    if sha != UPSTREAM_SHA:
        raise AuditError("upstream_sha_mismatch")
    evaluate(root, sha=sha)
    paths = (SERVER, INVOKE, MODULE)
    for path in paths:
        dest = root / path
        if dest.is_symlink() or not dest.parent.is_dir():
            raise AuditError("unsafe_relay_path")
    server_file, invoke_file, module_file = (root / p for p in paths)
    if module_file.exists() or not server_file.is_file() or not invoke_file.is_file():
        raise AuditError("relay_missing_or_already_patched")
    if server_file.stat().st_size > 100000 or invoke_file.stat().st_size > 100000:
        raise AuditError("oversize_relay_source")
    server = server_file.read_text(encoding="utf-8")
    invoke = invoke_file.read_text(encoding="utf-8")
    needed_server = (SERVER_IMPORT, SERVER_LIST)
    needed_invoke = (INVOKE_IMPORT, GATE,
                     "  const requested = typeof args.deviceId === 'string'",
                     "  const dev = hub.get(deviceId);")
    paused = [line for line in invoke.splitlines() if
              line.startswith(PAUSED_START) and "paused by its owner." in line
              and line.rstrip().endswith("};")]
    if (len(paused) != 1 or any(server.count(token) != 1 for token in needed_server)
            or any(invoke.count(token) != 1 for token in needed_invoke)):
        raise AuditError("pinned_gateway_source_drift")
    if ("hermes-native-read-gate.js" in server+invoke
            or "isNativeOriginalReadTool" in server+invoke):
        raise AuditError("native_gate_already_present")
    if (TEMPLATE.is_symlink() or not TEMPLATE.is_file()
            or TEMPLATE.stat().st_size > 20000):
        raise AuditError("unsafe_template")
    module = TEMPLATE.read_text(encoding="utf-8")
    for required in ("HERMES_NATIVE_READ_DEVICE_ID", "originalWindowsReadToolCatalog",
                     "isNativeOriginalReadRequest", "isNativeOriginalDevice"):
        if module.count(required) < 1:
            raise AuditError("invalid_template")
    new_server = server.replace(SERVER_IMPORT, SERVER_IMPORT +
        "\nimport { originalWindowsReadToolCatalog } from './hermes-native-read-gate.js';")
    new_server = new_server.replace(SERVER_LIST,
        "      LIST_WORKSPACES_TOOL, RESOLVE_WORKSPACE_TOOL,\n"
        "      ...originalWindowsReadToolCatalog()] };")
    new_invoke = invoke.replace(INVOKE_IMPORT, INVOKE_IMPORT +
        "\nimport { isNativeOriginalReadTool, nativeDeviceId,"
        " isNativeOriginalReadRequest, isNativeOriginalDevice }"
        " from './hermes-native-read-gate.js';")
    new_invoke = new_invoke.replace(GATE,
        "  if (!isPermittedRemoteTool(tool, args) && !isNativeOriginalReadTool(tool)) {")
    new_invoke = new_invoke.replace(paused[0],
        paused[0] +
        "\n  const nativeExpected = nativeDeviceId();"
        "\n  if (isNativeOriginalReadTool(tool) || (nativeExpected && deviceId === nativeExpected)) {"
        "\n    if (!isNativeOriginalReadTool(tool)"
        "\n        || !isNativeOriginalReadRequest(tool, args)"
        "\n        || !isNativeOriginalDevice(requested, dev.ownerId === ctx.userId, dev.info, dev.tools))"
        "\n      return { ok: false, status: 403, message: 'HERMES_NATIVE_DEVICE_DENIED' };"
        "\n  }")
    if (server == new_server or invoke == new_invoke
            or new_invoke.count("HERMES_NATIVE_DEVICE_DENIED") != 1):
        raise AuditError("patch_no_effect")
    # Complete all source and template validation before ANY mutation.
    module_file.write_text(module, encoding="utf-8")
    server_file.write_text(new_server, encoding="utf-8")
    invoke_file.write_text(new_invoke, encoding="utf-8")
    return {"status": "DISPOSABLE_NATIVE_RELAY_GATE_PATCHED",
            "native_device_required": True, "live_deployment": False,
            "native_host_execution": False,
            "tools": ["native_file_stat", "native_file_read"]}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source-dir", required=True, type=Path)
    ap.add_argument("--sha", default=UPSTREAM_SHA)
    opts = ap.parse_args()
    try:
        output = apply(opts.source_dir, opts.sha)
    except (AuditError, OSError, UnicodeError, ValueError) as exc:
        reason = str(exc) if isinstance(exc, AuditError) else type(exc).__name__
        print(json.dumps({"status": "REFUSED", "reason": reason}), file=sys.stderr)
        return 2
    print(json.dumps(output, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
