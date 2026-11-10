"""H454: replace legacy paused-only Win32 READ relay with all three hosts.

Exact pinned disposable BRC source only, never live VPS code mutation.
Reuses the existing authenticated OAuth MCP endpoints and hub/store.
No generic process/write tools added; original host decisions require
owner-bound device identities in the native BRC pairing authorization.
"""
from __future__ import annotations
import argparse
from pathlib import Path
import sys

from scripts.h15_remote_commander_candidate_audit import AuditError, UPSTREAM_SHA, evaluate

MCP = Path("packages/relay/src/mcp")
SERVER = MCP / "server.ts"
NEW = MCP / "hermes-native-three-read.ts"
OLD_IMPORT = "import { NATIVE_TOOLS, invokeOwnerNativeRead } from './hermes-native-read.js';"
NEW_IMPORT = "import { NATIVE_THREE_TOOLS, invokeOwnerNativeThreeRead } from './hermes-native-three-read.js';"
OLD_CALL = "return await invokeOwnerNativeRead(hub, store, ctx, name, args);"
NEW_CALL = "return await invokeOwnerNativeThreeRead(hub, store, ctx, name, args);"
OLD_LIST = "...NATIVE_TOOLS] };"
NEW_LIST = "...NATIVE_THREE_TOOLS] };"
OLD_PRED = "name === 'native_file_list') {"
NEW_PRED = "name === 'native_file_list' || name === 'native_file_search') {"
TEMPLATE = Path(__file__).resolve().parents[1] / "deploy/h454/hermes-native-three-read.template.ts"


def apply(root: Path, *, sha: str = UPSTREAM_SHA) -> dict[str, object]:
    if sha != UPSTREAM_SHA:
        raise AuditError("unreviewed_upstream_sha")
    evaluate(root, sha=sha)
    server = root / SERVER
    target = root / NEW
    if any(p.is_symlink() or p.parent.is_symlink() for p in
           (server, target, TEMPLATE)):
        raise AuditError("native_three_route_symlink")
    if (not server.is_file() or server.stat().st_size > 130_000
        or target.exists() or not TEMPLATE.is_file()
        or TEMPLATE.stat().st_size > 25_000):
        raise AuditError("native_three_route_source_not_ready")
    original = server.read_text(encoding="utf-8")
    new = TEMPLATE.read_text(encoding="utf-8")
    for marker in (OLD_IMPORT, OLD_CALL, OLD_LIST, OLD_PRED):
        if original.count(marker) != 1:
            raise AuditError("native_three_route_marker_drift")
    for marker in (
        "NATIVE_THREE_TOOLS", "invokeOwnerNativeThreeRead",
        "ownerDevice", "hermesAuthTokenHash", "store.audit",
        "native_file_search",
    ):
        if marker not in new:
            raise AuditError("native_three_route_template_invalid")
    if any(marker in new for marker in ("start_process", "write_file", "execSync", "spawn(")):
        raise AuditError("native_three_route_forbidden_effect")
    changed = (original.replace(OLD_IMPORT, NEW_IMPORT)
               .replace(OLD_CALL, NEW_CALL)
               .replace(OLD_LIST, NEW_LIST)
               .replace(OLD_PRED, NEW_PRED))
    if (changed == original or changed.count(NEW_IMPORT) != 1
        or changed.count(NEW_CALL) != 1):
        raise AuditError("native_three_route_no_effect")
    # Every precondition is checked before either source write.
    target.write_text(new, encoding="utf-8")
    server.write_text(changed, encoding="utf-8")
    return {"status": "H454_NATIVE_THREE_READ_ROUTE_PATCHED_SOURCE_ONLY",
            "native_targets": 3, "owner_bound": True,
            "original_host_access": False, "production_mutation": False}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        apply(args.source_dir)
        print("H454_NATIVE_THREE_MCP_ROUTE=SOURCE_ONLY")
        return 0
    except (AuditError, OSError, ValueError, UnicodeError):
        print("H454_NATIVE_THREE_MCP_ROUTE=HOLD", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
