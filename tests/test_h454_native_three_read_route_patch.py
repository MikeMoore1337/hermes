"""H454: fail-closed three original-host MCP routing patch, offline only."""
from __future__ import annotations
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.h454_native_three_read_route_patch import (
    apply, OLD_IMPORT, OLD_CALL, OLD_LIST, OLD_PRED,
    NEW_IMPORT, NEW_CALL, NEW_LIST, NEW_PRED,
)
from scripts.h15_remote_commander_candidate_audit import AuditError

SOURCE = (OLD_IMPORT + "\n"
          "export function catalog() {\n  return { tools: [\n"
          "      LIST_WORKSPACES_TOOL, RESOLVE_WORKSPACE_TOOL, "
          + OLD_LIST + "\n}\n"
          "    if (name === 'native_file_read' || name === 'native_file_stat'"
          " || " + OLD_PRED + "\n"
          "      " + OLD_CALL + "\n    }\n")


class NativeThreeMcpRoutePatch(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.path = self.root / "packages/relay/src/mcp/server.ts"
        self.path.parent.mkdir(parents=True)
        self.path.write_text(SOURCE, encoding="utf-8")
        p = patch("scripts.h454_native_three_read_route_patch.evaluate")
        p.start()
        self.addCleanup(p.stop)

    def test_exact_three_host_replacement_and_no_generic_tools(self):
        out = apply(self.root)
        self.assertEqual(out["native_targets"], 3)
        self.assertFalse(out["production_mutation"])
        source = self.path.read_text(encoding="utf-8")
        self.assertIn(NEW_IMPORT, source)
        self.assertIn(NEW_CALL, source)
        self.assertIn(NEW_LIST, source)
        self.assertIn(NEW_PRED, source)
        self.assertNotIn(OLD_IMPORT, source)
        self.assertNotIn(OLD_CALL, source)
        generated = (
            self.root / "packages/relay/src/mcp/hermes-native-three-read.ts"
        ).read_text(encoding="utf-8")
        for marker in ("ownerDevice", "hermesAuthTokenHash",
                       "store.audit", "native_file_search",
                       "native_file_read", "native_file_stat",
                       "native_file_list"):
            self.assertIn(marker, generated)
        self.assertNotIn("start_process", generated)
        self.assertNotIn("write_file", generated)

    def test_refuse_reapply_and_drift_before_source_writes(self):
        apply(self.root)
        stable = self.path.read_bytes()
        with self.assertRaises(AuditError):
            apply(self.root)
        self.assertEqual(stable, self.path.read_bytes())
        self.path.write_text(SOURCE.replace(OLD_IMPORT, "UNKNOWN()"))
        before = self.path.read_bytes()
        (self.root / "packages/relay/src/mcp/hermes-native-three-read.ts").unlink()
        with self.assertRaises(AuditError):
            apply(self.root)
        self.assertEqual(before, self.path.read_bytes())

    def test_wrong_sha_and_escaped_server_denied(self):
        with self.assertRaises(AuditError):
            apply(self.root, sha="f"*40)
        outside = self.root / "outside"
        outside.write_text(SOURCE)
        self.path.unlink()
        self.path.symlink_to(outside)
        with self.assertRaises(AuditError):
            apply(self.root)
        self.assertEqual(outside.read_text(), SOURCE)


if __name__ == "__main__":
    unittest.main()
