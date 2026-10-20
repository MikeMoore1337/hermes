"""#371: MCP tool policy must be enforced at BOTH gateway boundaries."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.h15_brc_harden_gateway import (
    apply, SERVER, INVOKE, POLICY, CATALOG, SERVER_IMPORT, SERVER_LIST, INVOKE_MARKER,
    STATIC_LIST_MARKER,
)
from scripts.h15_remote_commander_candidate_audit import AuditError

SERVER_SOURCE = SERVER_IMPORT + "\n" + SERVER_LIST + "\n" + STATIC_LIST_MARKER + "\n"
INVOKE_SOURCE = (
    "import { createHash } from 'node:crypto';\n"
    "export function invokeTool() {\n" + INVOKE_MARKER + "\n}\n"
)


class GatewayPolicyTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        for name, data in ((SERVER, SERVER_SOURCE), (INVOKE, INVOKE_SOURCE)):
            f = self.root / name
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(data, encoding="utf-8")
        guard = patch(
            "scripts.h15_brc_harden_gateway.evaluate",
            return_value={"status": "SOURCE_PIN_VERIFIED"},
        )
        guard.start()
        self.addCleanup(guard.stop)

    def test_gateway_filters_advertisement_and_execution_independently(self):
        verdict = apply(self.root)
        server = (self.root / SERVER).read_text(encoding="utf-8")
        invoke = (self.root / INVOKE).read_text(encoding="utf-8")
        policy = (self.root / POLICY).read_text(encoding="utf-8")
        catalog = (self.root / CATALOG).read_text(encoding="utf-8")
        self.assertIn("isPermittedRemoteTool(t.name, {})", server)
        self.assertIn("pinnedToolCatalog()", server)
        self.assertIn("pinnedToolCatalog", catalog)
        self.assertIn("compiledAgentSchema", catalog)
        self.assertIn("isPermittedRemoteTool(t.name, {})", catalog)
        self.assertIn("HERMES_PINNED_TOOL_CATALOG_MISSING_OR_DUPLICATE", catalog)
        self.assertIn("isPermittedRemoteTool(tool, args)", invoke)
        self.assertIn("HERMES_REMOTE_TOOL_DENIED", invoke)
        self.assertIn("args.isUrl === true", policy)
        self.assertIn("'start_process'", policy)
        self.assertNotIn("'set_config_value'", policy)
        self.assertNotIn("'send_file_transfer'", policy)
        self.assertFalse(verdict["production_ready"])

    def test_refuse_repeat_patch(self):
        apply(self.root)
        with self.assertRaisesRegex(AuditError, "policy_already_present"):
            apply(self.root)

    def test_source_drift_refused_without_changes(self):
        f = self.root / SERVER
        altered = SERVER_SOURCE.replace("if (!merged.has(t.name))", "if (unreviewed())")
        f.write_text(altered, encoding="utf-8")
        with self.assertRaisesRegex(AuditError, "relay_policy_source_changed"):
            apply(self.root)
        self.assertEqual(f.read_text(encoding="utf-8"), altered)
        self.assertFalse((self.root / POLICY).exists())
        self.assertFalse((self.root / CATALOG).exists())

    def test_bad_sha_refused(self):
        with self.assertRaisesRegex(AuditError, "unreviewed_upstream_sha"):
            apply(self.root, sha="f" * 40)

    def test_symlinked_gateway_source_refused(self):
        p = self.root / INVOKE
        p.unlink()
        target = self.root / "victim"
        target.write_text(INVOKE_SOURCE, encoding="utf-8")
        p.symlink_to(target)
        with self.assertRaisesRegex(AuditError, "relay_policy_path_unsafe"):
            apply(self.root)
        self.assertEqual(target.read_text(encoding="utf-8"), INVOKE_SOURCE)


if __name__ == "__main__":
    unittest.main()
