"""Hermes #371 scoped hardening of immutable, untrusted BRC source."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.h15_brc_apply_policy_patch import (
    apply, DENIED_TOOLS, REMOTE_URL_DENIED,
)
from scripts.h15_remote_commander_candidate_audit import AuditError


ORIGINAL = """import { getConfig, setConfigValue } from './core/tools/config.js';
const TOOL_HANDLERS = {
  get_config: () => getConfig(),
  set_config_value: (a) => setConfigValue(a),
  get_recent_tool_calls: (a) => handlers.handleGetRecentToolCalls(a),
  start_process: (a) => handlers.handleStartProcess(a),
  read_file: (a) => handlers.handleReadFile(a),
  write_file: (a) => handlers.handleWriteFile(a),
  prepare_file_transfer: (a) => handlers.handlePrepareFileTransfer(a),
  send_file_transfer: (a) => handlers.handleSendFileTransfer(a),
  receive_file_transfer: (a) => handlers.handleReceiveFileTransfer(a),
};
if (!handler) { return error; }
t.name in TOOL_HANDLERS
"""

EDIT = """async function edit() {
    if (count > 0 && count !== expectedReplacements) {
        return {
            content: [{type: 'text', text: 'Expected occurrences mismatch'}],
        };
    }
    return writeReplacement();
}
"""


class BrcHardeningTests(unittest.TestCase):
    def test_offline_bundle_distributes_the_edit_handler_change(self):
        workflow = (Path(__file__).resolve().parents[1] /
                    ".github/workflows/h15-remote-commander-candidate.yml").read_text(encoding="utf-8")
        paths = workflow.split('cat > "$bundle/EXPECTED_PATHS.txt" <<\'PATHS\'\n', 1)[1].split('\n          PATHS', 1)[0]
        self.assertIn("packages/agent/src/core/tools/edit.ts", [line.strip() for line in paths.splitlines()])

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.dispatcher = self.root / "packages/agent/src/dispatcher.ts"
        self.dispatcher.parent.mkdir(parents=True)
        self.dispatcher.write_text(ORIGINAL, encoding="utf-8")
        self.edit = self.root / "packages/agent/src/core/tools/edit.ts"
        self.edit.parent.mkdir(parents=True)
        self.edit.write_text(EDIT, encoding="utf-8")
        guard = patch("scripts.h15_brc_apply_policy_patch.evaluate", return_value={
            "status": "SOURCE_PIN_VERIFIED"
        })
        guard.start()
        self.addCleanup(guard.stop)

    def test_patch_removes_policy_mutation_and_external_file_host(self):
        result = apply(self.root)
        new = self.dispatcher.read_text(encoding="utf-8")
        for name in DENIED_TOOLS:
            self.assertNotIn("  " + name + ":", new)
        self.assertIn("  start_process:", new)
        self.assertIn("  write_file:", new)
        self.assertIn("a.isUrl === true", new)
        self.assertIn(REMOTE_URL_DENIED, new)
        self.assertFalse(result["production_ready"])
        self.assertEqual(result["live_execution"], "DENIED")

    def test_sensitive_config_reads_removed_but_real_file_and_shell_remain(self):
        result = apply(self.root)
        patched = self.dispatcher.read_text(encoding="utf-8")
        self.assertIn("get_config", result["blocked_tools"])
        self.assertIn("get_recent_tool_calls", result["blocked_tools"])
        self.assertNotIn("import { getConfig", patched)
        self.assertNotIn("  get_config:", patched)
        self.assertNotIn("  get_recent_tool_calls:", patched)
        self.assertIn("  start_process:", patched)
        self.assertIn("  write_file:", patched)

    def test_changed_config_read_handler_rejected_atomically(self):
        changed = ORIGINAL.replace(
            "  get_config: () => getConfig(),",
            "  get_config: () => unexpectedConfig(),",
        )
        self.dispatcher.write_text(changed, encoding="utf-8")
        with self.assertRaisesRegex(AuditError, "hardened_handler_pattern_missing"):
            apply(self.root)
        self.assertEqual(self.dispatcher.read_text(encoding="utf-8"), changed)

    def test_second_patching_is_rejected(self):
        apply(self.root)
        with self.assertRaisesRegex(AuditError, "hardened_handler_pattern_missing"):
            apply(self.root)

    def test_upstream_changed_handler_is_rejected_without_writing(self):
        old = ORIGINAL.replace(
            "  send_file_transfer: (a) => handlers.handleSendFileTransfer(a),",
            "  send_file_transfer: (a) => unknownHandler(a),",
        )
        self.dispatcher.write_text(old, encoding="utf-8")
        # This patch intentionally supports only explicit known handler
        # locations; a new handler of the same name still gets removed,
        # whereas an unexpected name must fail.
        old = old.replace(
            "  send_file_transfer: (a) => unknownHandler(a),",
            "  alternate_transfer: (a) => unknownHandler(a),",
        )
        self.dispatcher.write_text(old, encoding="utf-8")
        with self.assertRaisesRegex(AuditError, "hardened_handler_pattern_missing"):
            apply(self.root)
        self.assertEqual(self.dispatcher.read_text(encoding="utf-8"), old)

    def test_symlinked_dispatcher_refused(self):
        self.dispatcher.unlink()
        target = self.root / "src.txt"
        target.write_text(ORIGINAL, encoding="utf-8")
        self.dispatcher.symlink_to(target)
        with self.assertRaisesRegex(AuditError, "unsafe_dispatcher"):
            apply(self.root)

    def test_remote_url_handler_change_denied(self):
        source = ORIGINAL.replace(
            "  read_file: (a) => handlers.handleReadFile(a),",
            "  read_file: (a) => proxyFile(a),",
        )
        self.dispatcher.write_text(source, encoding="utf-8")
        with self.assertRaisesRegex(AuditError, "unreviewed_dispatcher_change"):
            apply(self.root)

    def test_edit_conflict_is_error_and_success_branch_is_preserved(self):
        apply(self.root)
        actual = self.edit.read_text(encoding="utf-8")
        expected = EDIT.replace("        return {\n", "        return {\n            isError: true,\n")
        self.assertEqual(actual, expected)
        self.assertIn("return writeReplacement();", actual)

    def test_changed_edit_branch_refuses_before_any_source_write(self):
        changed = EDIT.replace("count !== expectedReplacements", "count >= expectedReplacements")
        self.edit.write_text(changed, encoding="utf-8")
        with self.assertRaisesRegex(AuditError, "unreviewed_edit_conflict_branch"):
            apply(self.root)
        self.assertEqual(self.dispatcher.read_text(encoding="utf-8"), ORIGINAL)
        self.assertEqual(self.edit.read_text(encoding="utf-8"), changed)

    def test_symlinked_edit_handler_refused_before_dispatcher_write(self):
        self.edit.unlink()
        target = self.root / "edit-original.ts"
        target.write_text(EDIT, encoding="utf-8")
        self.edit.symlink_to(target)
        with self.assertRaisesRegex(AuditError, "unsafe_edit_handler"):
            apply(self.root)
        self.assertEqual(target.read_text(encoding="utf-8"), EDIT)
        self.assertEqual(self.dispatcher.read_text(encoding="utf-8"), ORIGINAL)


if __name__ == "__main__":
    unittest.main()
