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
  write_pdf: (a) => handlers.handleWritePdf(a),
  create_directory: (a) => handlers.handleCreateDirectory(a),
  move_file: (a) => handlers.handleMoveFile(a),
  edit_block: (a) => handlers.handleEditBlock(a),
  prepare_file_transfer: (a) => handlers.handlePrepareFileTransfer(a),
  send_file_transfer: (a) => handlers.handleSendFileTransfer(a),
  receive_file_transfer: (a) => handlers.handleReceiveFileTransfer(a),
};
let cachedDefs: ToolDefinition[] | null = null;
t.name in TOOL_HANDLERS
export async function callTool(name: string, args: Args): Promise<ToolResult> {
  const handler = TOOL_HANDLERS[name];
  if (!handler) { return error; }
  try {
    const result = (await handler(args ?? {})) as ToolResult;
    return result;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { content: [{ type: 'text', text: `Error in ${name}: ${message}` }], isError: true };
  }
}
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

FILESYSTEM = """    const info: Record<string, any> = {
        created: fileInfo.created ?? fallbackInfo.created,
    };

    // Add type-specific metadata from file handler
    return info;
"""

TERMINAL = """class TerminalManager {
  forceTerminate(pid: number): boolean {
    const session = this.sessions.get(pid);
    session.process.kill('SIGINT');
    setTimeout(() => {
          if (this.sessions.has(pid)) {
            session.process.kill('SIGKILL');
          }
    }, 1000);
    return true;
  }
  listActiveSessions() { return []; }
}
"""

PROCESS_TOOLS = """export async function forceTerminate(args: unknown): Promise<ServerResult> {
  const success = terminalManager.forceTerminate(pid);
  return {
    content: [{ text: success ? `Successfully initiated termination of session ${pid}`
      : `No active session found for PID ${pid}` }],
  };
}
export async function listSessions() { return []; }
"""

SEARCH_MANAGER = """        if (!session.isComplete && !session.process.killed) {
          session.process.kill('SIGTERM');
        }
      if (session.totalMatches > 0) {
        session.isError = false;
      }
"""
SEARCH_HANDLERS = """export async function handleStartSearch(args) {
    output += `${result.isComplete ? 'COMPLETED' : 'RUNNING'}`;
      output += `\\n✅ Search completed.`;
    return {
      content: [{ type: "text", text: output }],
    };
}
export async function handleGetMoreSearchResults(args) {
    output += `${results.isComplete ? 'COMPLETED' : 'IN PROGRESS'}`;
      output += `\\n✅ Search completed.`;
      if (results.wasIncomplete) {
        permissionWarning();
      }
    return {
      content: [{ type: "text", text: output }],
    };
}
export async function handleStopSearch(args) { return originalStop(); }
"""


class BrcHardeningTests(unittest.TestCase):
    def test_offline_bundle_distributes_patched_agent_sources(self):
        workflow = (Path(__file__).resolve().parents[1] /
                    ".github/workflows/h15-remote-commander-candidate.yml").read_text(encoding="utf-8")
        paths = workflow.split('cat > "$bundle/EXPECTED_PATHS.txt" <<\'PATHS\'\n', 1)[1].split('\n          PATHS', 1)[0]
        for path in ("packages/agent/src/core/tools/edit.ts", "packages/agent/src/core/tools/filesystem.ts",
                     "packages/agent/src/core/tools/improved-process-tools.ts", "packages/agent/src/core/terminal-manager.ts",
                     "packages/agent/src/core/search-manager.ts",
                     "packages/agent/src/core/handlers/search-handlers.ts"):
            self.assertIn(path, [line.strip() for line in paths.splitlines()])

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
        self.filesystem = self.root / "packages/agent/src/core/tools/filesystem.ts"
        self.filesystem.write_text(FILESYSTEM, encoding="utf-8")
        self.terminal = self.root / "packages/agent/src/core/terminal-manager.ts"
        self.terminal.write_text(TERMINAL, encoding="utf-8")
        self.process_tools = self.root / "packages/agent/src/core/tools/improved-process-tools.ts"
        self.process_tools.write_text(PROCESS_TOOLS, encoding="utf-8")
        self.search = self.root / "packages/agent/src/core/search-manager.ts"
        self.search.write_text(SEARCH_MANAGER, encoding="utf-8")
        self.search_handlers = self.root / "packages/agent/src/core/handlers/search-handlers.ts"
        self.search_handlers.parent.mkdir(parents=True)
        self.search_handlers.write_text(SEARCH_HANDLERS, encoding="utf-8")
        guard = patch("scripts.h15_brc_apply_policy_patch.evaluate", return_value={
            "status": "SOURCE_PIN_VERIFIED"
        })
        guard.start()
        self.addCleanup(guard.stop)

    def test_changed_search_inputs_refuse_before_any_source_write(self):
        for target, original in ((self.search, SEARCH_MANAGER), (self.search_handlers, SEARCH_HANDLERS)):
            with self.subTest(path=target.name):
                target.write_text(original.replace("isComplete", "unexpectedState"), encoding="utf-8")
                paths = (self.dispatcher, self.edit, self.filesystem, self.terminal, self.process_tools,
                         self.search, self.search_handlers)
                before = {p: p.read_bytes() for p in paths}
                with self.assertRaisesRegex(AuditError, "unreviewed_search_timeout"):
                    apply(self.root)
                self.assertEqual({p: p.read_bytes() for p in paths}, before)
                target.write_text(original, encoding="utf-8")

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

    def test_patch_marks_ambiguous_epoch_without_removing_created_field(self):
        apply(self.root)
        actual = self.filesystem.read_text(encoding="utf-8")
        self.assertIn("info.created instanceof Date && info.created.getTime() === 0", actual)
        self.assertIn("info.created = null;", actual)
        self.assertIn("info.createdStatus = 'unavailable_or_epoch';", actual)
        self.assertIn("return info;", actual)

    def test_unreviewed_mutation_dispatcher_refuses_without_writing(self):
        self.dispatcher.write_text(ORIGINAL.replace("  move_file:", "  unexpected_move:"), encoding="utf-8")
        paths = (self.dispatcher, self.edit, self.filesystem, self.terminal, self.process_tools,
                 self.search, self.search_handlers)
        before = {p: p.read_bytes() for p in paths}
        with self.assertRaisesRegex(AuditError, "unreviewed_file_mutation_dispatcher"):
            apply(self.root)
        self.assertEqual({p: p.read_bytes() for p in paths}, before)

    def test_changed_file_info_refuses_before_any_source_write(self):
        self.filesystem.write_text(FILESYSTEM.replace("fileInfo.created", "unreviewed.created"), encoding="utf-8")
        paths = (self.dispatcher, self.edit, self.filesystem, self.terminal, self.process_tools,
                 self.search, self.search_handlers)
        before = {p: p.read_bytes() for p in paths}
        with self.assertRaisesRegex(AuditError, "unreviewed_file_info_birthtime"):
            apply(self.root)
        self.assertEqual({p: p.read_bytes() for p in paths}, before)

    def test_unreviewed_termination_refuses_without_writing(self):
        for target, original in ((self.terminal, TERMINAL), (self.process_tools, PROCESS_TOOLS)):
            with self.subTest(path=target.name):
                target.write_text(original.replace("forceTerminate", "unexpectedTermination"), encoding="utf-8")
                paths = (self.dispatcher, self.edit, self.filesystem, self.terminal, self.process_tools,
                         self.search, self.search_handlers)
                before = {p: p.read_bytes() for p in paths}
                with self.assertRaisesRegex(AuditError, "unreviewed_terminal_termination"):
                    apply(self.root)
                self.assertEqual({p: p.read_bytes() for p in paths}, before)
                target.write_text(original, encoding="utf-8")

    def test_termination_requires_successful_signal_and_discloses_scope(self):
        apply(self.root)
        terminal = self.terminal.read_text(encoding="utf-8")
        tools = self.process_tools.read_text(encoding="utf-8")
        self.assertIn("if (!session.process.kill('SIGINT'))", terminal)
        self.assertIn("if (!session.process.kill('SIGKILL'))", terminal)
        self.assertIn("Only the tracked process is signaled; descendants may remain.", tools)

    def test_changed_initial_termination_signal_refuses_without_writing(self):
        self.terminal.write_text(TERMINAL.replace("kill('SIGINT')", "kill('SIGTERM')"), encoding="utf-8")
        paths = (self.dispatcher, self.edit, self.filesystem, self.terminal, self.process_tools,
                 self.search, self.search_handlers)
        before = {p: p.read_bytes() for p in paths}
        with self.assertRaisesRegex(AuditError, "unreviewed_terminal_termination"):
            apply(self.root)
        self.assertEqual({p: p.read_bytes() for p in paths}, before)

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
