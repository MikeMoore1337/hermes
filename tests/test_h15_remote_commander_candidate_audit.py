"""Offline contract tests for #371 self-hosted MCP upstream gate."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts.h15_remote_commander_candidate_audit import (
    AuditError, REQUIRED, UPSTREAM_SHA, evaluate,
)


class CandidateAuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.files = {name: "fixture" for name in REQUIRED}
        self.files["LICENSE"] = "MIT License fixture"
        self.files["NOTICE"] = "Desktop Commander contributors MIT"
        self.files["package.json"] = json.dumps(
            {"license": "MIT", "packageManager": "pnpm@11.24.0"}
        )
        self.files["packages/relay/src/app.ts"] = (
            "mcpAuthRouter StreamableHTTPServerTransport"
        )
        self.files["packages/relay/src/mcp/invoke.ts"] = "store.audit("
        self.files["packages/agent/src/dispatcher.ts"] = " ".join(
            ("start_process:", "interact_with_process:", "read_file:",
             "write_file:", "set_config_value:")
        )
        self.files["packages/agent/src/core/config-manager.ts"] = (
            "allowedDirectories: []"
        )
        self.files["packages/agent/src/core/tools/improved-process-tools.ts"] = (
            "startProcess executeNodeCode"
        )
        for name, content in self.files.items():
            p = self.root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
        self.patch_run = patch(
            "scripts.h15_remote_commander_candidate_audit.subprocess.run",
            return_value=subprocess.CompletedProcess(
                [], 0, stdout=UPSTREAM_SHA + "\n"
            ),
        )
        self.patch_run.start()
        self.addCleanup(self.patch_run.stop)

    def test_approved_hash_reports_risks_but_never_live_permission(self):
        result = evaluate(self.root)
        self.assertEqual(result["status"], "SOURCE_PIN_VERIFIED")
        self.assertFalse(result["production_ready"])
        self.assertEqual(result["live_execution"], "DENIED")
        self.assertEqual(
            result["next_gate"], "OS_SANDBOX_AND_NEGATIVE_E2E_REQUIRED"
        )
        self.assertTrue(all(result["security_findings"].values()))

    def test_unreviewed_version_is_denied(self):
        with self.assertRaisesRegex(AuditError, "unreviewed_upstream_sha"):
            evaluate(self.root, sha="e" * 40)

    def test_checkout_sha_mismatch_is_denied(self):
        with patch(
            "scripts.h15_remote_commander_candidate_audit.subprocess.run",
            return_value=subprocess.CompletedProcess([], 0, stdout="f" * 40),
        ):
            with self.assertRaisesRegex(AuditError, "upstream_revision_mismatch"):
                evaluate(self.root)

    def test_missing_mcp_auth_rejected(self):
        (self.root / "packages/relay/src/app.ts").write_text(
            "StreamableHTTPServerTransport"
        )
        with self.assertRaisesRegex(AuditError, "oauth_not_verified"):
            evaluate(self.root)

    def test_missing_or_changed_risk_requires_review(self):
        (self.root / "packages/agent/src/core/config-manager.ts").write_text(
            "allowedDirectories: ['sandbox']"
        )
        with self.assertRaisesRegex(AuditError, "risk_signatures_changed"):
            evaluate(self.root)

    def test_removal_of_policy_mutation_changes_expected_toolset(self):
        (self.root / "packages/agent/src/dispatcher.ts").write_text(
            "start_process: interact_with_process: read_file: write_file:"
        )
        with self.assertRaisesRegex(AuditError, "expected_remote_tool_missing"):
            evaluate(self.root)

    def test_symlinked_file_rejected(self):
        f = self.root / "NOTICE"
        f.unlink()
        f.symlink_to(self.root / "LICENSE")
        with self.assertRaisesRegex(AuditError, "symlink_in_candidate"):
            evaluate(self.root)

    def test_license_notice_required(self):
        (self.root / "NOTICE").write_text("unlicensed")
        with self.assertRaisesRegex(AuditError, "license_notice_missing"):
            evaluate(self.root)


if __name__ == "__main__":
    unittest.main()
