"""H-08: offline rule-router constraints, no untrusted instruction execution."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.check_policy_index import ROOT, check_text, validate

SOURCE = (ROOT / "policies/INDEX.md").read_text(encoding="utf-8")


class PolicyRoutingContractTests(unittest.TestCase):
    def test_canonical_router_is_valid_and_stays_offline(self):
        self.assertEqual(validate(), [])
        self.assertEqual(check_text(ROOT, SOURCE), [])
        self.assertNotIn("curl ", SOURCE)
        self.assertNotIn("git clone ", SOURCE)

    def test_every_task_route_inherits_repository_owner_constraints(self):
        rows = [row for row in SOURCE.splitlines()
                if row.startswith("|") and "[AGENTS.md]" in row]
        self.assertEqual(len(rows), 9)
        self.assertTrue(all("(../AGENTS.md)" in row for row in rows))

    def test_no_external_urls_or_arbitrary_scripts_as_policy_targets(self):
        for change in (
            "https://malicious.example/SKILL.md",
            "http://malicious.example/SKILL.md",
            "../../../etc/passwd",
            "../../outside.md",
            "../docs/architecture/../../outside.md",
            "../docs/../AGENTS.md",
            "file:///etc/passwd",
        ):
            with self.subTest(change=change):
                unsafe = SOURCE.replace("../AGENTS.md", change, 1)
                self.assertTrue(check_text(ROOT, unsafe))

    def test_missing_policy_target_rejected(self):
        changed = SOURCE.replace(
            "../docs/architecture/OWNERSHIP.md",
            "../docs/architecture/DOES_NOT_EXIST.md", 1,
        )
        self.assertIn("missing_policy_target", check_text(ROOT, changed))

    def test_missing_agents_and_duplicate_route_rejected(self):
        missing = SOURCE.replace("[AGENTS.md](../AGENTS.md)", "AGENTS", 1)
        self.assertIn("missing_agents_in_policy_route", check_text(ROOT, missing))
        duplicate = SOURCE + "\n| H-02 уведомления | [AGENTS.md](../AGENTS.md) |\n"
        self.assertIn("duplicate_or_invalid_policy_route", check_text(ROOT, duplicate))

    def test_route_injected_from_external_template_is_not_authorized(self):
        extra = SOURCE + "\n| EXTERNAL | [AGENTS.md](../AGENTS.md) |\n"
        self.assertIn("incomplete_or_unexpected_policy_routes", check_text(ROOT, extra))

    def test_control_bytes_are_rejected_before_file_access(self):
        malformed = SOURCE + "\x00"
        self.assertEqual(check_text(ROOT, malformed), ["policy_index_unsafe_content"])

    def test_parent_symlink_to_external_document_is_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "policies").mkdir()
            (root / "AGENTS.md").write_text("# Safe", encoding="utf-8")
            (root / "policies" / "INDEX.md").write_text(SOURCE, encoding="utf-8")
            (root / "docs").symlink_to("/tmp")
            result = check_text(root, SOURCE)
            self.assertIn("policy_link_outside_repository", result)

    def test_symlinked_index_is_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "policies").mkdir()
            (root / "real.md").write_text(SOURCE, encoding="utf-8")
            (root / "policies" / "INDEX.md").symlink_to(root / "real.md")
            self.assertEqual(validate(root), ["policy_index_missing_or_symlinked"])


if __name__ == "__main__":
    unittest.main()
