"""H-15 exact OCI owner release decision: offline, no Docker and no secrets."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/h15_brc_release_approval.py"
DEPLOY = ROOT / "deploy/h15/owner-relay.sh"
IMAGE = "sha256:" + "b" * 64


class ReleaseApprovalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("h15_release_approval", SCRIPT)
        cls.gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.gate)

    def valid_decision(self):
        return {
            "schema": 1,
            "decision": "OWNER_ACCEPTED_RESIDUAL_CVE_RISK",
            "scope": "INTERNAL_OAUTH_ONLY_NO_AGENTS_NO_PUBLIC_MCP",
            "image_id": IMAGE,
            "upstream_sha": "cbe511702dd0147650353c29ac6ab1decd8afda1",
            "hermes_commit": "a" * 40,
            "oci_archive_sha256": "c" * 64,
            "trivy_report_sha256": "d" * 64,
            "cve_triage_sha256": "e" * 64,
            "reviewed_residual_cve_ids": ["CVE-2023-45853", "CVE-2026-93687"],
        }

    def test_exact_owner_decision_accepted_for_one_image(self):
        self.gate.validate_decision(self.valid_decision(), IMAGE)

    def test_changed_image_never_inherits_approval(self):
        with self.assertRaises(self.gate.ApprovalDenied):
            self.gate.validate_decision(self.valid_decision(), "sha256:" + "f" * 64)

    def test_decision_scope_evidence_and_cve_inputs_must_be_explicit(self):
        wrong = (
            ("decision", "CI_IMAGE_VERIFIED_NOT_DEPLOYABLE"),
            ("scope", "FULL_DEVICE_ACCESS"),
            ("hermes_commit", "latest"),
            ("oci_archive_sha256", ""),
            ("trivy_report_sha256", "not-a-digest"),
            ("cve_triage_sha256", "e" * 63),
            ("upstream_sha", "f" * 40),
            ("schema", True),
            ("reviewed_residual_cve_ids", ["CVE-2026-93687", "CVE-2023-45853"]),
            ("reviewed_residual_cve_ids", ["CVE-2026-93687", "CVE-2026-93687"]),
            ("reviewed_residual_cve_ids", ["invalid-CVE"]),
            ("reviewed_residual_cve_ids", "CVE-2026-93687"),
        )
        for key, value in wrong:
            with self.subTest(key=key, value=value):
                doc = self.valid_decision()
                doc[key] = value
                with self.assertRaises(self.gate.ApprovalDenied):
                    self.gate.validate_decision(doc, IMAGE)

    def test_unknown_keys_cannot_override_a_reviewed_decision(self):
        doc = self.valid_decision()
        doc["automatic_ci_go"] = True
        with self.assertRaises(self.gate.ApprovalDenied):
            self.gate.validate_decision(doc, IMAGE)
        del doc["automatic_ci_go"]
        del doc["trivy_report_sha256"]
        with self.assertRaises(self.gate.ApprovalDenied):
            self.gate.validate_decision(doc, IMAGE)

    def test_duplicate_json_keys_refused_even_when_last_value_seems_correct(self):
        with self.assertRaises(self.gate.ApprovalDenied):
            json.loads('{"image_id":"old","image_id":"new"}',
                       object_pairs_hook=self.gate.no_duplicate_keys)

    def test_valid_private_permissions_but_not_symlinks_or_world_read(self):
        with tempfile.TemporaryDirectory() as folder:
            parent = Path(folder)
            os.chmod(parent, 0o700)
            approved = parent / "approval.json"
            approved.write_text(json.dumps(self.valid_decision()))
            os.chmod(approved, 0o600)
            params = {"owner_uid": os.getuid(), "owner_gid": os.getgid()}
            self.gate.validate_private_file(approved, **params)
            os.chmod(approved, 0o644)
            with self.assertRaises(self.gate.ApprovalDenied):
                self.gate.validate_private_file(approved, **params)
            os.chmod(approved, 0o600)
            alias = parent / "alias.json"
            alias.symlink_to(approved)
            with self.assertRaises(self.gate.ApprovalDenied):
                self.gate.validate_private_file(alias, **params)
            os.chmod(parent, 0o755)
            with self.assertRaises(self.gate.ApprovalDenied):
                self.gate.validate_private_file(approved, **params)

    def test_parser_requires_owner_file_and_never_mints_approval(self):
        with tempfile.TemporaryDirectory() as folder:
            doc = Path(folder) / "approval.json"
            doc.write_text(json.dumps(self.valid_decision()))
            # Pure parser test uses mocked filesystem authorization only;
            # production CLI always checks root:root owner and 0700/0600.
            with patch.object(self.gate, "validate_private_file"):
                self.gate.check_release_approval(doc, IMAGE)
            doc.write_text('{"schema":1,"schema":2}')
            with patch.object(self.gate, "validate_private_file"):
                with self.assertRaises(self.gate.ApprovalDenied):
                    self.gate.check_release_approval(doc, IMAGE)

    def test_production_cli_refuses_missing_approval_without_docker(self):
        with tempfile.TemporaryDirectory() as folder:
            proc = subprocess.run(
                [sys.executable, str(SCRIPT), "--file",
                 str(Path(folder) / "not-present.json"), "--image-id", IMAGE],
                capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 2)
            self.assertIn("H15_OWNER_IMAGE_APPROVAL=REFUSED", proc.stdout)
            self.assertNotIn("PASS", proc.stdout)

    def test_preflight_and_start_check_approval_before_docker(self):
        sh = DEPLOY.read_text()
        self.assertIn("production-approval.json", sh)
        self.assertIn('check_release_approval "$2"', sh)
        self.assertIn("OWNER_RELEASE_APPROVAL_REQUIRED", sh)
        self.assertLess(sh.index('check_release_approval "$2"'),
                        sh.index('    check_infrastructure\n', sh.index('case "$mode" in')))
        self.assertIn('[[ "$2" != "$EVALUATION_IMAGE" ]]', sh)
        self.assertNotIn("docker pull", sh)
        self.assertNotIn("docker build", sh)


if __name__ == "__main__":
    unittest.main()
