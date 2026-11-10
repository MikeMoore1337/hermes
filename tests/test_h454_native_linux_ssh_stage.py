"""H454 separate native Linux SSH staging: synthetic files, no production SSH."""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import h454_native_linux_ssh_stage as stage
from scripts.h454_native_readonly_bundle import (
    ARCHIVE_NAME, RECEIPT_NAME, SOURCE_FILES, build_bytes,
)

SHA = "b"*40


def bundle(target="hermes-vps"):
    source = {x: ("# synthetic " + x + "\n").encode() for x in SOURCE_FILES}
    return build_bytes(target=target, release_sha=SHA, sources=source)


class StageSyntheticContracts(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory(prefix="h454-ssh-stage-")
        self.addCleanup(t.cleanup)
        self.path = Path(t.name) / "private"
        self.path.mkdir(mode=0o700)
        self.uid = os.geteuid()

    def frame(self, target):
        archive, receipt = bundle(target)
        return stage.encode(target=target, release_sha=SHA,
                            archive=archive, receipt=receipt)

    def do_stage(self, target="hermes-vps"):
        return stage.stage(self.frame(target), target=target,
                           root=self.path, owner_uid=self.uid,
                           check_ancestors=False)

    def do_cleanup(self, target="hermes-vps"):
        return stage.cleanup(self.frame(target), target=target,
                             root=self.path, owner_uid=self.uid,
                             check_ancestors=False)

    def test_both_hosts_staged_then_reverted_exact_bundle_without_service(self):
        for target in sorted(stage.TARGETS):
            with self.subTest(target=target):
                before = set(self.path.iterdir())
                result = self.do_stage(target)
                self.assertEqual(result["status"], "SOURCE_STAGED_NOT_INSTALLED")
                self.assertFalse(result["service_installed"])
                self.assertFalse(result["native_device_paired"])
                self.assertFalse(result["original_host_files_touched"])
                leaf = self.path / (target + "-" + SHA)
                self.assertEqual({x.name for x in leaf.iterdir()},
                                 {ARCHIVE_NAME, RECEIPT_NAME})
                self.assertTrue(all(
                    x.stat().st_mode & 0o777 == 0o600 for x in leaf.iterdir()))
                verified = stage.verify_report(
                    stage._canonical(result) + b"\n",
                    expected_target=target, release_sha=SHA,
                    bundle_sha256=result["bundle_sha256"], action="stage",
                )
                self.assertEqual(verified, result)
                with self.assertRaises(stage.StageDenied):
                    self.do_stage(target)  # never overwrite
                cleaned = self.do_cleanup(target)
                self.assertEqual(cleaned["status"], "SOURCE_STAGING_CLEANED")
                self.assertEqual(set(self.path.iterdir()), before)

    def test_bad_archive_receipt_digest_target_and_duplicate_json_refused(self):
        for target in stage.TARGETS:
            frame = self.frame(target)
            fields = json.loads(frame)
            for mutation in (
                {**fields, "bundle_sha256": "c"*64},
                {**fields, "target": "other-vps"},
                {**fields, "release_sha": "f"*40},
                {**fields, "archive_b64": base64.b64encode(b"invalid").decode()},
                {**fields, "receipt_b64": base64.b64encode(b"invalid").decode()},
                {**fields, "owner_approved": True},
            ):
                with self.subTest(target=target,fields=list(mutation)), self.assertRaises(
                    stage.StageDenied
                ):
                    stage.decode(stage._canonical(mutation), expected_target=target)
            with self.assertRaises(stage.StageDenied):
                stage.decode(frame + b"\n", expected_target=target)
            with self.assertRaises(stage.StageDenied):
                stage.decode(b'{"target":"a","target":"b"}', expected_target=target)
            with self.assertRaises(stage.StageDenied):
                stage.decode(frame * 2, expected_target=target)
            with self.assertRaises(stage.StageDenied):
                stage.decode(b"Z" * (stage.MAX_FRAME + 1), expected_target=target)
            self.assertEqual(list(self.path.iterdir()), [])

    def test_cleanup_rejects_tampered_member_and_leaves_original_untouched(self):
        self.do_stage()
        leaf = self.path / ("hermes-vps-" + SHA)
        original = leaf / RECEIPT_NAME
        original.write_text("different receipt")
        with self.assertRaises(stage.StageDenied):
            self.do_cleanup()
        self.assertTrue(leaf.exists())
        self.assertTrue(original.exists())
        original.unlink()
        original.symlink_to(self.path)
        with self.assertRaises(stage.StageDenied):
            self.do_cleanup()
        self.assertTrue(leaf.exists())

    def test_foreign_release_folder_collision_never_deleted(self):
        leaf = self.path / ("hermes-vps-" + SHA)
        leaf.mkdir(mode=0o700)
        marker = leaf / "foreign.txt"
        marker.write_text("other device bytes")
        with self.assertRaises(stage.StageDenied):
            self.do_stage()
        self.assertEqual(marker.read_text(), "other device bytes")

    def test_separate_owner_approved_host_ssh_environments_and_no_deploy_key(self):
        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github/workflows/h454-native-linux-ssh-stage.yml").read_text()
        for marker in (
            "workflow_dispatch:", "release_sha:", "stage", "cleanup",
            "h454-hermes-native-stage", "h454-yfc-native-stage",
            "H454_NATIVE_STAGE_OWNER_APPROVED",
            "H454_NATIVE_STAGE_HOST", "H454_NATIVE_STAGE_KEY",
            "H454_NATIVE_STAGE_KNOWN_HOSTS",
            "refs/heads/main", "Hermes repository checks",
            "Hermes Control Center UI", "StrictHostKeyChecking=yes",
            "IdentitiesOnly=yes", "ForwardAgent=no",
            "RequestTTY=no", "ClearAllForwardings=yes",
            "h454-native-stage@$HOST",
            "H454_NATIVE_LINUX_SYSTEMD_INSTALLED=NO",
            "H454_NATIVE_DEVICE_PAIRED=NO",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, workflow)
        for forbidden in (
            "HERMES_DEPLOY_KEY", "sudo ", "useradd ", "systemctl ",
            "docker ", "ssh-keyscan ", "curl ", "scp ",
            "workflow_dispatch: push", "pull_request:",
        ):
            self.assertNotIn(forbidden, workflow)

    def test_owner_account_and_forced_ssh_command_are_mandatory(self):
        with patch.dict(os.environ, {"SSH_ORIGINAL_COMMAND": "stage"}):
            with patch.object(stage.os, "geteuid", return_value=0):
                with self.assertRaises(stage.StageDenied):
                    stage._forced_ssh_preflight("stage")
        with patch.dict(os.environ, {"SSH_ORIGINAL_COMMAND": "arbitrary"}, clear=False):
            with self.assertRaises(stage.StageDenied):
                stage._forced_ssh_preflight("stage")

    def test_malicious_report_or_extra_field_does_not_prove_stage(self):
        result = self.do_stage()
        valid=stage._canonical(result)+b"\n"
        for bad in (
            valid + b"\n",
            valid.replace(b'"service_installed":false', b'"service_installed":true'),
            valid.replace(b'"status":', b'"extra":1,"status":'),
            valid.replace(b'"bundle_sha256":', b'"bundle_sha256":"wrong","bundle_sha256":'),
            valid.replace(b'"release_sha":', b'"release_sha":"wrong","release_sha":'),
        ):
            with self.subTest(bad=bad[:50]), self.assertRaises(stage.StageDenied):
                stage.verify_report(
                    bad, expected_target="hermes-vps", release_sha=SHA,
                    bundle_sha256=result["bundle_sha256"], action="stage",
                )


if __name__ == "__main__":
    unittest.main()
