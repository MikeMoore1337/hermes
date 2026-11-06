"""Offline contract tests for the owner-approved, but NOT installed, Docker GC fix."""
from __future__ import annotations

import os
import subprocess
import unittest
from pathlib import Path
from unittest.mock import Mock, call, patch

from scripts import h01_docker_gc_safe as gc
from scripts.h01_ops_agent_service import H01Denied


class H01GCProtectionTests(unittest.TestCase):
    def host(self):
        return (
            patch.object(gc.os, "geteuid", return_value=0),
            patch.object(gc.socket, "gethostname", return_value=gc.TARGET_HOST),
        )

    def test_default_dry_run_never_invokes_gc(self):
        root, hostname = self.host()
        with root, hostname, patch.object(gc, "safe_image", return_value="sha256:" + "a" * 64) as check, \
                patch.object(gc.subprocess, "run") as child:
            self.assertEqual(gc.run_gc(), {
                "status": "DRY_RUN", "pin": "VERIFIED", "mutated": False,
            })
        check.assert_called_once()
        child.assert_not_called()

    def test_wrong_host_denied_even_for_dry_run(self):
        with patch.object(gc.socket, "gethostname", return_value="other-vps"), \
                patch.object(gc.os, "geteuid", return_value=0), \
                patch.object(gc, "safe_image") as check, \
                patch.object(gc.subprocess, "run") as child:
            with self.assertRaisesRegex(gc.GCBlocked, "wrong_host_or_privilege"):
                gc.run_gc(apply=True)
        check.assert_not_called()
        child.assert_not_called()

    def test_missing_or_invalid_pinned_image_blocks_all_pruning(self):
        root, hostname = self.host()
        with root, hostname, patch.object(gc, "safe_image",
                side_effect=H01Denied("patched_image_not_verified")), \
                patch.object(gc.subprocess, "run") as child:
            with self.assertRaisesRegex(gc.GCBlocked, "h01_image_pin_not_verified"):
                gc.run_gc(apply=True)
        child.assert_not_called()

    def test_gc_preserves_bounded_policy_image_label(self):
        root, hostname = self.host()
        image = "sha256:" + "a" * 64
        with root, hostname, patch.object(gc, "safe_image", return_value=image) as check, \
                patch.object(gc.subprocess, "run", return_value=Mock(returncode=0)) as child:
            result = gc.run_gc(apply=True)
        self.assertEqual(result["status"], "GC_PASS")
        self.assertEqual(check.call_count, 2)
        self.assertEqual(child.call_count, 3)
        self.assertEqual(child.call_args_list[-1].args[0], gc.GC_JOBS[-1][1])
        self.assertEqual(gc.GC_JOBS[-1][1], (
            "docker", "image", "prune", "-af", "--filter", "until=168h",
            "--filter", "label!=hermes.native.tool.policy=bounded-v0222",
        ))
        # No unfenced image-prune command is permitted.
        for name, args in gc.GC_JOBS:
            if args[:3] == ("docker", "image", "prune"):
                self.assertIn(gc.PROTECTED_POLICY_LABEL, args)

    def test_failed_prior_stage_never_runs_image_prune(self):
        root, hostname = self.host()
        with root, hostname, patch.object(gc, "safe_image", return_value="sha256:" + "a" * 64), \
                patch.object(gc.subprocess, "run", side_effect=[
                    Mock(returncode=0), Mock(returncode=1),
                ]) as child:
            with self.assertRaisesRegex(gc.GCBlocked, "builder_failed"):
                gc.run_gc(apply=True)
        self.assertEqual(child.call_count, 2)

    def test_after_gc_image_must_still_match_exact_digest(self):
        root, hostname = self.host()
        with root, hostname, patch.object(gc, "safe_image", side_effect=[
                    "sha256:" + "a" * 64, "sha256:" + "b" * 64,
                ]), patch.object(gc.subprocess, "run", return_value=Mock(returncode=0)):
            with self.assertRaisesRegex(gc.GCBlocked, "h01_image_changed_after_gc"):
                gc.run_gc(apply=True)

    def test_installable_wrapper_routes_only_through_guarded_module(self):
        path = Path(__file__).resolve().parents[1] / "deploy/hermes-docker-gc.sh"
        wrapper = path.read_text(encoding="utf-8")
        self.assertIn("set -euo pipefail", wrapper)
        self.assertIn("cd /opt/hermes-agent-owner", wrapper)
        self.assertIn("scripts.h01_docker_gc_safe --apply", wrapper)
        self.assertNotIn("docker image prune", wrapper)
        self.assertNotIn("docker system prune", wrapper)


if __name__ == "__main__":
    unittest.main()
