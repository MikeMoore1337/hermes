"""Validate H-15 production split-root timer safety; no Cloudflare calls."""
from __future__ import annotations

import os
from pathlib import Path
import stat
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from control_center import cloudflare_analytics_runner as runner


SHA = "a" * 40


class CloudflareDailyRunnerTests(unittest.TestCase):
    def setup_tree(self, root: Path):
        ui = root / "hermes-control-center"
        owner = root / "hermes-agent-owner"
        release = ui / "releases" / ("main-" + SHA)
        release.mkdir(parents=True)
        target = owner / "releases" / ("main-" + SHA)
        source = target / "scripts"
        source.mkdir(parents=True)
        for name in ("h15_cloudflare_analytics_collect.py",
                     "h15_cloudflare_analytics_probe.py"):
            (source / name).write_text("# pinned owner source\n")
        (ui / "current").symlink_to(release, target_is_directory=True)
        return ui, owner, target

    def test_accept_exact_matching_root_owner_release(self):
        with TemporaryDirectory() as tmp:
            ui, owner, target = self.setup_tree(Path(tmp))
            self.assertEqual(runner.trusted_owner_release(
                ui_root=ui, owner_root=owner,
                expected_uid=os.getuid()), target)
            with self.assertRaises(ValueError):
                runner.trusted_owner_release(
                    ui_root=ui, owner_root=owner,
                    expected_uid=os.getuid() + 1)

    def test_reject_mismatched_sha_symlink_or_group_writable_sources(self):
        with TemporaryDirectory() as tmp:
            ui, owner, target = self.setup_tree(Path(tmp))
            source = target / "scripts" / "h15_cloudflare_analytics_collect.py"
            source.chmod(0o666)
            with self.assertRaises(ValueError):
                runner.trusted_owner_release(
                    ui_root=ui, owner_root=owner, expected_uid=os.getuid())
            source.chmod(0o644)
            ui_current = ui / "current"
            ui_current.unlink()
            other = ui / "releases" / ("main-" + "b" * 40)
            other.mkdir()
            ui_current.symlink_to(other)
            with self.assertRaises(ValueError):
                runner.trusted_owner_release(
                    ui_root=ui, owner_root=owner, expected_uid=os.getuid())
            ui_current.unlink()
            ui_current.symlink_to(Path(tmp))
            with self.assertRaises(ValueError):
                runner.trusted_owner_release(
                    ui_root=ui, owner_root=owner, expected_uid=os.getuid())

    def test_bad_release_fails_before_any_cloudflare_credential_read(self):
        with patch.object(runner.os, "geteuid", return_value=0), \
             patch.object(runner, "trusted_owner_release",
                          side_effect=ValueError("untrusted")), \
             patch("scripts.h15_cloudflare_analytics_probe.load_credentials") as token:
            self.assertEqual(runner.main(), 2)
            token.assert_not_called()


if __name__ == "__main__":
    unittest.main()
