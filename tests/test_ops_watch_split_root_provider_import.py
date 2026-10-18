"""Regression for #295: split-root production layout, not just full CI checkout.

The regular CI checkout has control_center/ adjacent to ops_watch/, while the
VPS deploy deliberately splits those modules across two immutable roots.
"""
from __future__ import annotations

import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ops_watch import quota_alerts


SHA = "a" * 40


class OpsWatchProviderImportLayout(unittest.TestCase):
    def fixture(self, root: Path):
        ui = root / "hermes-control-center"
        owner = root / "hermes-agent-owner"
        release = ui / "releases" / ("main-" + SHA)
        (release / "control_center").mkdir(parents=True)
        (release / "control_center" / "__init__.py").write_text("")
        (release / "control_center" / "provider_registry.py").write_text(
            "def registry(**_kwargs): return {'providers': []}\n"
        )
        active_owner = owner / "releases" / ("main-" + SHA)
        (active_owner / "ops_watch").mkdir(parents=True)
        (active_owner / "ops_watch" / "quota_alerts.py").write_text("# pinned\n")
        (ui / "current").symlink_to(release, target_is_directory=True)
        return ui, owner, release

    def test_valid_pinned_split_root_reachable(self):
        with tempfile.TemporaryDirectory() as tmp:
            ui, owner, release = self.fixture(Path(tmp))
            self.assertEqual(quota_alerts.trusted_provider_release(
                ui_root=ui, owner_root=owner, expected_uid=os.getuid()), release)
            with patch.object(quota_alerts, "find_spec", return_value=None), \\
                    patch.object(quota_alerts, "trusted_provider_release",
                                 return_value=release), \\
                    patch.object(quota_alerts.sys, "path", [str(owner)]):
                quota_alerts._bind_control_center()
                self.assertEqual(quota_alerts.sys.path, [str(release), str(owner)])

    def test_monorepo_import_does_not_mutate_python_path(self):
        with patch.object(quota_alerts, "find_spec", return_value=object()), \\
                patch.object(quota_alerts, "trusted_provider_release") as finder, \\
                patch.object(quota_alerts.sys, "path", ["full-repo"]):
            quota_alerts._bind_control_center()
            finder.assert_not_called()
            self.assertEqual(quota_alerts.sys.path, ["full-repo"])

    def test_reject_symlink_outside_release(self):
        with tempfile.TemporaryDirectory() as tmp:
            ui, owner, release = self.fixture(Path(tmp))
            outer = Path(tmp) / "foreign" / ("main-" + SHA)
            outer.mkdir(parents=True)
            (ui / "current").unlink()
            (ui / "current").symlink_to(outer)
            with self.assertRaisesRegex(RuntimeError, "provider_release_untrusted"):
                quota_alerts.trusted_provider_release(
                    ui_root=ui, owner_root=owner, expected_uid=os.getuid())

    def test_reject_sha_mismatch_or_missing_current_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            ui, owner, release = self.fixture(Path(tmp))
            other = owner / "releases" / ("main-" + "b" * 40)
            (other / "ops_watch").mkdir(parents=True)
            (owner / "releases" / ("main-" + SHA) /
                "ops_watch" / "quota_alerts.py").unlink()
            with self.assertRaisesRegex(RuntimeError, "provider_release_untrusted"):
                quota_alerts.trusted_provider_release(
                    ui_root=ui, owner_root=owner, expected_uid=os.getuid())

    def test_reject_group_write_and_nonroot_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            ui, owner, release = self.fixture(Path(tmp))
            mode=release.stat().st_mode
            release.chmod(stat.S_IMODE(mode) | stat.S_IWGRP)
            try:
                with self.assertRaisesRegex(RuntimeError, "provider_release_untrusted"):
                    quota_alerts.trusted_provider_release(
                        ui_root=ui, owner_root=owner, expected_uid=os.getuid())
            finally:
                release.chmod(stat.S_IMODE(mode))
            with self.assertRaisesRegex(RuntimeError, "provider_release_untrusted"):
                quota_alerts.trusted_provider_release(
                    ui_root=ui, owner_root=owner,
                    expected_uid=os.getuid()+1000)

    def test_no_client_inference_ever_needed_for_root_selection(self):
        with tempfile.TemporaryDirectory() as tmp:
            ui, owner, release = self.fixture(Path(tmp))
            with patch("socket.socket", side_effect=AssertionError("unexpected network")):
                selected=quota_alerts.trusted_provider_release(
                    ui_root=ui,owner_root=owner,expected_uid=os.getuid())
                self.assertEqual(selected,release)


if __name__ == "__main__":
    unittest.main()
