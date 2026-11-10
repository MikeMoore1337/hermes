"""H454 disabled Linux source installer - no actual OS installation in tests."""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from device_fabric.native_install_preview import SCHEMA, SERVICE
from scripts import h454_native_linux_install_off as off
from scripts.h454_native_readonly_bundle import build_bytes, SOURCE_FILES

RELEASE = "a"*40
TARGET = "hermes-vps"


def fixture():
    source = {name: ("# synthetic " + name + "\n").encode("ascii")
              for name in SOURCE_FILES}
    bundle, receipt = build_bytes(
        target=TARGET, release_sha=RELEASE, sources=source,
    )
    sha = hashlib.sha256(bundle).hexdigest()
    service, identity = SERVICE[TARGET]
    manifest = json.dumps({
        "schema": SCHEMA, "target": TARGET, "release_sha": RELEASE,
        "artifact_sha256": sha, "service_name": service,
        "service_identity": identity, "start_state": "DISABLED",
        "access_mode": "READ_ONLY",
        "roots": [{"project": "hermes", "path": "/srv/hermes/source"}],
    }, sort_keys=True, separators=(",", ":")).encode("ascii")
    return bundle, receipt, sha, manifest


class PureInstallPlan(unittest.TestCase):
    def setUp(self):
        self.bundle, self.receipt, self.sha, self.manifest = fixture()

    def plan(self, **changes):
        opts = dict(target=TARGET, release_sha=RELEASE,
                    bundle_sha256=self.sha, manifest=self.manifest,
                    bundle=self.bundle, receipt=self.receipt)
        return off.plan_bytes(**{**opts, **changes})

    def test_verified_bundle_and_inert_unit_no_effects(self):
        p = self.plan()
        self.assertEqual(len(p.source), len(SOURCE_FILES))
        self.assertEqual({x for x, _ in p.source}, set(SOURCE_FILES))
        self.assertIn(b"PrivateNetwork=yes\n", p.unit)
        self.assertNotIn(b"\n[Install]\n", p.unit)
        self.assertNotIn(b"Restart=always", p.unit)
        self.assertIn(b"--target hermes-vps", p.unit)
        self.assertEqual(p.bundle_sha256, self.sha)
        self.assertNotIn("/srv/hermes", str(off.preview(p)))
        self.assertNotIn("secret", repr(p))
        self.assertFalse(off.preview(p)["installed"])

    def test_bundle_receipt_manifest_or_target_tamper_denied(self):
        tests = (
            {"bundle_sha256": "f"*64}, {"bundle": self.bundle + b"x"},
            {"receipt": self.receipt + b"\n"},
            {"manifest": self.manifest + b"\n"},
            {"release_sha": "f"*40}, {"target": "yfc-vps"},
            {"target": "windows"}, {"bundle": b"x"*100},
        )
        for item in tests:
            with self.subTest(item=str(item)[:90]), self.assertRaises(
                off.DisabledInstallDenied
            ):
                self.plan(**item)

    def test_owner_approval_must_not_be_supplied_in_manifest(self):
        d = json.loads(self.manifest)
        for dangerous in ("owner_approved", "install_now", "sudo", "commands"):
            with self.subTest(dangerous=dangerous), self.assertRaises(
                off.DisabledInstallDenied
            ):
                self.plan(manifest=json.dumps(
                    {**d, dangerous: True},
                    sort_keys=True, separators=(",", ":"),
                ).encode("ascii"))

    def test_plan_has_no_subprocess_or_file_write(self):
        with patch("subprocess.run", side_effect=AssertionError("run forbidden")), \
             patch("builtins.open", side_effect=AssertionError("open forbidden")):
            p = self.plan()
        self.assertEqual(p.target, TARGET)

    def test_cli_default_is_explicit_and_failure_is_sanitized(self):
        out = io.StringIO()
        with patch("sys.stdout", out):
            exit_code = off.main([
                "plan", "--target", TARGET, "--release-sha", "bad",
                "--bundle-sha256", self.sha,
                "--manifest", "/definitely/missing", "--bundle", "/not/here",
                "--receipt", "/missing/receipt",
            ])
        self.assertEqual(exit_code, 2)
        self.assertIn("H454_LINUX_DISABLED_INSTALL_DENIED", out.getvalue())
        self.assertNotIn("/definitely", out.getvalue())


class TemporaryDisabledInstallation(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="h454-linux-disabled-")
        self.addCleanup(self.scratch.cleanup)
        root = Path(self.scratch.name)
        self.paths = off.InstallPaths(
            releases=root / "releases",
            units=root / "units",
            receipts=root / "receipts",
        )
        for item in (self.paths.releases, self.paths.units, self.paths.receipts):
            item.mkdir(mode=0o700)
        bundle, receipt, sha, manifest = fixture()
        self.plan = off.plan_bytes(
            target=TARGET, release_sha=RELEASE, bundle_sha256=sha,
            bundle=bundle, receipt=receipt, manifest=manifest,
        )
        self.daemon = Mock()

    def install(self):
        with patch.object(off.sys, "platform", "linux"):
            return off._install_off(
                self.plan, paths=self.paths, reload_daemon=self.daemon,
                owner_uid=os.geteuid(), check_ancestors=False,
            )

    def test_actual_temp_source_and_unit_created_disabled_no_start(self):
        result = self.install()
        release, unit, receipt = off._fixed_paths(self.plan, self.paths)
        self.assertEqual(result["status"], "DISABLED_SOURCE_INSTALLED")
        self.assertEqual(unit.read_bytes(), self.plan.unit)
        self.assertEqual(receipt.read_bytes(), off._expected_receipt(self.plan))
        self.assertEqual({x.relative_to(release).as_posix() for x in
                          release.rglob("*") if x.is_file()}, set(SOURCE_FILES))
        self.assertTrue(all((p.stat().st_mode & 0o222) == 0
                            for p in release.rglob("*") if p.is_file()))
        self.daemon.assert_called_once()
        with self.assertRaises(off.DisabledInstallDenied):
            self.install()  # no overwrite or second daemon-reload
        self.daemon.assert_called_once()

    def test_rollback_only_exact_new_install_never_external_state(self):
        self.install()
        with patch.object(off.sys, "platform", "linux"):
            report = off._rollback_off(
                self.plan, paths=self.paths, reload_daemon=self.daemon,
                inactive=lambda _unit: True, owner_uid=os.geteuid(),
                check_ancestors=False,
            )
        release, unit, receipt = off._fixed_paths(self.plan, self.paths)
        self.assertEqual(report["status"], "DISABLED_SOURCE_ROLLED_BACK")
        self.assertFalse(release.exists())
        self.assertFalse(unit.exists())
        self.assertTrue(receipt.exists())  # audit evidence retained
        self.assertEqual(self.daemon.call_count, 2)

    def test_rollback_denies_active_service_or_tampered_unit(self):
        self.install()
        with patch.object(off.sys, "platform", "linux"):
            with self.assertRaises(off.DisabledInstallDenied):
                off._rollback_off(
                    self.plan, paths=self.paths, reload_daemon=self.daemon,
                    inactive=lambda _unit: False, owner_uid=os.geteuid(),
                    check_ancestors=False,
                )
        _release, unit, _receipt = off._fixed_paths(self.plan, self.paths)
        unit.write_bytes(b"malicious modified unit")
        with patch.object(off.sys, "platform", "linux"):
            with self.assertRaises(off.DisabledInstallDenied):
                off._rollback_off(
                    self.plan, paths=self.paths, reload_daemon=self.daemon,
                    inactive=lambda _unit: True, owner_uid=os.geteuid(),
                    check_ancestors=False,
                )
        self.assertTrue(unit.exists())

    def test_partial_write_cleanup_and_occupied_release_survive(self):
        release, unit, receipt = off._fixed_paths(self.plan, self.paths)
        # The exclusive writer must remove only the file it created.
        target = self.paths.units / "partial-created.tmp"
        with patch.object(off.os, "fchmod", side_effect=OSError("synthetic failure")):
            with self.assertRaises(off.DisabledInstallDenied):
                off._write_new(target, b"synthetic", 0o600)
        self.assertFalse(target.exists())
        release.mkdir()
        marker = release / "preexisting.txt"
        marker.write_text("another actor's original data", encoding="utf-8")
        with self.assertRaises(off.DisabledInstallDenied):
            self.install()
        self.assertEqual(marker.read_text(encoding="utf-8"),
                         "another actor's original data")
        self.assertFalse(unit.exists())
        self.assertFalse(receipt.exists())

    def test_rollback_denies_modified_source_content(self):
        self.install()
        release, unit, receipt = off._fixed_paths(self.plan, self.paths)
        file = release / self.plan.source[0][0]
        file.chmod(0o644)
        file.write_text("tampered source", encoding="utf-8")
        with patch.object(off.sys, "platform", "linux"):
            with self.assertRaises(off.DisabledInstallDenied):
                off._rollback_off(
                    self.plan, paths=self.paths, reload_daemon=self.daemon,
                    inactive=lambda _unit: True, owner_uid=os.geteuid(),
                    check_ancestors=False,
                )
        self.assertTrue(unit.exists())
        self.assertTrue(receipt.exists())
        self.assertEqual(self.daemon.call_count, 1)

    def test_symlink_parent_and_present_other_unit_are_denied(self):
        release, unit, receipt = off._fixed_paths(self.plan, self.paths)
        unit.symlink_to(self.paths.receipts)
        with self.assertRaises(off.DisabledInstallDenied):
            self.install()
        unit.unlink()
        with tempfile.TemporaryDirectory() as outside:
            self.paths.units.rmdir()
            self.paths.units.symlink_to(outside, target_is_directory=True)
            with self.assertRaises(off.DisabledInstallDenied):
                self.install()
        self.assertFalse(release.exists())
        self.assertFalse(receipt.exists())


if __name__ == "__main__":
    unittest.main()
