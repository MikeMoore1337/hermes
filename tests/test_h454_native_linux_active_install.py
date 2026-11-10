"""H454 owner-root ACTIVE Linux unit registration, disabled-only fixtures.

Real source archives and exclusive temporary file writes. No production
host, systemd service, SSH, owner credential or original source file IO.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock, patch

from scripts import h454_native_linux_install_off as off
from scripts import h454_native_linux_active_install as active
from scripts.h454_native_linux_active_unit import render_active_unit
from tests.test_h454_native_linux_install_off import fixture, RELEASE, TARGET


class NativeActiveInstallTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="h454-real-linux-unit-")
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.paths = off.InstallPaths(
            releases=root / "releases",
            units=root / "units",
            receipts=root / "receipts",
        )
        for item in (self.paths.releases, self.paths.units, self.paths.receipts):
            item.mkdir(mode=0o700)
        bundle, receipt, sha, manifest = fixture()
        self.manifest=manifest
        self.plan = off.plan_bytes(
            target=TARGET, release_sha=RELEASE,
            bundle_sha256=sha,manifest=manifest,
            bundle=bundle, receipt=receipt,
        )
        self.unit = render_active_unit(
            manifest,target=TARGET,release_sha=RELEASE,
            manifest_sha256=hashlib.sha256(manifest).hexdigest(),
            relay_ipv4="8.8.4.4",dns_ipv4="1.1.1.1",
        )
        self.daemon=Mock()
        with patch.object(off.sys,"platform","linux"):
            off._install_off(
                self.plan,paths=self.paths,reload_daemon=self.daemon,
                owner_uid=os.geteuid(),check_ancestors=False,
            )
        self.daemon.reset_mock()

    def args(self, **override):
        value=dict(
            plan=self.plan,unit_text=self.unit,manifest=self.manifest,
            relay_ipv4="8.8.4.4",dns_ipv4="1.1.1.1",
            paths=self.paths,reload_daemon=self.daemon,
            is_disabled=lambda _unit: True,
            owner_uid=os.geteuid(),ancestors=False,
        )
        value.update(override)
        return value

    def test_actual_exclusive_disabled_registration_and_clean_rollback(self):
        with patch.object(active.sys,"platform","linux"):
            report=active.install_disabled(**self.args())
        self.assertEqual(report["status"],"NATIVE_ACTIVE_UNIT_INSTALLED_DISABLED")
        self.assertFalse(report["started"])
        self.assertFalse(report["enabled"])
        self.assertFalse(report["device_paired"])
        unit,receipt=active._paths(self.plan,self.paths)
        self.assertEqual(unit.read_bytes(),self.unit.encode())
        self.assertEqual(receipt.read_bytes(),
                         active._unit_receipt(self.plan,self.unit.encode()))
        self.assertEqual(unit.stat().st_mode & 0o777,0o644)
        self.assertEqual(receipt.stat().st_mode & 0o777,0o600)
        self.daemon.assert_called_once()
        with patch.object(active.sys,"platform","linux"):
            with self.assertRaises(active.ActiveInstallDenied):
                active.install_disabled(**self.args())
            result=active.rollback_disabled(**self.args())
        self.assertEqual(result["status"],"NATIVE_ACTIVE_UNIT_ROLLED_BACK")
        self.assertFalse(unit.exists())
        self.assertTrue(receipt.exists())  # immutable audit receipt retained
        release,preflight,source_receipt=off._fixed_paths(self.plan,self.paths)
        self.assertTrue(release.is_dir())
        self.assertTrue(preflight.is_file())
        self.assertTrue(source_receipt.is_file())
        self.assertEqual(self.daemon.call_count,2)

    def test_forged_unit_cannot_change_exec_or_widen_permissions(self):
        originals=(
            self.unit.replace("IPAddressDeny=any","IPAddressDeny="),
            self.unit.replace("ProtectSystem=strict","ProtectSystem=full"),
            self.unit.replace("User=hermes-commander-native","User=root"),
            self.unit.replace("ExecStart=/usr/bin/python3",
                              "ExecStart=/bin/bash"),
            self.unit.replace("Restart=on-success","Restart=always"),
            self.unit + "\nExecStartPost=/bin/sh\n",
        )
        for value in originals:
            with self.subTest(modification=value[-90:]):
                with patch.object(active.sys,"platform","linux"), \
                     self.assertRaises(active.ActiveInstallDenied):
                    active.install_disabled(**self.args(unit_text=value))
        unit,receipt=active._paths(self.plan,self.paths)
        self.assertFalse(unit.exists())
        self.assertFalse(receipt.exists())
        self.daemon.assert_not_called()

    def test_root_only_staged_source_must_remain_bitwise_original(self):
        release,preflight,original=off._fixed_paths(self.plan,self.paths)
        data=release/"scripts/h454_native_linux_runtime.py"
        data.chmod(0o644)
        data.write_bytes(b"unreviewed modification")
        with patch.object(active.sys,"platform","linux"), \
             self.assertRaises(active.ActiveInstallDenied):
            active.install_disabled(**self.args())
        unit,receipt=active._paths(self.plan,self.paths)
        self.assertFalse(unit.exists())
        self.assertFalse(receipt.exists())
        self.daemon.assert_not_called()

    def test_foreign_unit_and_symlink_are_not_overwritten_or_removed(self):
        unit,receipt=active._paths(self.plan,self.paths)
        unit.write_text("FOREIGN unit",encoding="ascii")
        with patch.object(active.sys,"platform","linux"), \
             self.assertRaises(active.ActiveInstallDenied):
            active.install_disabled(**self.args())
        self.assertEqual(unit.read_text(),"FOREIGN unit")
        unit.unlink()
        outside=self.paths.receipts/"original.txt"
        outside.write_text("original")
        unit.symlink_to(outside)
        with patch.object(active.sys,"platform","linux"), \
             self.assertRaises(active.ActiveInstallDenied):
            active.install_disabled(**self.args())
        self.assertEqual(outside.read_text(),"original")
        self.assertFalse(receipt.exists())

    def test_failed_reload_or_live_service_rolls_back_only_new_files(self):
        unit,receipt=active._paths(self.plan,self.paths)
        reject=Mock(side_effect=[OSError("synthetic daemon reload"),None])
        with patch.object(active.sys,"platform","linux"), \
             self.assertRaises(active.ActiveInstallDenied):
            active.install_disabled(**self.args(reload_daemon=reject))
        self.assertFalse(unit.exists())
        self.assertFalse(receipt.exists())
        self.assertEqual(reject.call_count,2)
        self.daemon.assert_not_called()
        with patch.object(active.sys,"platform","linux"), \
             self.assertRaises(active.ActiveInstallDenied):
            active.install_disabled(**self.args(is_disabled=lambda _:False))
        self.assertFalse(unit.exists())
        self.assertFalse(receipt.exists())
        self.assertEqual(self.daemon.call_count,2)

    def test_rollback_active_or_tampered_unit_fails_closed(self):
        with patch.object(active.sys,"platform","linux"):
            active.install_disabled(**self.args())
        unit,receipt=active._paths(self.plan,self.paths)
        with patch.object(active.sys,"platform","linux"), \
             self.assertRaises(active.ActiveInstallDenied):
            active.rollback_disabled(**self.args(is_disabled=lambda _:False))
        self.assertTrue(unit.exists())
        unit.chmod(0o644)
        unit.write_text("changed unit")
        with patch.object(active.sys,"platform","linux"), \
             self.assertRaises(active.ActiveInstallDenied):
            active.rollback_disabled(**self.args())
        self.assertTrue(unit.exists())
        self.assertTrue(receipt.exists())

    def test_wrong_egress_or_manifest_digest_is_denied_without_files(self):
        for modifications in (
            {"relay_ipv4":"1.1.1.1"},
            {"dns_ipv4":"127.0.0.1"},
            {"manifest":self.manifest+b"\n"},
            {"unit_text":self.unit.replace(
                "--manifest-sha256 ","--manifest-sha256 0")},
        ):
            with self.subTest(change=modifications), \
                 patch.object(active.sys,"platform","linux"), \
                 self.assertRaises(active.ActiveInstallDenied):
                active.install_disabled(**self.args(**modifications))
        unit,receipt=active._paths(self.plan,self.paths)
        self.assertFalse(unit.exists())
        self.assertFalse(receipt.exists())

    def test_cli_never_installs_without_real_privileged_owner_tty(self):
        with patch.object(active.os,"geteuid",return_value=0), \
             patch.object(active.sys,"platform","linux"), \
             patch.object(active.sys,"stdin",SimpleNamespace(isatty=lambda:False)), \
             self.assertRaises(active.ActiveInstallDenied):
            active._owner_tty_confirm(self.plan,"INSTALL",self.unit)


if __name__=="__main__":
    unittest.main()
