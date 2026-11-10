"""H454 SSH inventory is strictly read only, canonical and nonprivileged."""
from __future__ import annotations

import json
import unittest
from unittest.mock import patch
from scripts import h454_native_linux_inventory as inv


def fixture(target="hermes-vps"):
    return {
        "schema": inv.SCHEMA, "target": target, "arch": "x64",
        "systemd": "PRESENT", "service_user": "ABSENT",
        "service_unit": "ABSENT", "release_directory": "ABSENT",
        "owner_roots": "UNVERIFIED", "native_host_pass": False,
        "host_changes": False,
    }


def encoded(value):
    return json.dumps(value, sort_keys=True,
                      separators=(",", ":")).encode("ascii")


class InventoryContracts(unittest.TestCase):
    def test_strict_report_for_both_native_targets(self):
        for target in inv.TARGETS:
            with self.subTest(target=target):
                got = inv.verify_report(encoded(fixture(target)),
                                        expected_target=target)
                self.assertFalse(got["native_host_pass"])
                self.assertEqual(got["owner_roots"], "UNVERIFIED")

    def test_forged_or_private_output_denied(self):
        baseline = fixture()
        cases = (
            b"{}", b"\xff", encoded(baseline)+b"\n",
            encoded({**baseline, "target": "yfc-vps"}),
            encoded({**baseline, "native_host_pass": True}),
            encoded({**baseline, "owner_roots": "/root"}),
            encoded({**baseline, "service_unit": "/etc/secret"}),
            encoded({**baseline, "owner_approved": True}),
            encoded(baseline).replace(
                b'"target":', b'"target":"fake","target":', 1),
        )
        for value in cases:
            with self.subTest(raw=value[:24]), self.assertRaises(inv.InventoryDenied):
                inv.verify_report(value, expected_target="hermes-vps")

    def test_only_exact_original_ssh_command_under_nonroot(self):
        with patch.object(inv.sys, "platform", "linux"), \
             patch.object(inv.os, "geteuid", return_value=1001), \
             patch.object(inv.os, "getegid", return_value=1001), \
             patch.object(inv.platform, "machine", return_value="x86_64"), \
             patch.object(inv, "_identity", return_value="ABSENT"), \
             patch.object(inv, "_path_status", return_value="ABSENT"), \
             patch.dict(inv.os.environ, {"SSH_ORIGINAL_COMMAND": "inventory",
                                          "MY_SECRET": "SECRET_NEVER_LEAK"}), \
             patch("subprocess.run", side_effect=AssertionError("no subprocess")):
            got = inv.inventory("hermes-vps")
        self.assertNotIn("SECRET_NEVER_LEAK", str(got))
        self.assertFalse(got["host_changes"])
        with patch.object(inv.sys, "platform", "linux"), \
             patch.object(inv.os, "geteuid", return_value=1001), \
             patch.object(inv.os, "getegid", return_value=1001), \
             patch.dict(inv.os.environ, {"SSH_ORIGINAL_COMMAND": "bash"}):
            with self.assertRaises(inv.InventoryDenied):
                inv.inventory("hermes-vps")
        with patch.object(inv.sys, "platform", "linux"), \
             patch.object(inv.os, "geteuid", return_value=0), \
             patch.dict(inv.os.environ, {"SSH_ORIGINAL_COMMAND": "inventory"}):
            with self.assertRaises(inv.InventoryDenied):
                inv.inventory("hermes-vps")

    def test_bad_service_identity_is_blocked(self):
        from types import SimpleNamespace
        with patch.object(inv.pwd, "getpwnam",
                          return_value=SimpleNamespace(
                              pw_uid=0, pw_gid=0, pw_shell="/bin/bash")):
            self.assertEqual(inv._identity(), "BLOCKED")


if __name__ == "__main__":
    unittest.main()
