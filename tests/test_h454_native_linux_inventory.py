"""H454 SSH inventory is strictly read only, canonical and nonprivileged."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from scripts import h454_native_linux_inventory as inv


def fixture(target="hermes-vps"):
    return {
        "schema": inv.SCHEMA, "target": target, "arch": "x64",
        "operator_sha256": hashlib.sha256(Path(inv.__file__).read_bytes()).hexdigest(),
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
                for raw in (encoded(fixture(target)),
                            encoded(fixture(target)) + b"\n"):
                    got = inv.verify_report(raw, expected_target=target)
                    self.assertFalse(got["native_host_pass"])
                    self.assertEqual(got["owner_roots"], "UNVERIFIED")

    def test_forged_or_private_output_denied(self):
        baseline = fixture()
        cases = (
            b"{}", b"\xff", b" " + encoded(baseline),
            encoded(baseline) + b"\n\n",
            encoded({**baseline, "target": "yfc-vps"}),
            encoded({**baseline, "native_host_pass": True}),
            encoded({**baseline, "owner_roots": "/root"}),
            encoded({**baseline, "operator_sha256": "0"*64}),
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

    def test_manual_workflow_keys_are_scoped_to_one_host_environment(self):
        flow = (Path(__file__).resolve().parents[1] /
                ".github/workflows/h454-native-linux-inventory.yml").read_text(
                    encoding="utf-8"
                )
        for expected in (
            "workflow_dispatch:", "contents: read", "actions: read",
            "environment:", "h454-hermes-native-inventory",
            "h454-yfc-native-inventory",
            "secrets.H454_NATIVE_INVENTORY_KEY",
            "secrets.H454_NATIVE_INVENTORY_HOST",
            "secrets.H454_NATIVE_INVENTORY_KNOWN_HOSTS",
            "StrictHostKeyChecking=yes", "ClearAllForwardings=yes",
            "timeout 25s ssh", "head -c 4097",
            "persist-credentials: false", "inventory",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, flow)
        for forbidden in (
            "secrets.H454_NATIVE_HERMES_INVENTORY_KEY",
            "secrets.H454_NATIVE_YFC_INVENTORY_KEY",
            "secrets.HERMES_DEPLOY_KEY",
            "ssh-keyscan", "sudo ", "systemctl ",
            "pull_request:", "push:", "sshpass",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, flow)

    def test_bad_service_identity_is_blocked(self):
        from types import SimpleNamespace
        with patch.object(inv.pwd, "getpwnam",
                          return_value=SimpleNamespace(
                              pw_uid=0, pw_gid=0, pw_shell="/bin/bash")):
            self.assertEqual(inv._identity(), "BLOCKED")


if __name__ == "__main__":
    unittest.main()
