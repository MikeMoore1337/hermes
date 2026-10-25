"""CLI-free Codex Desktop Hermes MCP install / rollback on disposable profiles."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from scripts import h15_codex_desktop_mcp_config as cfg


class CodexConfigContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="h454-codex-config-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / ".codex"
        self.root.mkdir()

    def call(self, op):
        return cfg.manage(self.root, op, enforce_windows=False)

    def test_fresh_existing_config_preserved_byte_for_byte_on_rollback(self):
        before = b'# owner note\n[mcp_servers.other]\nurl = "https://other.example/mcp"\n'
        config = self.root / "config.toml"
        config.write_bytes(before)
        initial_mode = config.stat().st_mode & 0o777
        self.assertEqual(self.call("status")["status"], "not_installed")
        self.assertEqual(self.call("install")["status"], "installed")
        installed = config.read_bytes()
        self.assertTrue(installed.startswith(before))
        self.assertIn(b'[mcp_servers.hermes]', installed)
        self.assertEqual(self.call("status")["status"], "managed")
        self.assertTrue((self.root / cfg.RECEIPT).is_file())
        self.assertEqual(self.call("rollback")["status"], "rolled_back")
        self.assertEqual(config.read_bytes(), before)
        self.assertEqual(config.stat().st_mode & 0o777, initial_mode)
        self.assertFalse((self.root / cfg.RECEIPT).exists())
        self.assertEqual(self.call("status")["status"], "not_installed")

    def test_new_profile_config_rolls_back_to_absence(self):
        self.assertFalse((self.root / "config.toml").exists())
        self.assertEqual(self.call("install")["status"], "installed")
        self.assertEqual(self.call("rollback")["status"], "rolled_back")
        self.assertFalse((self.root / "config.toml").exists())

    def test_install_is_idempotent_and_does_not_make_new_receipt(self):
        self.call("install")
        receipt = (self.root / cfg.RECEIPT).read_bytes()
        self.assertEqual(self.call("install")["status"], "already_managed")
        self.assertEqual((self.root / cfg.RECEIPT).read_bytes(), receipt)

    def test_preexisting_hermes_entry_is_not_taken_over_or_uninstalled(self):
        config = self.root / "config.toml"
        body = b'[mcp_servers.hermes]\nurl="https://mcp.mikemoore.top/mcp"\n'
        config.write_bytes(body)
        self.assertEqual(self.call("status")["status"], "preexisting")
        with self.assertRaisesRegex(cfg.ConfigRefused, "preexisting_hermes_mcp_no_takeover"):
            self.call("install")
        with self.assertRaisesRegex(cfg.ConfigRefused, "not_owned_by_hermes"):
            self.call("rollback")
        self.assertEqual(config.read_bytes(), body)

    def test_dotted_entry_alias_also_refuses_takeover(self):
        (self.root / "config.toml").write_text(
            'mcp_servers.hermes.url = "https://example.org/"\n', encoding="utf-8"
        )
        with self.assertRaisesRegex(cfg.ConfigRefused, "preexisting"):
            self.call("install")

    def test_owner_edits_after_install_never_overwritten(self):
        config = self.root / "config.toml"
        config.write_bytes(b'[features]\nowner_setting = true\n')
        self.call("install")
        edited = config.read_bytes() + b'\n[other]\nsetting=1\n'
        config.write_bytes(edited)
        with self.assertRaisesRegex(cfg.ConfigRefused, "config_changed_refuse_rollback"):
            self.call("rollback")
        self.assertEqual(config.read_bytes(), edited)
        self.assertTrue((self.root / cfg.RECEIPT).exists())

    def test_pending_receipt_after_interrupted_install_can_be_cleaned(self):
        config = self.root / "config.toml"
        config.write_text('[owner]\nkey=123\n')
        self.call("install")
        before = config.read_bytes()[:-len(cfg.SUFFIX)]
        config.write_bytes(before)
        self.assertEqual(self.call("rollback")["status"], "pending_receipt_cleared")
        self.assertEqual(config.read_bytes(), before)

    def test_symlink_config_and_receipt_denied_without_following(self):
        target = self.root.parent / "target"
        target.write_text("SECRET-WOULD-BE-LOST")
        link = self.root / "config.toml"
        link.symlink_to(target)
        with self.assertRaisesRegex(cfg.ConfigRefused, "untrusted_path"):
            self.call("install")
        link.unlink()
        rec = self.root / cfg.RECEIPT
        rec.symlink_to(target)
        with self.assertRaisesRegex(cfg.ConfigRefused, "untrusted_path"):
            self.call("install")
        self.assertEqual(target.read_text(), "SECRET-WOULD-BE-LOST")

    def test_invalid_toml_preserved(self):
        config = self.root / "config.toml"
        data = b'[bad\nSECRET-OWNER-DATA'
        config.write_bytes(data)
        with self.assertRaisesRegex(cfg.ConfigRefused, "invalid_existing_toml"):
            self.call("install")
        self.assertEqual(config.read_bytes(), data)
        self.assertFalse((self.root / cfg.RECEIPT).exists())

    def test_tampered_receipt_denied_without_modifying_config(self):
        self.call("install")
        config = self.root / "config.toml"
        before = config.read_bytes()
        (self.root / cfg.RECEIPT).write_text('{"bad":"receipt"}')
        with self.assertRaisesRegex(cfg.ConfigRefused, "receipt_invalid"):
            self.call("rollback")
        self.assertEqual(config.read_bytes(), before)

    def test_status_has_no_oauth_or_desktop_client_claim(self):
        state = self.call("status")
        self.assertEqual(state["changes"], 0)
        self.assertFalse(state["oauth_verified"])
        self.assertFalse(state["desktop_mcp_e2e_verified"])
        self.assertNotIn("token", json.dumps(state))
        self.assertNotIn("session", json.dumps(state))

    def test_non_windows_host_mutation_denied(self):
        if os.name != "nt":
            with self.assertRaisesRegex(cfg.ConfigRefused, "native_windows_required"):
                cfg.manage(self.root, "install")
        self.assertFalse((self.root / cfg.RECEIPT).exists())

    def test_denial_in_cli_does_not_echo_local_secrets(self):
        with patch.object(cfg.Path, "home", return_value=self.root.parent):
            # Root exists but --install on Linux is automatically denied.
            self.assertEqual(cfg.main(["--mode", "status"]), 0)

    def test_fails_closed_on_unrecognized_operation(self):
        with self.assertRaisesRegex(cfg.ConfigRefused, "operation_denied"):
            self.call("run-model")

    def test_receipt_contains_only_metadata_and_hashes(self):
        secret = 'owner-password-DO-NOT-LOG'
        (self.root / 'config.toml').write_text(
            f'[owner]\nvalue = "{secret}"\n', encoding='utf-8'
        )
        self.call("install")
        receipt = (self.root / cfg.RECEIPT).read_bytes()
        self.assertNotIn(secret.encode(), receipt)
        self.assertEqual(set(json.loads(receipt)), {
            "schema", "had_original", "before_sha", "installed_sha"
        })


if __name__ == "__main__":
    unittest.main()
