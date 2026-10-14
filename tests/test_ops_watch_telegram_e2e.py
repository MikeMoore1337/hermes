"""Offline checks for one-shot Ops Watch Telegram E2E. No HTTP calls."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ops_watch.telegram_e2e import (
    MARKER, VerificationError, main, read_credentials, verify_once,
)

TOKEN = "123456789:" + "A" * 35
CHAT = "123456789"


class CredentialFileTests(unittest.TestCase):
    def setUp(self):
        self.context = tempfile.TemporaryDirectory()
        self.addCleanup(self.context.cleanup)
        self.root = Path(self.context.name)
        self.file = self.root / "secret.env"

    def valid_file(self):
        self.file.write_text(
            f"HERMES_ALERT_BOT_TOKEN={TOKEN}\nHERMES_ALERT_PRIVATE_CHAT_ID={CHAT}\n",
            encoding="ascii",
        )
        self.file.chmod(0o600)

    def test_protected_file_reads_without_printing_values(self):
        self.valid_file()
        self.assertEqual(read_credentials(self.file), (TOKEN, CHAT))

    def test_symlink_and_world_readable_file_refused(self):
        self.valid_file()
        alias = self.root / "link"
        alias.symlink_to(self.file)
        with self.assertRaisesRegex(VerificationError, "credential_file_unavailable"):
            read_credentials(alias)
        self.file.chmod(0o644)
        with self.assertRaisesRegex(VerificationError, "credential_file_unsafe"):
            read_credentials(self.file)

    def test_missing_extra_duplicate_and_invalid_keys_refused(self):
        for value in (
            "HERMES_ALERT_BOT_TOKEN=bad\n",
            f"HERMES_ALERT_BOT_TOKEN={TOKEN}\nHERMES_ALERT_BOT_TOKEN={TOKEN}\n",
            f"HERMES_ALERT_BOT_TOKEN={TOKEN}\nHERMES_ALERT_PRIVATE_CHAT_ID={CHAT}\nUNKNOWN=1\n",
            f"HERMES_ALERT_BOT_TOKEN={TOKEN}\nHERMES_ALERT_PRIVATE_CHAT_ID=-10012345\n",
        ):
            with self.subTest(value_length=len(value)):
                self.file.write_text(value, encoding="ascii")
                self.file.chmod(0o600)
                with self.assertRaises(VerificationError):
                    read_credentials(self.file)


class IsolatedDeliveryTests(unittest.TestCase):
    def test_true_receipt_ack_and_no_second_delivery(self):
        calls = []
        def accepted(*, token, chat_id, text):
            calls.append((token, chat_id, text))
            return 15001
        result = verify_once(TOKEN, CHAT, transport=accepted)
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0][2].startswith(MARKER))
        self.assertEqual(result["status"], "ACCEPTED_BY_TELEGRAM_AND_ACK_PERSISTED")
        self.assertEqual(result["message_id"], 15001)
        self.assertTrue(result["duplicate_send_blocked"])
        self.assertFalse(result["production_queue_modified"])

    def test_transport_failure_keeps_test_sandbox_isolated(self):
        from ops_watch.telegram_sender import TelegramGateError
        def failed(**kwargs):
            raise TelegramGateError("telegram_network_or_tls_failure")
        with self.assertRaises(TelegramGateError):
            verify_once(TOKEN, CHAT, transport=failed)

    def test_main_without_execute_never_loads_token_or_sends(self):
        with patch("ops_watch.telegram_e2e.read_credentials") as reader:
            with patch("ops_watch.telegram_e2e.verify_once") as sender:
                self.assertEqual(main([]), 0)
            reader.assert_not_called()
            sender.assert_not_called()


if __name__ == "__main__":
    unittest.main()
