"""Simulated Telegram-only API responses; never send real messages in CI."""
from __future__ import annotations

import json
import socket
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import Mock, patch

from ops_watch.delivery_contract import stats
from ops_watch.state_store import persist
from ops_watch.telegram_sender import (
    TelegramGateError, _credentials, _message, _resolve, post_once, send_one,
)

NOW = datetime(2026, 10, 14, 18, 0, tzinfo=UTC)
BOT = "123456789:" + "X" * 35
CHAT = "12345678"


def event():
    return [{"code": "timer_inactive", "fingerprint": "ops:timer_inactive"}]


class CredentialsAndSecurityTests(unittest.TestCase):
    def test_no_credentials_or_no_explicit_owner_chat(self):
        for bot, chat in (("", CHAT), (BOT, ""), (BOT, "-1001234567"),
                          (BOT, "@other_channel"), ("abc", CHAT),
                          (BOT, "http://example.com"), (BOT, "0")):
            with self.subTest(chat=chat), self.assertRaises(TelegramGateError):
                _credentials(bot, chat)

    @patch("ops_watch.telegram_sender.socket.getaddrinfo")
    def test_global_dns_only(self, dns):
        dns.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 443)),
        ]
        with self.assertRaisesRegex(TelegramGateError, "telegram_private_dns_denied"):
            _resolve()

    @patch("ops_watch.telegram_sender.socket.getaddrinfo")
    def test_ipv4_fallback_after_validating_ipv6(self, dns):
        dns.return_value = [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "",
             ("2606:4700:4700::1111", 443, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
        ]
        self.assertEqual(_resolve(), "8.8.8.8")


class SenderTransportTests(unittest.TestCase):
    def fake(self, *, status=200, data=None):
        payload = data if data is not None else {
            "ok": True, "result": {
                "message_id": 445, "chat": {"id": int(CHAT)}
            }
        }
        response = Mock(status=status)
        response.getheader.side_effect = lambda key, default=None: default
        response.read.return_value = json.dumps(payload).encode("utf-8")
        client = Mock()
        client.getresponse.return_value = response
        return client

    @patch("ops_watch.telegram_sender._resolve", return_value="8.8.8.8")
    def test_one_post_to_explicit_owner_and_real_response(self, resolver):
        client = self.fake()
        self.assertEqual(post_once(token=BOT, chat_id=int(CHAT), text="test",
                                   connect=lambda _: client), 445)
        self.assertEqual(client.request.call_count, 1)
        args, kwargs = client.request.call_args
        self.assertEqual(args[:2], ("POST", f"/bot{BOT}/sendMessage"))
        sent = json.loads(kwargs["body"])
        self.assertEqual(sent, {"chat_id": int(CHAT), "text": "test"})
        self.assertNotIn("allow_paid_broadcast", kwargs["body"].decode())
        client.close.assert_called_once_with()

    @patch("ops_watch.telegram_sender._resolve", return_value="8.8.8.8")
    def test_wrong_chat_or_missing_receipt_refused(self, resolver):
        for answer in (
            {"ok": True, "result": {"message_id": 33, "chat": {"id": 999}}},
            {"ok": True, "result": {"message_id": 0, "chat": {"id": int(CHAT)}}},
            {"ok": True, "result": {"chat": {"id": int(CHAT)}}},
        ):
            client = self.fake(data=answer)
            with self.assertRaises(TelegramGateError):
                post_once(token=BOT, chat_id=int(CHAT), text="test",
                          connect=lambda _: client)

    @patch("ops_watch.telegram_sender._resolve", return_value="8.8.8.8")
    def test_http_429_and_other_errors_no_retry(self, resolver):
        for status in (302, 400, 401, 403, 429, 500):
            client = self.fake(status=status)
            with self.subTest(status=status), self.assertRaisesRegex(
                TelegramGateError, "telegram_api_refused"
            ):
                post_once(token=BOT, chat_id=int(CHAT), text="test",
                          connect=lambda _: client)
            self.assertEqual(client.request.call_count, 1)

    @patch("ops_watch.telegram_sender._resolve", return_value="8.8.8.8")
    def test_exception_never_prints_secret_token(self, resolver):
        client = self.fake()
        client.request.side_effect = OSError("token=" + BOT)
        with self.assertRaises(TelegramGateError) as r:
            post_once(token=BOT, chat_id=int(CHAT), text="test",
                      connect=lambda _: client)
        self.assertEqual(str(r.exception), "telegram_network_or_tls_failure")
        self.assertNotIn(BOT, str(r.exception))
        client.close.assert_called_once_with()


class LocalAcknowledgeTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.dir = Path(temp.name)
        self.dir.chmod(0o700)
        persist(self.dir, [], lambda: [], observed=NOW)
        persist(self.dir, event(), lambda: [], observed=NOW)

    def test_confirm_real_mock_transport_receipt_only(self):
        accepted = send_one(
            self.dir, token=BOT, chat=CHAT, now=NOW,
            transport=lambda **_: 55,
        )
        self.assertEqual(accepted["status"], "ACCEPTED_BY_TELEGRAM")
        self.assertEqual(stats(self.dir)["acknowledged"], 1)

    def test_bad_credentials_block_before_claim(self):
        with self.assertRaises(TelegramGateError):
            send_one(self.dir, token="", chat=CHAT, now=NOW)
        self.assertEqual(stats(self.dir)["unacknowledged"], 1)

    def test_failure_never_acknowledges_sent(self):
        def failure(**kwargs):
            raise TelegramGateError("telegram_network_or_tls_failure")
        with self.assertRaises(TelegramGateError):
            send_one(self.dir, token=BOT, chat=CHAT, now=NOW, transport=failure)
        self.assertEqual(stats(self.dir)["acknowledged"], 0)

    def test_send_message_contains_only_bounded_fixed_catalog_text(self):
        from ops_watch.delivery_contract import claim_one
        item = claim_one(self.dir, now=NOW)
        text = _message(item)
        self.assertIn("Таймер новостей неактивен", text)
        self.assertNotIn("http", text)
        self.assertNotIn("Bearer", text)


if __name__ == "__main__":
    unittest.main()
