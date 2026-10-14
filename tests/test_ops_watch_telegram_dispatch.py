"""No-network scheduled Ops Watch sender / systemd least-privilege contracts."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ops_watch import telegram_dispatch

ROOT = Path(__file__).resolve().parents[1]
SERVICE = ROOT / "deploy/hermes-ops-alerts.service"
TIMER = ROOT / "deploy/hermes-ops-alerts.timer"
BOT = "123456789:" + "X" * 35
CHAT = "123456789"


class ScheduledSenderTests(unittest.TestCase):
    def test_dry_run_never_reads_credentials_or_opens_transport(self):
        with patch.object(telegram_dispatch, "stats", return_value={
            "total": 0, "acknowledged": 0, "exhausted": 0, "unacknowledged": 0,
        }), patch.object(telegram_dispatch, "read_credentials") as creds:
            with patch.object(telegram_dispatch, "send_one") as send:
                self.assertEqual(telegram_dispatch.main([]), 0)
                creds.assert_not_called()
                send.assert_not_called()

    def test_explicit_execute_sends_at_most_one_using_scoped_credentials(self):
        with patch.object(telegram_dispatch, "read_credentials", return_value=(BOT, CHAT)):
            with patch.object(telegram_dispatch, "send_one", return_value={
                "status": "ACCEPTED_BY_TELEGRAM", "event_id": 12,
            }) as send:
                self.assertEqual(telegram_dispatch.main(["--execute"]), 0)
                self.assertEqual(send.call_count, 1)
                arguments = send.call_args
                self.assertEqual(arguments.kwargs["token"], BOT)
                self.assertEqual(arguments.kwargs["chat"], CHAT)

    def test_absent_or_unsafe_credentials_no_delivery(self):
        from ops_watch.telegram_e2e import VerificationError
        with patch.object(telegram_dispatch, "read_credentials",
                          side_effect=VerificationError("unsafe")):
            with patch.object(telegram_dispatch, "send_one") as send:
                self.assertEqual(telegram_dispatch.main(["--execute"]), 2)
                send.assert_not_called()

    def test_unavailable_transport_returns_failure_not_fake_success(self):
        from ops_watch.telegram_sender import TelegramGateError
        with patch.object(telegram_dispatch, "read_credentials", return_value=(BOT, CHAT)):
            with patch.object(telegram_dispatch, "send_one",
                              side_effect=TelegramGateError("telegram_network_or_tls_failure")):
                self.assertEqual(telegram_dispatch.main(["--execute"]), 2)

    def test_systemd_service_has_no_yfc_privileges_or_auto_restart(self):
        data = SERVICE.read_text()
        assert "ExecStart=/usr/bin/python3 -m ops_watch.telegram_dispatch --execute" in data
        assert "User=root" in data  # Existing 0600 root-owned outbox and credentials.
        for expected in (
            "CapabilityBoundingSet=\n", "NoNewPrivileges=yes",
            "ProtectSystem=strict", "ProtectHome=yes", "PrivateDevices=yes",
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
            "ReadWritePaths=/var/lib/hermes-agent/ops-watch",
            "InaccessiblePaths=/var/lib/hermes ",
            "MemoryMax=96M", "TimeoutStartSec=35s",
            "ReadOnlyPaths=/etc/hermes-agent/ops-watch.env",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, data)
        for forbidden in (
            "EnvironmentFile=", "Restart=always", "Restart=on-failure",
            "CAP_DAC_READ_SEARCH", "CAP_NET_ADMIN", "ExecStartPre=/bin/sh",
            "hermes-discovery.service", "your-fitness-coach",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, data)

    def test_one_event_per_10_minute_tick_without_catch_up_burst(self):
        data = TIMER.read_text()
        for required in (
            "OnBootSec=8min", "OnUnitActiveSec=10min", "Persistent=false",
            "Unit=hermes-ops-alerts.service", "RandomizedDelaySec=20s",
        ):
            self.assertIn(required, data)
        self.assertNotIn("OnCalendar=", data)


if __name__ == "__main__":
    unittest.main()
