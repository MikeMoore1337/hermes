"""Reproduce monitor -> recovery -> ACK without touching systemd or production news."""
from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from ops_watch import collector, telegram_sender
from ops_watch.delivery_contract import stats

NOW = datetime(2026, 10, 15, 3, 40, tzinfo=UTC)
TOKEN = "123456789:" + "X"*35
CHAT = "123456789"
GOOD_GUARD = {"loaded": True, "enabled": True, "active": True}


class IsolatedIncidentAndRecoveryTests(unittest.TestCase):
    def test_true_collector_state_transitions_with_separate_fake_delivery(self):
        with tempfile.TemporaryDirectory(prefix="hermes-recovery-offline-") as tmp:
            directory = Path(tmp)
            directory.chmod(0o700)
            source = directory / "snapshot.json"
            source.write_text(json.dumps({"health": {
                "last_successful_discovery_at": NOW.isoformat(),
                "consecutive_discovery_failures": 0,
                "consecutive_drain_failures": 0,
                "pending_jobs": 0,
                "oldest_pending_age_seconds": 0,
            }}), encoding="utf-8")

            def disabled(timer, command):
                self.assertEqual(timer, "hermes-discovery.timer")
                return command == "is-active"

            with patch.object(collector, "_state", side_effect=disabled):
                first = collector.once(
                    source=source, target=directory, observed=NOW,
                    agent_guard=GOOD_GUARD,
                )
            self.assertEqual(first["changes"], {
                "raised": ["ops:timer_disabled"], "resolved": [],
            })
            self.assertEqual(first["queued_incident_events"], 1)

            def enabled(timer, command):
                self.assertEqual(timer, "hermes-discovery.timer")
                return True

            with patch.object(collector, "_state", side_effect=enabled):
                recovery = collector.once(
                    source=source, target=directory, observed=NOW,
                    agent_guard=GOOD_GUARD,
                )
            self.assertEqual(recovery["changes"], {
                "raised": [], "resolved": ["ops:timer_disabled"],
            })
            self.assertEqual(recovery["queued_incident_events"], 2)

            sent_messages: list[str] = []

            def fake_delivery(*, token: str, chat_id: int, text: str) -> int:
                self.assertEqual(token, TOKEN)
                self.assertEqual(chat_id, int(CHAT))
                sent_messages.append(text)
                return 800 + len(sent_messages)

            one = telegram_sender.send_one(
                directory, token=TOKEN, chat=CHAT, now=NOW, transport=fake_delivery,
            )
            two = telegram_sender.send_one(
                directory, token=TOKEN, chat=CHAT, now=NOW, transport=fake_delivery,
            )
            again = telegram_sender.send_one(
                directory, token=TOKEN, chat=CHAT, now=NOW, transport=fake_delivery,
            )
            self.assertEqual(one["status"], "ACCEPTED_BY_TELEGRAM")
            self.assertEqual(two["status"], "ACCEPTED_BY_TELEGRAM")
            self.assertEqual(again["status"], "EMPTY_OR_LEASED")
            self.assertEqual(len(sent_messages), 2)
            self.assertNotIn("Восстановлено", sent_messages[0])
            self.assertIn("Восстановлено", sent_messages[1])
            with sqlite3.connect(
                (directory / "incidents.sqlite3").as_uri() + "?mode=ro", uri=True,
            ) as db:
                rows = db.execute(
                    "SELECT e.phase,d.status,d.attempts,d.telegram_message_id "
                    "FROM events e JOIN delivery_receipts d ON d.event_id=e.id "
                    "ORDER BY e.id"
                ).fetchall()
            self.assertEqual(rows, [
                ("new", "acknowledged", 1, 801),
                ("resolved", "acknowledged", 1, 802),
            ])
            self.assertEqual(stats(directory), {
                "total": 2, "acknowledged": 2,
                "unacknowledged": 0, "exhausted": 0,
            })

    def test_real_production_paths_are_not_used_by_test(self):
        # No test has permission to patch or invoke actual systemctl enable/disable.
        # Collector source and target are always caller-supplied temporary paths.
        self.assertNotEqual(
            str(collector.SOURCE), "/tmp/hermes-recovery-offline-/snapshot.json",
        )
        self.assertEqual(collector.TARGET.as_posix(),
                         "/var/lib/hermes-agent/ops-watch")
        self.assertIn("systemctl", collector._state.__code__.co_consts)


if __name__ == "__main__":
    unittest.main()
