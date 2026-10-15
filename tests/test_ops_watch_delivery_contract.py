"""Offline deterministic handoff tests for owner-only incident notifications."""
from __future__ import annotations

import sqlite3
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from ops_watch.core import InputError
from ops_watch.delivery_contract import claim_one, confirm_one, stats
from ops_watch.state_store import DATABASE, persist

NOW = datetime(2026, 10, 14, 14, 0, tzinfo=UTC)


def incident(code):
    return [{"code": code, "fingerprint": "ops:" + code}]


class LeaseContractTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.directory = Path(t.name)
        self.directory.chmod(0o700)
        persist(self.directory, [], lambda: [], observed=NOW)

    def raise_one(self, code="timer_inactive"):
        persist(self.directory, incident(code), lambda: [], observed=NOW)

    def test_claim_only_one_oldest_incident_and_hold_order(self):
        self.raise_one()
        first = claim_one(self.directory, now=NOW)
        self.assertEqual(first["event_id"], 1)
        self.assertEqual(first["title"], "Таймер новостей неактивен")
        self.assertEqual(first["attempt"], 1)
        self.assertIsNone(claim_one(self.directory, now=NOW + timedelta(seconds=1)))
        self.assertNotIn("recipient", str(first))

    def test_ack_from_transport_is_durable_and_not_reoffered(self):
        self.raise_one()
        first = claim_one(self.directory, now=NOW)
        confirm_one(self.directory, event_id=first["event_id"],
                    lease_token=first["lease_token"], telegram_message_id=77,
                    now=NOW + timedelta(seconds=1))
        self.assertEqual(stats(self.directory),
                         {"total": 1, "acknowledged": 1,
                          "unacknowledged": 0, "exhausted": 0})
        self.assertIsNone(claim_one(self.directory, now=NOW + timedelta(hours=1)))

    def test_wrong_or_replayed_token_rejected(self):
        self.raise_one()
        first = claim_one(self.directory, now=NOW)
        for token in ("a" * 32, "wrong", "bearer token", ""):
            with self.subTest(token=token), self.assertRaises(InputError):
                confirm_one(self.directory, event_id=1, lease_token=token,
                            telegram_message_id=5, now=NOW)
        self.assertEqual(stats(self.directory)["acknowledged"], 0)

    def test_failed_remote_ack_leaves_event_retryable_after_lease(self):
        self.raise_one()
        a = claim_one(self.directory, now=NOW)
        later = NOW + timedelta(seconds=91)
        b = claim_one(self.directory, now=later)
        self.assertEqual(a["event_id"], b["event_id"])
        self.assertNotEqual(a["lease_token"], b["lease_token"])
        self.assertEqual(b["attempt"], 2)
        with self.assertRaisesRegex(InputError, "delivery_confirmation_stale"):
            confirm_one(self.directory, event_id=1, lease_token=a["lease_token"],
                        telegram_message_id=51, now=later)
        self.assertEqual(stats(self.directory)["acknowledged"], 0)

    def test_at_most_five_attempts_then_refuse_new_sends(self):
        self.raise_one()
        for i in range(5):
            current = NOW + timedelta(seconds=91 * i)
            res = claim_one(self.directory, now=current)
            self.assertEqual(res["attempt"], i + 1)
        self.assertIsNone(claim_one(self.directory, now=NOW + timedelta(seconds=91 * 6)))
        self.assertEqual(stats(self.directory)["exhausted"], 1)

    def test_exhausted_incident_never_blocks_later_recovery(self):
        self.raise_one()
        persist(self.directory, [], lambda: [], observed=NOW)
        for index in range(5):
            current = NOW + timedelta(seconds=91 * index)
            leased = claim_one(self.directory, now=current)
            self.assertEqual(leased["event_id"], 1)
            self.assertEqual(leased["attempt"], index + 1)
        # Once the fifth lease expires, preserve its receipt but offer
        # the later real recovery instead of blocking all notifications.
        subsequent = claim_one(self.directory, now=NOW + timedelta(seconds=91 * 6))
        self.assertEqual(subsequent["event_id"], 2)
        self.assertEqual(subsequent["phase"], "resolved")
        self.assertEqual(subsequent["attempt"], 1)
        confirm_one(self.directory, event_id=2,
                    lease_token=subsequent["lease_token"],
                    telegram_message_id=31,
                    now=NOW + timedelta(seconds=91 * 6 + 1))
        self.assertEqual(stats(self.directory),
                         {"total": 2, "acknowledged": 1,
                          "unacknowledged": 1, "exhausted": 1})
        self.assertIsNone(claim_one(self.directory, now=NOW + timedelta(hours=3)))

    def test_exhausted_but_tampered_message_fails_closed(self):
        self.raise_one()
        persist(self.directory, [], lambda: [], observed=NOW)
        for index in range(5):
            leased = claim_one(self.directory, now=NOW + timedelta(seconds=91 * index))
            self.assertEqual(leased["event_id"], 1)
        with sqlite3.connect(self.directory / DATABASE) as db:
            db.execute("UPDATE events SET title='FAKE UNKNOWN INSTRUCTION' WHERE id=1")
        with self.assertRaisesRegex(InputError,"delivery_event_tampered"):
            claim_one(self.directory, now=NOW + timedelta(seconds=91 * 6))

    def test_queue_is_fifo_and_ordered_behind_unacked_item(self):
        self.raise_one()
        persist(self.directory, [], lambda: [], observed=NOW)
        first = claim_one(self.directory, now=NOW)
        self.assertEqual(first["event_id"], 1)
        self.assertIsNone(claim_one(self.directory, now=NOW + timedelta(seconds=1)))
        confirm_one(self.directory, event_id=1, lease_token=first["lease_token"],
                    telegram_message_id=21, now=NOW)
        next_event = claim_one(self.directory, now=NOW)
        self.assertEqual(next_event["event_id"], 2)
        self.assertEqual(next_event["phase"], "resolved")

    def test_tampered_stored_message_rejected(self):
        self.raise_one()
        with sqlite3.connect(self.directory / DATABASE) as db:
            db.execute("UPDATE events SET title='TOKEN PRIVATE' WHERE id=1")
        with self.assertRaisesRegex(InputError, "delivery_event_tampered"):
            claim_one(self.directory, now=NOW)

    def test_tampered_stored_action_rejected(self):
        self.raise_one()
        with sqlite3.connect(self.directory / DATABASE) as db:
            db.execute("UPDATE events SET action='go to attacker website' WHERE id=1")
        with self.assertRaisesRegex(InputError, "delivery_event_tampered"):
            claim_one(self.directory, now=NOW)

    def test_timezone_and_invalid_receipt_ids_are_rejected(self):
        self.raise_one()
        first = claim_one(self.directory, now=NOW)
        bads = (0, True, -1, "100", {})
        for id_ in bads:
            with self.subTest(id_=id_), self.assertRaises(InputError):
                confirm_one(self.directory, event_id=1,
                            lease_token=first["lease_token"],
                            telegram_message_id=id_, now=NOW)
        with self.assertRaisesRegex(InputError, "delivery_timezone_required"):
            claim_one(self.directory, now=datetime(2026, 10, 14))

    def test_expired_confirmation_is_rejected(self):
        self.raise_one()
        first = claim_one(self.directory, now=NOW)
        with self.assertRaisesRegex(InputError, "delivery_confirmation_expired"):
            confirm_one(self.directory, event_id=1,
                        lease_token=first["lease_token"],
                        telegram_message_id=777,
                        now=NOW + timedelta(seconds=92))

    def test_aggregate_stats_is_readonly_before_any_delivery(self):
        self.raise_one()
        self.assertEqual(stats(self.directory)["unacknowledged"], 1)
        with sqlite3.connect(self.directory / DATABASE) as db:
            tables = {r[0] for r in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )}
        self.assertNotIn("delivery_receipts", tables)

    def test_readonly_stats_handles_uri_metacharacters_in_folder_name(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "events?mode=rwc#not-a-fragment"
            directory.mkdir(mode=0o700)
            persist(directory, [], lambda: [], observed=NOW)
            persist(directory, incident("timer_inactive"), lambda: [], observed=NOW)
            original = (directory / DATABASE).stat()
            self.assertEqual(stats(directory)["unacknowledged"], 1)
            self.assertEqual((directory / DATABASE).stat().st_size, original.st_size)
            with sqlite3.connect(directory / DATABASE) as db:
                names = {r[0] for r in db.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )}
            self.assertNotIn("delivery_receipts", names)

    def test_no_telegram_egress_or_secrets_in_module(self):
        import inspect
        from ops_watch import delivery_contract
        source = inspect.getsource(delivery_contract)
        for forbidden in ("urllib", "requests", "http.client",
                          "sendMessage", "BOT_TOKEN", "api.telegram.org"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
