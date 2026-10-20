"""#295: offline quota alert -> durable queue -> Telegram ACK -> recovery.

This is NOT a live alert: all state is in a mode-0700 temporary directory,
the transport is an in-memory stand-in, and no provider/Telegram request occurs.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from ops_watch import collector, quota_alerts, telegram_dispatch, telegram_sender
from ops_watch.delivery_contract import stats

TOKEN = "123456789:" + "A" * 35
CHAT = "123456789"
QUOTA_PATHS = {p: Path("/this-path-must-not-be-read") for p in (
    "codex", "desktop", "cloudflare", "github"
)}


def provider(id_: str, status: str, used: int | None) -> dict:
    windows = [] if used is None else [{"used_percent": used}]
    return {"id": id_, "status": status, "windows": windows}


def registry(desktop: tuple[str, int | None],
             github: tuple[str, int | None]) -> dict:
    return {"providers": [
        provider("desktop_commander", *desktop),
        provider("github_api", *github),
        # No Cloudflare advisory datum may create a fabricated quota alert.
        provider("cloudflare_workers_ai", "low", 99),
    ]}


class QuotaTelegramFullChainTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory(prefix="quota-alert-synthetic-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.root.chmod(0o700)
        self.source = self.root / "news.json"
        self.now = datetime.now(UTC)
        self.source.write_text(json.dumps({"health": {
            "last_successful_discovery_at": self.now.isoformat(),
            "consecutive_discovery_failures": 0,
            "consecutive_drain_failures": 0,
            "pending_jobs": 0,
            "oldest_pending_age_seconds": 0,
        }}), encoding="utf-8")
        self.messages: list[str] = []
        self.delivered: list[int] = []

    def transport(self, *, token: str, chat_id: int, text: str) -> int:
        self.assertEqual(token, TOKEN)
        self.assertEqual(chat_id, int(CHAT))
        self.assertIn("Hermes Ops Watch", text)
        self.assertNotIn(TOKEN, text)
        self.assertNotIn(CHAT, text)
        self.messages.append(text)
        return 7000 + len(self.messages)

    def step(self, desktop: tuple[str, int | None],
             github: tuple[str, int | None], seconds: int):
        with patch.object(collector, "_state", return_value=True), \
             patch.object(collector, "_codex_telemetry", return_value=None), \
             patch.object(collector, "observed_status", return_value=None), \
             patch.object(quota_alerts, "registry",
                          return_value=registry(desktop, github)):
            return collector.once(
                source=self.source, target=self.root,
                observed=self.now + timedelta(seconds=seconds),
                agent_guard={"loaded": True, "enabled": True, "active": True},
                quota_paths=QUOTA_PATHS,
            )

    def drain_using_actual_dispatch(self):
        # Same dispatch, reservation, immutable text catalog, Telegram
        # transport adapter and durable ACK used by the timer; only
        # credentials and network transport are replaced in-memory.
        def delivery(path, *, token, chat, now):
            self.assertEqual(path, telegram_dispatch.SANDBOX_OUTBOX)
            return telegram_sender.send_one(
                self.root, token=token, chat=chat, now=now,
                transport=self.transport,
            )
        with patch.object(telegram_dispatch, "read_credentials",
                          return_value=(TOKEN, CHAT)), \
             patch.object(telegram_dispatch, "send_one",
                          side_effect=delivery), \
             patch.object(telegram_dispatch, "SANDBOX_OUTBOX", self.root):
            for _ in range(15):
                result = telegram_dispatch.dispatch_once()
                if result["status"] == "EMPTY_OR_LEASED":
                    return
                self.assertEqual(result["status"], "ACCEPTED_BY_TELEGRAM")
                self.delivered.append(result["event_id"])
        self.fail("Queue not emptied in at most fifteen bounded dispatch ticks")

    def test_threshold_escalation_dedup_unknown_preservation_and_recovery(self):
        one = self.step(("low", 80), ("ok", 5), 0)
        self.assertEqual(one["changes"]["raised"], ["ops:quota_desktop_80"])
        self.drain_using_actual_dispatch()
        count = len(self.messages)

        duplicate = self.step(("low", 80), ("ok", 5), 1)
        self.assertEqual(duplicate["changes"], {"raised": [], "resolved": []})
        self.drain_using_actual_dispatch()
        self.assertEqual(len(self.messages), count)

        escalation = self.step(("low", 95), ("low", 95), 2)
        self.assertEqual(set(escalation["changes"]["raised"]), {
            "ops:quota_desktop_95", "ops:quota_github_95"})
        self.assertEqual(escalation["changes"]["resolved"],
                         ["ops:quota_desktop_80"])
        self.drain_using_actual_dispatch()

        severe = self.step(("exhausted", 100), ("auth_required", None), 3)
        self.assertEqual(set(severe["changes"]["raised"]), {
            "ops:quota_desktop_exhausted", "ops:quota_github_auth"})
        self.drain_using_actual_dispatch()

        unknown = self.step(("unknown", None), ("stale", None), 4)
        self.assertNotIn("ops:quota_desktop_exhausted",
                         unknown["changes"]["resolved"])
        self.assertIn("quota_desktop_exhausted", unknown["active_codes"])
        self.assertEqual(unknown["changes"]["raised"], ["ops:quota_github_stale"])
        self.drain_using_actual_dispatch()

        recovered = self.step(("ok", 5), ("ok", 5), 5)
        # The previous confirmed GitHub 95% alarm is preserved across
        # auth_required/stale evidence; only a fresh healthy observation
        # may resolve it alongside the stale-source warning.
        self.assertEqual(set(recovered["changes"]["resolved"]), {
            "ops:quota_desktop_exhausted", "ops:quota_github_stale",
            "ops:quota_github_95"})
        self.drain_using_actual_dispatch()
        total = stats(self.root)
        self.assertEqual(total["total"], len(self.delivered))
        self.assertEqual(total["acknowledged"], total["total"])
        self.assertEqual(total["unacknowledged"], 0)
        self.assertEqual(total["exhausted"], 0)
        self.assertEqual(len(self.messages), total["total"])

        # Validate actual durable ACKs for both new and resolved phases,
        # not just an in-memory transport invocation.
        uri = (self.root / "incidents.sqlite3").absolute().as_uri() + "?mode=ro"
        with sqlite3.connect(uri, uri=True) as db:
            records = db.execute(
                "SELECT e.fingerprint,e.phase,d.status,d.attempts,"
                "d.telegram_message_id,d.acknowledged_at "
                "FROM events e JOIN delivery_receipts d ON e.id=d.event_id "
                "WHERE e.fingerprint LIKE 'ops:quota_%' ORDER BY e.id"
            ).fetchall()
        self.assertEqual(len(records), total["total"])
        self.assertTrue(all(
            status == "acknowledged" and attempts == 1
            and type(message_id) is int and message_id > 0 and stamp
            for _, _, status, attempts, message_id, stamp in records
        ))
        self.assertTrue(any(phase == "resolved" for _, phase, *_ in records))
        self.assertTrue(any(code == "ops:quota_github_auth"
                            for code, *_ in records))
        self.assertTrue(all("Cloudflare" not in message
                            for message in self.messages))
        self.drain_using_actual_dispatch()
        self.assertEqual(len(self.messages), total["total"])

    def test_no_real_sender_or_cloud_api_in_offline_test(self):
        from ops_watch import telegram_sender as sender
        with patch.object(sender, "post_once",
                          side_effect=AssertionError("LIVE_TELEGRAM_DENIED")), \
             patch("ops_watch.telegram_sender._resolve",
                   side_effect=AssertionError("LIVE_NETWORK_DENIED")):
            result = self.step(("ok", 5), ("ok", 5), 0)
            self.assertEqual(result["changes"], {"raised": [], "resolved": []})
            self.drain_using_actual_dispatch()
            self.assertEqual(self.messages, [])


if __name__ == "__main__":
    unittest.main()
