"""Read-only Ops Watch readers must escape SQLite URI metacharacters."""
from __future__ import annotations

import sqlite3
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from ops_watch.core import InputError
from ops_watch.delivery_contract import stats
from ops_watch.state_store import DATABASE, inspect, persist, read_current

NOW = datetime(2026, 10, 15, 12, tzinfo=UTC)
FINDING = [{"code": "timer_inactive", "fingerprint": "ops:timer_inactive"}]


class ReadOnlySQLiteURITests(unittest.TestCase):
    def test_query_and_fragment_in_directory_do_not_redirect_sqlite(self):
        for folder in ("ops?mode=rwc#hidden", "ops#fragment?mode=memory", "ops normal"):
            with self.subTest(folder=folder):
                with tempfile.TemporaryDirectory(prefix="hermes-ops-uri-") as temp:
                    directory = Path(temp) / folder
                    directory.mkdir(mode=0o700)
                    persist(directory, [], lambda: [], observed=NOW)
                    persist(directory, FINDING, lambda: [], observed=NOW)
                    original = (directory / DATABASE).read_bytes()
                    self.assertEqual(read_current(directory), FINDING)
                    self.assertEqual(len(inspect(directory)), 1)
                    self.assertEqual(inspect(directory)[0]["fingerprint"],
                                     "ops:timer_inactive")
                    self.assertEqual(stats(directory)["unacknowledged"], 1)
                    self.assertEqual((directory / DATABASE).read_bytes(), original)
                    self.assertEqual(
                        sorted(p.name for p in directory.iterdir()),
                        [DATABASE],
                    )

    def test_hardlinked_database_is_rejected_by_both_readers(self):
        with tempfile.TemporaryDirectory(prefix="hermes-ops-hardlink-") as temp:
            directory = Path(temp)
            directory.chmod(0o700)
            persist(directory, FINDING, lambda: [], observed=NOW)
            linked = directory / "unapproved-extra-link.sqlite"
            linked.hardlink_to(directory / DATABASE)
            with self.assertRaisesRegex(InputError, "unsafe_outbox_db"):
                read_current(directory)
            with self.assertRaisesRegex(InputError, "unsafe_outbox_db"):
                inspect(directory)
            self.assertEqual(linked.read_bytes(), (directory / DATABASE).read_bytes())

    def test_readers_stay_read_only_when_history_present(self):
        with tempfile.TemporaryDirectory(prefix="hermes-ops-ro-") as temp:
            directory = Path(temp)
            directory.chmod(0o700)
            persist(directory, FINDING, lambda: [], observed=NOW)
            with sqlite3.connect(directory / DATABASE) as conn:
                before = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            self.assertEqual(len(inspect(directory, max_items=1)), 1)
            self.assertEqual(read_current(directory), FINDING)
            with sqlite3.connect(directory / DATABASE) as conn:
                after = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
