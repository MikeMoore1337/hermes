"""Read-only Ops Watch to Advisor projection tests."""
from __future__ import annotations

import os
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from ops_watch import advisor_adapter as adapter
from ops_watch.advisor_adapter import (
    ADAPTER_SCHEMA,
    AdvisorAdapterError,
    read_events,
    rules_assessment,
)
from ops_watch.core import InputError
from ops_watch.incident_preview import ACTIONS, CRITICAL, TITLES
from ops_watch.state_store import persist

NOW = datetime(2026, 10, 15, 12, tzinfo=UTC)


class OpsWatchAdvisorAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="hermes-advisor-adapter-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def row(self, event_id: int, code: str, phase: str = "new") -> dict[str, object]:
        resolved = phase == "resolved"
        return {
            "id": event_id,
            "fingerprint": "ops:" + code,
            "phase": phase,
            "severity": "resolved" if resolved else (
                "critical" if code in CRITICAL else "warning"
            ),
            "title": ("Восстановлено: " if resolved else "") + TITLES[code],
            "action": "Дополнительные действия не требуются" if resolved else ACTIONS[code],
            "created_at": NOW.isoformat(),
        }

    def read(self, rows, **kwargs):
        with patch.object(adapter, "inspect", return_value=rows) as reader:
            result = read_events(self.directory, **kwargs)
        reader.assert_called_once()
        return result

    def test_active_event_is_mapped_without_writing_source(self) -> None:
        adapted = self.read(
            [self.row(1, "provider_rate_limited")],
            provenance="anonymized_copy",
            max_items=10,
        )
        self.assertEqual(adapted[0]["schema"], ADAPTER_SCHEMA)
        self.assertEqual(adapted[0]["provenance"], "anonymized_copy")
        self.assertEqual(adapted[0]["event"]["error_code"], "HTTP_429")
        self.assertEqual(adapted[0]["event"]["recovery_state"], "active")
        self.assertEqual(adapted[0]["analysis"]["decision"], "RULES_ONLY")

    def test_recovery_is_not_reported_as_active(self) -> None:
        recovered = self.read(
            [self.row(2, "timer_inactive", "resolved")],
            provenance="readonly_snapshot",
            event_id=2,
        )[0]
        self.assertEqual(recovered["phase"], "resolved")
        self.assertEqual(recovered["event"]["recovery_state"], "recovered")
        self.assertEqual(recovered["event"]["service_state"], "healthy")
        self.assertEqual(recovered["analysis"]["decision"], "RULES_ONLY")
        self.assertEqual(rules_assessment(recovered)["status"], "resolved")

    def test_multiple_events_and_repeat_reads_are_bounded(self) -> None:
        rows = [self.row(2, "outbox_backlog"), self.row(1, "provider_rate_limited")]
        first = self.read(rows, provenance="synthetic")
        second = self.read(rows, provenance="synthetic")
        self.assertEqual(first, second)
        self.assertEqual(len(first), 2)
        self.assertIn("ADVISOR_CANDIDATE", {item["analysis"]["decision"] for item in first})

    def test_missing_source_is_rejected_without_creating_database(self) -> None:
        with patch.object(adapter, "inspect", side_effect=InputError("unavailable")):
            with self.assertRaisesRegex(AdvisorAdapterError, "source_unavailable"):
                read_events(self.directory, provenance="readonly_snapshot")
        self.assertFalse((self.directory / "incidents.sqlite3").exists())

    def test_unknown_or_tampered_records_are_rejected(self) -> None:
        unknown = {
            "id": 1, "fingerprint": "ops:unknown", "phase": "new",
            "severity": "warning", "title": "x", "action": "x",
            "created_at": NOW.isoformat(),
        }
        with patch.object(adapter, "inspect", return_value=[unknown]):
            with self.assertRaisesRegex(AdvisorAdapterError, "unknown_event_code"):
                read_events(self.directory, provenance="readonly_snapshot")

        tampered = self.row(1, "ci_failed")
        tampered["title"] = "private"
        with patch.object(adapter, "inspect", return_value=[tampered]):
            with self.assertRaisesRegex(AdvisorAdapterError, "event_record_invalid"):
                read_events(self.directory, provenance="readonly_snapshot")

    def test_event_selection_and_provenance_are_explicit(self) -> None:
        with patch.object(adapter, "inspect", return_value=[self.row(1, "ci_failed")]):
            with self.assertRaisesRegex(AdvisorAdapterError, "event_not_found"):
                read_events(self.directory, provenance="readonly_snapshot", event_id=999)
        with self.assertRaisesRegex(AdvisorAdapterError, "event_provenance_invalid"):
            read_events(self.directory, provenance="production")

    @unittest.skipUnless(os.name == "posix", "state_store uses POSIX ownership checks")
    def test_real_state_store_projection_preserves_recovery_and_repeats(self) -> None:
        code = "provider_rate_limited"
        current = [{"code": code, "fingerprint": "ops:" + code}]
        persist(self.directory, current, lambda: [], observed=NOW)
        persist(self.directory, [], lambda: [], observed=NOW.replace(second=1))
        persist(self.directory, current, lambda: [], observed=NOW.replace(second=2))
        database = self.directory / "incidents.sqlite3"
        before = database.read_bytes()

        adapted = read_events(
            self.directory,
            provenance="readonly_snapshot",
            max_items=10,
        )

        self.assertEqual(database.read_bytes(), before)
        self.assertEqual(len(adapted), 3)
        self.assertEqual(adapted[0]["analysis"]["decision"], "ADVISOR_CANDIDATE")
        self.assertEqual(adapted[0]["event"]["repeat_count"], 3)
        self.assertEqual(adapted[1]["phase"], "resolved")
        self.assertEqual(adapted[1]["analysis"]["decision"], "RULES_ONLY")
        self.assertEqual(adapted[2]["analysis"]["decision"], "ADVISOR_CANDIDATE")


if __name__ == "__main__":
    unittest.main()
