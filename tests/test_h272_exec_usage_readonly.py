"""#272 synthetic tests. All usage and artifacts are fabricated offline."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

from scripts.h272_exec_usage_readonly import UsageHold, read_one


def event(kind, **extra):
    return json.dumps({"type": kind, **extra}, ensure_ascii=False) + "\n"


class H272ExecUsageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.db = root / "jobs.sqlite3"
        self.artifacts = root / "artifacts"
        self.artifacts.mkdir(mode=0o700)
        self.jid = "synthetic-job-001"
        self.secret = "SECRET_MUST_NOT_LEAK_IN_ANY_RESULT"
        self.payload = (
            event("thread.started", thread_id="synthetic-thread") +
            event("item.completed", item={"type": "agent_message", "text": self.secret}) +
            event("turn.completed", usage={
                "input_tokens": 120, "cached_input_tokens": 35,
                "output_tokens": 23, "reasoning_output_tokens": 17,
            })
        )
        with sqlite3.connect(self.db) as c:
            c.execute("""CREATE TABLE jobs (
                job_id TEXT, status TEXT, attempt_count INTEGER,
                invocation_state TEXT, last_error_code TEXT, result_ref TEXT,
                delivered REAL, model TEXT, started REAL, finished REAL)""")
        self.install(self.payload)

    def install(self, payload):
        for old in self.artifacts.iterdir():
            old.unlink()
        raw = payload.encode()
        digest = hashlib.sha256(raw).hexdigest()
        path = self.artifacts / f"{self.jid}-{digest}.jsonl"
        path.write_bytes(raw)
        path.chmod(0o600)
        with sqlite3.connect(self.db) as c:
            c.execute("DELETE FROM jobs")
            c.execute("INSERT INTO jobs VALUES (?,?,?,?,?,?,?,?,?,?)", (
                self.jid, "succeeded", 1, "finished", None,
                f"artifact:{self.jid}:{digest}", 100.0, "gpt-6.1-sol", 20.0, 30.0
            ))
        return path

    def check(self):
        return read_one(db=self.db, artifacts=self.artifacts)

    def assert_hold(self, code):
        with self.assertRaisesRegex(UsageHold, "^" + code + "$"):
            self.check()

    def test_one_real_shape_turn_and_privacy(self):
        result = self.check()
        self.assertEqual(result["usage"], {
            "input": 120, "cached_input": 35, "output": 23,
            "reasoning_output": 17,
        })
        self.assertEqual(result["quality"], "cli_reported_not_provider_verified")
        self.assertIsNone(result["actual_spend_usd"])
        self.assertEqual(result["turns_observed"], 1)
        self.assertNotIn(self.secret, repr(result))
        self.assertNotIn(self.jid, repr(result))
        self.assertNotIn(str(self.db), repr(result))

    def test_no_turn_usage_is_unknown_not_zero(self):
        self.install(event("thread.started", thread_id="t1"))
        self.assert_hold("NO_COMPLETED_TURN_USAGE")

    def test_multiple_turns_ambiguous_never_sum(self):
        self.install(self.payload + event("turn.completed", usage={
            "input_tokens": 240, "cached_input_tokens": 70, "output_tokens": 46
        }))
        self.assert_hold("MULTI_TURN_USAGE_AMBIGUOUS")

    def test_negative_boolean_and_inconsistent_cache_rejected(self):
        for n, cached in ((-1, 0), (True, 0), (10, 11), ("12", 0)):
            self.install(event("turn.completed", usage={
                "input_tokens": n, "cached_input_tokens": cached,
                "output_tokens": 3
            }))
            self.assert_hold("USAGE_FIELDS_INVALID")

    def test_non_fatal_item_payload_discarded(self):
        self.install(event("item.completed", item={
            "type": "agent_message", "text": self.secret
        }) + event("turn.completed", usage={
            "input_tokens": 1, "cached_input_tokens": 0, "output_tokens": 2
        }))
        result = self.check()
        self.assertIsNone(result["usage"]["reasoning_output"])
        self.assertNotIn(self.secret, repr(result))

    def test_errors_fail_closed(self):
        self.install(self.payload + event("turn.failed", error={"message": self.secret}))
        self.assert_hold("STREAM_HAS_ERROR")
        self.install(self.payload + event("item.completed", item={
            "type": "error", "message": self.secret
        }))
        self.assert_hold("STREAM_HAS_ERROR")

    def test_tampered_artifact_cannot_be_used(self):
        target = self.install(self.payload)
        target.write_bytes(target.read_bytes() + b"x")
        self.assert_hold("ARTIFACT_INTEGRITY_UNVERIFIED")

    def test_symlinks_and_missing_database_denied(self):
        target = self.install(self.payload)
        target.unlink()
        target.symlink_to(self.db)
        self.assert_hold("ARTIFACT_INTEGRITY_UNVERIFIED")
        self.db.unlink()
        self.assert_hold("SCHEDULER_DATABASE_UNAVAILABLE")

    def test_status_and_attempt_bound(self):
        for attempt, status, state in ((2, "succeeded", "finished"),
                                       (1, "succeeded", "uncertain")):
            with sqlite3.connect(self.db) as c:
                c.execute("UPDATE jobs SET attempt_count=?,status=?,invocation_state=?",
                          (attempt, status, state))
            self.assert_hold("SUCCESS_INVARIANT_FAILED")

    def test_invalid_json_payload_not_printed(self):
        self.install('{"type":"turn.completed","usage":INVALID}\n')
        self.assert_hold("EVENT_JSON_INVALID")

    def test_no_success_fails_closed(self):
        with sqlite3.connect(self.db) as c:
            c.execute("UPDATE jobs SET status='blocked'")
        self.assert_hold("NO_DELIVERED_SUCCESS")


if __name__ == "__main__":
    unittest.main()
