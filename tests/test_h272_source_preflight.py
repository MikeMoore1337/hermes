"""Synthetic source-only tests. No Codex, credentials, service, or network."""
import io
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from scripts.h272_source_preflight_readonly import (
    PreflightHold, inspect_source, main,
)

UUID = "019acd30-197e-7000-8000-000000000001"


class SourcePreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name) / "auth"
        self.day = self.home / "sessions" / "2026" / "10" / "25"
        self.day.mkdir(parents=True)
        self.file = self.day / f"rollout-2026-10-25T13-00-00-{UUID}.jsonl"
        self.uid = os.geteuid()

    def collect(self):
        return inspect_source(self.home, expected_uid=self.uid)

    def test_one_file_metadata_only(self):
        secret = b'PRIVATE_USER_PROMPT and sk-proj-secret'
        self.file.write_bytes(secret)
        with patch.object(Path, "open", side_effect=AssertionError("content read")):
            self.assertEqual(self.collect(), {"rollout_files": 1, "total_bytes": len(secret)})
        self.assertEqual(self.file.read_bytes(), secret)

    def test_empty_never_means_active_telemetry(self):
        with self.assertRaisesRegex(PreflightHold, "NO_ROLLOUT_FILES"):
            self.collect()

    def test_missing_sessions_is_not_permission_error(self):
        shutil.rmtree(self.home / "sessions")
        with self.assertRaisesRegex(PreflightHold, "^SESSIONS_DIRECTORY_MISSING$"):
            self.collect()

    def test_missing_auth_remains_distinct_from_missing_sessions(self):
        shutil.rmtree(self.home)
        with self.assertRaisesRegex(PreflightHold, "^SOURCE_DIRECTORY_UNAVAILABLE$"):
            self.collect()

    def test_permission_denial_remains_generic_hold(self):
        sessions = self.home / "sessions"
        actual_lstat = Path.lstat

        def denied(path):
            if path == sessions:
                raise PermissionError("private diagnostic must not echo this")
            return actual_lstat(path)

        with patch.object(Path, "lstat", autospec=True, side_effect=denied):
            with self.assertRaisesRegex(PreflightHold, "^SOURCE_DIRECTORY_UNAVAILABLE$"):
                self.collect()

    def test_unapproved_identity_cannot_inspect(self):
        self.file.write_bytes(b"private")
        with self.assertRaisesRegex(PreflightHold, "COLLECTOR_IDENTITY_MISMATCH"):
            inspect_source(self.home, expected_uid=self.uid + 1)

    def test_sessions_and_file_symlinks_denied(self):
        self.file.symlink_to(self.day / "unknown-file")
        with self.assertRaisesRegex(PreflightHold, "ROLLOUT_NOT_REGULAR_FILE"):
            self.collect()
        self.file.unlink()
        (self.home / "sessions").rename(self.home / "real")
        (self.home / "sessions").symlink_to(self.home / "real")
        with self.assertRaisesRegex(PreflightHold, "SOURCE_DIRECTORY_NOT_REAL"):
            self.collect()

    def test_wrong_file_owner_not_trusted(self):
        self.file.write_bytes(b"safe")
        with patch("scripts.h272_source_preflight_readonly.os.geteuid", return_value=self.uid + 1):
            with self.assertRaisesRegex(PreflightHold, "ROLLOUT_OWNER_MISMATCH"):
                inspect_source(self.home, expected_uid=self.uid + 1)

    def test_unrecognized_rollout_name_fails_closed(self):
        (self.day / "rollout-unknown.jsonl").write_bytes(b"private")
        with self.assertRaisesRegex(PreflightHold, "ROLLOUT_NAME_UNRECOGNIZED"):
            self.collect()

    def test_size_and_file_bounds(self):
        self.file.write_bytes(b"x")
        with patch("scripts.h272_source_preflight_readonly.MAX_FILE_BYTES", 0):
            with self.assertRaisesRegex(PreflightHold, "ROLLOUT_SIZE_LIMIT"):
                self.collect()
        with patch("scripts.h272_source_preflight_readonly.MAX_FILES", 0):
            with self.assertRaisesRegex(PreflightHold, "ROLLOUT_COUNT_LIMIT"):
                self.collect()

    def test_non_content_failure_output_redacted(self):
        output = io.StringIO()
        with patch("scripts.h272_source_preflight_readonly.HOME", self.home), \
             patch("scripts.h272_source_preflight_readonly.USERNAME", "unused"), \
             patch("scripts.h272_source_preflight_readonly.pwd.getpwnam") as user, \
             patch("sys.stdout", output):
            user.return_value.pw_uid = self.uid
            self.assertEqual(main(), 2)
        report = output.getvalue()
        self.assertIn("HOLD_NO_ROLLOUT_FILES", report)
        self.assertIn("SESSION_CONTENT_READ=NO", report)
        self.assertIn("MODEL_CALLS_ADDED=0", report)
        self.assertNotIn(str(self.home), report)
        self.assertNotIn(UUID, report)

    def test_missing_permissions_fail_closed(self):
        self.file.write_bytes(b"private")
        original = os.access
        with patch("scripts.h272_source_preflight_readonly.os.access",
                   side_effect=lambda p, flags: False if str(p) == str(self.file)
                   else original(p, flags)):
            with self.assertRaisesRegex(PreflightHold, "ROLLOUT_NOT_READABLE"):
                self.collect()


if __name__ == "__main__":
    unittest.main()
