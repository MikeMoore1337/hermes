"""Offline SQLite credential-regression scenarios; no live relay or secrets."""
from pathlib import Path
import hashlib
import os
import shutil
import sqlite3
import tempfile
import unittest

from scripts.h15_brc_state_rollback_guard import (
    CredentialRegressionDenied, compare_disposable_copies, main,
)

SCHEMA = """
CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT, password_hash TEXT);
CREATE TABLE oauth_clients (client_id TEXT PRIMARY KEY, client_secret TEXT, metadata TEXT);
CREATE TABLE auth_codes (code TEXT PRIMARY KEY, client_id TEXT, user_id TEXT,
    code_challenge TEXT, redirect_uri TEXT, scopes TEXT, resource TEXT, expires_at INT);
CREATE TABLE tokens (token_hash TEXT PRIMARY KEY, kind TEXT, client_id TEXT,
    user_id TEXT, scopes TEXT, resource TEXT, expires_at INT, revoked INT);
CREATE TABLE devices (device_id TEXT PRIMARY KEY, user_id TEXT, token_hash TEXT, paused INT);
CREATE TABLE device_codes (device_code TEXT PRIMARY KEY, user_id TEXT, approved INT,
    denied INT, device_id TEXT, expires_at INT);
CREATE TABLE api_keys (key_hash TEXT PRIMARY KEY, user_id TEXT, revoked INT);
"""


@unittest.skipUnless(os.name == "posix", "Offline POSIX copy gate")
class StateRollbackGuard(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="h15-rollback-disposable-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        os.chmod(self.root, 0o700)
        self.snapshot = self.root / "snapshot.sqlite"
        self.current = self.root / "current.sqlite"
        with sqlite3.connect(self.snapshot) as db:
            db.executescript(SCHEMA)
            db.execute("INSERT INTO users VALUES ('u', 'owner', 'hash-old')")
            db.execute("INSERT INTO oauth_clients VALUES ('c', NULL, '{}')")
            db.execute("INSERT INTO auth_codes VALUES ('authcode', 'c', 'u', 'challenge', 'url', 'scope', NULL, 9000)")
            db.execute("INSERT INTO tokens VALUES ('accessHash', 'access', 'c', 'u', 'scope', NULL, 9000, 0)")
            db.execute("INSERT INTO tokens VALUES ('refreshHash', 'refresh', 'c', 'u', 'scope', NULL, 9000, 0)")
            db.execute("INSERT INTO devices VALUES ('dev', 'u', 'oldTokenHash', 0)")
            db.execute("INSERT INTO device_codes VALUES ('code', 'u', 1, 0, 'dev', 9000)")
            db.execute("INSERT INTO api_keys VALUES ('keyHash', 'u', 0)")
        shutil.copy2(self.snapshot, self.current)
        os.chmod(self.snapshot, 0o600)
        os.chmod(self.current, 0o600)

    def reset_current(self):
        shutil.copy2(self.snapshot, self.current)
        os.chmod(self.current, 0o600)

    def update(self, sql):
        with sqlite3.connect(self.current) as db:
            db.execute(sql)

    def check_refused(self, sql):
        self.update(sql)
        with self.assertRaisesRegex(CredentialRegressionDenied, "STALE_SECURITY_STATE"):
            compare_disposable_copies(self.snapshot, self.current)

    def test_identical_offline_snapshots_pass_without_writing(self):
        before = [hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in (self.snapshot, self.current)]
        self.assertEqual(compare_disposable_copies(self.snapshot, self.current),
                         "PASS_READ_ONLY_NO_CREDENTIAL_REINTRODUCTION")
        self.assertEqual(before, [hashlib.sha256(p.read_bytes()).hexdigest()
                                  for p in (self.snapshot, self.current)])

    def test_revoked_access_or_refresh_token_cannot_resurrect(self):
        for sql in ("UPDATE tokens SET revoked=1 WHERE token_hash='accessHash'",
                    "DELETE FROM tokens WHERE token_hash='refreshHash'"):
            with self.subTest(sql=sql):
                self.reset_current()
                self.check_refused(sql)

    def test_device_rotation_removal_pause_and_owner_change_denied(self):
        for sql in ("UPDATE devices SET token_hash='newTokenHash' WHERE device_id='dev'",
                    "DELETE FROM devices WHERE device_id='dev'",
                    "UPDATE devices SET paused=1 WHERE device_id='dev'",
                    "UPDATE devices SET user_id='other' WHERE device_id='dev'"):
            with self.subTest(sql=sql):
                self.reset_current()
                self.check_refused(sql)

    def test_revoked_api_key_and_consumed_codes_denied(self):
        for sql in ("UPDATE api_keys SET revoked=1 WHERE key_hash='keyHash'",
                    "DELETE FROM auth_codes WHERE code='authcode'",
                    "DELETE FROM device_codes WHERE device_code='code'",
                    "DELETE FROM oauth_clients WHERE client_id='c'",
                    "UPDATE users SET password_hash='newHash' WHERE id='u'"):
            with self.subTest(sql=sql):
                self.reset_current()
                self.check_refused(sql)

    def test_refuse_unsafe_file_modes_and_sidecars(self):
        os.chmod(self.snapshot, 0o644)
        with self.assertRaisesRegex(CredentialRegressionDenied, "UNSAFE_COPY_PERMISSIONS"):
            compare_disposable_copies(self.snapshot, self.current)
        os.chmod(self.snapshot, 0o600)
        (self.root / "snapshot.sqlite-wal").write_bytes(b"unsafe sidecar")
        with self.assertRaisesRegex(CredentialRegressionDenied, "UNSAFE_COPY_SIDECAR"):
            compare_disposable_copies(self.snapshot, self.current)

    def test_refuse_symlink_or_hardlinked_snapshot(self):
        target = self.root / "snapshot-original.sqlite"
        os.rename(self.snapshot, target)
        self.snapshot.symlink_to(target)
        with self.assertRaisesRegex(CredentialRegressionDenied, "UNSAFE_COPY_PATH"):
            compare_disposable_copies(self.snapshot, self.current)
        self.snapshot.unlink()
        os.link(target, self.snapshot)
        with self.assertRaisesRegex(CredentialRegressionDenied, "UNSAFE_COPY_TYPE"):
            compare_disposable_copies(self.snapshot, self.current)

    def test_refuse_current_database_as_snapshot(self):
        with self.assertRaisesRegex(CredentialRegressionDenied, "PRIVATE_DISPOSABLE_DIRECTORY_REQUIRED"):
            compare_disposable_copies(self.current, self.current)

    def test_cli_does_not_print_credentials_on_refusal(self):
        self.update("UPDATE tokens SET revoked=1 WHERE token_hash='accessHash'")
        from contextlib import redirect_stdout
        from io import StringIO
        output = StringIO()
        with redirect_stdout(output):
            rc = main(["--snapshot-copy", str(self.snapshot),
                       "--current-copy", str(self.current)])
        self.assertEqual(rc, 2)
        self.assertNotIn("accessHash", output.getvalue())
        self.assertIn("NOT_AUTHORIZED", output.getvalue())


if __name__ == "__main__":
    unittest.main()
