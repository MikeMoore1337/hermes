"""H-15 deploy contract: tests are offline and never touch Docker or owner VPS."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy/h15/owner-relay.sh"
BACKUP = ROOT / "deploy/h15/backup-relay.py"
EVALUATION_ID = "sha256:4f0da80149db3670c3b0d14462e5609225b3718c09872f48e9ba584a4de0a7e6"


class H15ProductionRelayContractTests(unittest.TestCase):
    def test_bash_syntax(self):
        result = subprocess.run(["bash", "-n", str(DEPLOY)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_no_autostart_and_inactive_by_default(self):
        code = DEPLOY.read_text()
        self.assertIn("H15_BRC_OWNER_APPROVED_OAUTH_ONLY", code)
        self.assertIn("YES_OAUTH_ONLY_NO_AGENTS", code)
        self.assertIn("H15_BRC_OWNER_APPROVED_STOP", code)
        self.assertIn("EVALUATION_IMAGE_NOT_PRODUCTION_APPROVED", code)
        self.assertIn(EVALUATION_ID, code)
        self.assertIn("H15_DEPLOY_CHANGES=NONE", code)
        self.assertIn("UNAUTHORIZED_MCP_HTTP=401", code)
        self.assertIn("PUBLIC_MCP_HTTP=503", code)
        self.assertIn("H15_DEPLOY_START=PASS", code)
        self.assertNotIn("docker pull", code)
        self.assertNotIn("docker build", code)

    def test_no_broad_host_network_or_privileged_access(self):
        code = DEPLOY.read_text()
        for field in (
            "--network \"$NETWORK\"", "--ip \"$RELAY_IP\"", "--read-only",
            "--cap-drop ALL", "--security-opt no-new-privileges",
            "--pids-limit 80", "--memory 512m", "--cpus 0.50",
            "--mount \"type=bind,src=$STATE,dst=/state\"",
            "getent passwd", "--user \"$(id -u \"$ACCOUNT\")",
            "HOST=0.0.0.0", "PUBLIC_URL=\"$PUBLIC_URL\"",
            "TRUST_PROXY=false", "NETWORK=hermes-brc-internal",
        ):
            self.assertIn(field, code)
        for forbidden in (
            "--privileged", "--network host", "--publish", "--device ",
            "/var/run/docker.sock", "/root:/", "/var/lib/hermes-device-fabric",
            "docker system prune", "systemctl restart", "docker exec \"$NAME\" sh",
        ):
            self.assertNotIn(forbidden, code)
        self.assertIn("docker port \"$NAME\"", code)
        self.assertIn("FOREIGN_CONTAINER_REFUSED", code)
        self.assertIn("STATE_PERMISSIONS", code)
        self.assertIn("SECRET_PERMISSIONS", code)
        self.assertIn("FOREIGN_NETWORK_REFUSED", code)

    def test_bad_or_missing_cli_arguments_refused_without_docker(self):
        for args in ([], ["anything"], ["status", "extra"], ["start"]):
            with self.subTest(args=args):
                result = subprocess.run(["bash", str(DEPLOY), *args],
                                        capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("H15_BRC_DEPLOY_REFUSED=", result.stderr)
                self.assertNotIn("H15_DEPLOY_START=PASS", result.stdout)


class H15SqliteBackupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("h15_sqlite_backup", BACKUP)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def test_snapshot_preserves_data_and_has_0600_permissions(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            database = root / "state" / "relay.sqlite"
            database.parent.mkdir()
            archive = root / "archives"
            archive.mkdir(mode=0o700)
            with sqlite3.connect(database) as db:
                db.execute("CREATE TABLE calls (request TEXT)")
                db.execute("INSERT INTO calls VALUES (?)", ("test-call",))
            backup = self.module.backup_sqlite(database, archive)
            self.assertEqual(backup.parent, archive)
            self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
            with sqlite3.connect(backup) as restored:
                self.assertEqual(restored.execute("SELECT request FROM calls").fetchone()[0],
                                 "test-call")
                self.assertEqual(restored.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            self.assertFalse(list(archive.glob(".relay-backup-*")))

    def test_existing_snapshot_is_never_overwritten(self):
        from unittest.mock import patch
        from datetime import datetime, timezone

        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            source = root / "relay.sqlite"
            with sqlite3.connect(source) as db:
                db.execute("CREATE TABLE users (name TEXT)")
                db.execute("INSERT INTO users VALUES ('original')")
            target_dir = root / "backups"
            target_dir.mkdir(mode=0o700)
            fixed_now = datetime(2026, 10, 19, 15, 0, 0, 123456, tzinfo=timezone.utc)
            fixed_name = "relay-20261019T150000123456Z.sqlite3"
            existing = target_dir / fixed_name
            existing.write_bytes(b"must-not-be-overwritten")
            with patch.object(self.module.datetime, "now", return_value=fixed_now):
                with self.assertRaises(FileExistsError):
                    self.module.backup_sqlite(source, target_dir)
            self.assertEqual(existing.read_bytes(), b"must-not-be-overwritten")
            self.assertEqual(list(target_dir.glob(".relay-backup-*")), [])

    def test_nonexistent_and_symlinked_db_are_denied(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            archive = root / "archives"
            archive.mkdir(mode=0o700)
            with self.assertRaises(ValueError):
                self.module.backup_sqlite(root / "missing.sqlite", archive)
            source = root / "db"
            with sqlite3.connect(source) as db:
                db.execute("CREATE TABLE t (x)")
            alias = root / "alias"
            alias.symlink_to(source)
            with self.assertRaises(ValueError):
                self.module.backup_sqlite(alias, archive)

    def test_insecure_backup_dir_refused(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            database = root / "db.sqlite"
            with sqlite3.connect(database) as db:
                db.execute("CREATE TABLE t (x)")
            archive = root / "archives"
            archive.mkdir(mode=0o755)
            with self.assertRaises(PermissionError):
                self.module.backup_sqlite(database, archive)


if __name__ == "__main__":
    unittest.main()
