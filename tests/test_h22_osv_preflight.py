"""H-22: prerequisites never imply a completed OSV scan or trustworthy DB."""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from scripts import preflight_osv_offline_scan as preflight


ELF = b"\x7fELF\x02\x01" + b"\x00" * 12 + b"\x3e\x00"
ADVISORY = {"id": "PYSEC-2024-12345", "affected": []}


class OSVPreflightTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.binary = root / "osv-scanner_linux_amd64"
        self.binary.write_bytes(ELF)
        self.db_root = root / "db"
        self.lockfile = root / "uv.lock"
        self.lockfile.write_text(
            'version = 1\nrevision = 3\nrequires-python = ">=3.11"\n'
            '[[package]]\nname = "fictional-public"\nversion = "1.0"\n'
            'source = { registry = "https://pypi.org/simple" }\n',
            encoding="utf-8",
        )
        self.make_database("PyPI")
        self.patches = [
            patch.object(preflight, "BINARY_SIZE", len(ELF)),
            patch.object(preflight, "BINARY_SHA256", hashlib.sha256(ELF).hexdigest()),
        ]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    def make_database(self, eco, name="PYSEC-2024-12345.json", raw=None):
        directory = self.db_root / "osv-scanner" / eco
        directory.mkdir(parents=True, exist_ok=True)
        archive = directory / "all.zip"
        with zipfile.ZipFile(archive, "w") as handle:
            handle.writestr(name, json.dumps(ADVISORY).encode() if raw is None else raw)
        return archive

    def test_verified_binary_and_parseable_database_still_inconclusive(self):
        result = preflight.assess(self.binary, self.db_root, self.lockfile)
        self.assertEqual(result["status"], "INCONCLUSIVE")
        self.assertEqual(result["lockfile_ecosystem"], "PyPI")
        self.assertEqual(result["lockfile_packages_parsed"], 1)
        self.assertEqual(result["db_member_count"], 1)
        self.assertTrue(result["pilot_inputs_ready"])
        for flag in ("scanner_executed", "db_freshness_verified",
                     "db_completeness_verified", "publisher_provenance_verified",
                     "offline_network_boundary_verified", "resident_agent_allowed",
                     "auto_upgrade_allowed", "scanner_extraction_verified"):
            self.assertFalse(result[flag], flag)

    def test_npm_packages_are_counted_without_claiming_osv_extraction(self):
        self.lockfile.unlink()
        self.lockfile = self.lockfile.with_name("package-lock.json")
        self.lockfile.write_text(json.dumps({"lockfileVersion": 3, "packages": {
            "": {"name": "synthetic"},
            "node_modules/lodash": {"version": "4.17.20"},
            "node_modules/parent/node_modules/thing": {"version": "1.2.0"},
        }}))
        self.make_database("npm")
        result = preflight.assess(self.binary, self.db_root, self.lockfile)
        self.assertEqual((result["lockfile_ecosystem"], result["lockfile_packages_parsed"]),
                         ("npm", 2))
        self.assertFalse(result["scanner_extraction_verified"])

    def test_reject_binary_digest_mismatch(self):
        with patch.object(preflight, "BINARY_SHA256", "0" * 64):
            with self.assertRaisesRegex(preflight.Denied, "binary_digest_mismatch"):
                preflight.assess(self.binary, self.db_root, self.lockfile)

    def test_reject_binary_size_mismatch(self):
        with patch.object(preflight, "BINARY_SIZE", len(ELF) + 1):
            with self.assertRaisesRegex(preflight.Denied, "binary_size_mismatch"):
                preflight.assess(self.binary, self.db_root, self.lockfile)

    def test_reject_wrong_architecture(self):
        self.binary.write_bytes(ELF[:18] + b"\xb7\x00")
        with patch.object(preflight, "BINARY_SHA256",
                          hashlib.sha256(self.binary.read_bytes()).hexdigest()):
            with self.assertRaisesRegex(preflight.Denied, "unexpected_binary_architecture"):
                preflight.assess(self.binary, self.db_root, self.lockfile)

    def test_missing_database_is_not_security_pass(self):
        (self.db_root / "osv-scanner" / "PyPI" / "all.zip").unlink()
        with self.assertRaises(preflight.Denied):
            preflight.assess(self.binary, self.db_root, self.lockfile)

    def test_reject_corrupt_database(self):
        (self.db_root / "osv-scanner" / "PyPI" / "all.zip").write_bytes(b"fake ZIP")
        with self.assertRaises(preflight.Denied):
            preflight.assess(self.binary, self.db_root, self.lockfile)

    def test_reject_archive_path_traversal(self):
        self.make_database("PyPI", "../escape.json")
        with self.assertRaises(preflight.Denied):
            preflight.assess(self.binary, self.db_root, self.lockfile)

    def test_reject_database_without_json_advisory(self):
        self.make_database("PyPI", "notes.txt", b"not a vulnerability DB")
        with self.assertRaises(preflight.Denied):
            preflight.assess(self.binary, self.db_root, self.lockfile)

    def test_reject_malformed_advisory_sample(self):
        self.make_database("PyPI", raw=b'{"unexpected": true}')
        with self.assertRaises(preflight.Denied):
            preflight.assess(self.binary, self.db_root, self.lockfile)

    def test_reject_malformed_lockfile(self):
        self.lockfile.write_text("[[package]]\nname = [", encoding="utf-8")
        with self.assertRaisesRegex(preflight.Denied, "invalid_lockfile"):
            preflight.assess(self.binary, self.db_root, self.lockfile)

    def test_reject_unsupported_lockfile(self):
        self.lockfile = self.lockfile.with_name("requirements.txt")
        self.lockfile.write_text("requests==2.31.0")
        with self.assertRaisesRegex(preflight.Denied, "unsupported_lockfile"):
            preflight.assess(self.binary, self.db_root, self.lockfile)

    def test_reject_symlink_lockfile(self):
        original = self.lockfile
        self.lockfile = self.lockfile.with_name("symlink")
        self.lockfile.symlink_to(original)
        with self.assertRaises(preflight.Denied):
            preflight._file(self.lockfile, preflight.LOCKFILE_LIMIT)

    def test_cli_default_has_no_file_access(self):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            code = preflight.main([])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stream.getvalue())["status"], "NOT_EXECUTED")

    def test_cli_error_does_not_leak_paths(self):
        secret = "SECRET_PATH_MARKER"
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            code = preflight.main(["--check", "--binary", secret,
                                   "--db-root", secret, "--lockfile", secret])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(stream.getvalue())["status"], "INCONCLUSIVE")
        self.assertNotIn(secret, stream.getvalue())

    def test_cli_with_valid_inputs_returns_inconclusive_exit_2(self):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            code = preflight.main(["--check", "--binary", str(self.binary),
                                   "--db-root", str(self.db_root),
                                   "--lockfile", str(self.lockfile)])
        self.assertEqual(code, 2)
        self.assertTrue(json.loads(stream.getvalue())["pilot_inputs_ready"])


if __name__ == "__main__":
    unittest.main()
