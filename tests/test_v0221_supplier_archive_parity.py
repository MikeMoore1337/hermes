"""Offline archive parity refuses corrupt, incomplete or untrusted evidence."""
from __future__ import annotations

import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from scripts import verify_v0221_supplier_archive_parity as check

META = json.dumps([check.IMAGE]).encode() + b"|amd64"
SEVEN = {key: {"size": 3, "sha256": "a" * 64} for key in check.IMAGE_FILES}


def packet(data=None):
    return json.dumps({
        "schema": "hermes-v0221-vendor-selected-files-v1",
        "files": SEVEN if data is None else data,
    }).encode()


class SourceArchiveParityContracts(unittest.TestCase):
    def test_noop_default_and_explicit_directory_required(self):
        with patch.object(check, "observe") as observer:
            self.assertEqual(check.main([]), 0)
            self.assertEqual(check.main(["--execute"]), 2)
        observer.assert_not_called()

    def test_offline_archive_member_hash_and_modified_archive_denial(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "demo.tar"
            with tarfile.open(archive, mode="w") as out:
                info = tarfile.TarInfo("package/bin/demo")
                data = b"example-data"
                info.size = len(data)
                out.addfile(info, io.BytesIO(data))
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            selection = {"demo": (digest, {"package/bin/demo": "item"})}
            with patch.object(check, "ARCHIVES", selection):
                result = check.archive_evidence(Path(directory))
                self.assertEqual(result["item"]["size"], len(data))
                self.assertEqual(result["item"]["sha256"], hashlib.sha256(data).hexdigest())
                archive.write_bytes(archive.read_bytes() + b"changed")
                with self.assertRaisesRegex(check.SupplierEvidenceDenied, "archive_digest_mismatch"):
                    check.archive_evidence(Path(directory))

    def test_wrong_or_missing_archive_is_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(check.SupplierEvidenceDenied):
                check.archive_evidence(Path(directory))

    def test_matching_data_is_partial_no_go(self):
        result = check.evaluate(SEVEN, packet())
        self.assertEqual(result["status"], "SELECTED_VENDOR_RELEASE_BYTES_MATCH")
        self.assertEqual(result["matched_files"], 7)
        self.assertFalse(result["resident_agent_allowed"])
        self.assertFalse(result["signed_supplier_attestation_verified"])

    def test_incomplete_supplier_scope_fails_closed(self):
        with self.assertRaisesRegex(check.SupplierEvidenceDenied,
                                    "incomplete_official_archive_scope"):
            check.evaluate({}, packet())

    def test_hash_mismatch_is_explicit_not_attestation(self):
        altered = dict(SEVEN)
        altered["npm_bin"] = {"size": 3, "sha256": "0" * 64}
        result = check.evaluate(SEVEN, packet(altered))
        self.assertEqual(result["mismatched_files"], ["npm_bin"])
        self.assertFalse(result["resident_agent_allowed"])

    def test_schema_and_duplicate_keys_denied(self):
        for payload in (
            b"{}",
            b'{"schema":"a","schema":"b","files":{}}',
            packet({}),
            b"\xff",
        ):
            with self.subTest(length=len(payload)):
                with self.assertRaises(check.SupplierEvidenceDenied):
                    check.evaluate(SEVEN, payload)

    def test_nonzero_docker_commands_deny_even_with_fake_output(self):
        for failure_at in (1, 2):
            calls = []
            def runner(command, **kwargs):
                calls.append(command)
                return Mock(
                    stdout=META if len(calls) == 1 else packet(),
                    returncode=1 if len(calls) == failure_at else 0,
                )
            with self.subTest(failure_at=failure_at):
                with patch.object(check, "archive_evidence", return_value=SEVEN):
                    with self.assertRaises(check.SupplierEvidenceDenied):
                        check.observe(Path("."), runner)

    def test_only_pinned_restricted_inspection_is_invoked(self):
        calls = []
        def runner(command, **kwargs):
            calls.append((command, kwargs))
            return Mock(stdout=META if len(calls) == 1 else packet(), returncode=0,
                        stderr=b"PRIVATE_NO_ECHO")
        with patch.object(check, "archive_evidence", return_value=SEVEN):
            result = check.observe(Path("."), runner)
        expected = check.commands()
        self.assertEqual([call[0] for call in calls], list(expected))
        self.assertNotIn("--mount", expected[1])
        self.assertIn("--network", expected[1])
        self.assertIn("none", expected[1])
        self.assertEqual(calls[1][1]["stdout_limit"], 8192)
        self.assertNotIn("PRIVATE_NO_ECHO", str(result))


if __name__ == "__main__":
    unittest.main()
