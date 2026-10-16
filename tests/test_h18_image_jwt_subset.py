"""Network-free, Docker-free negative tests for H-18 local image source parity."""
from __future__ import annotations

import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from scripts import verify_v0222_image_jwt_subset as parity


class DummyDocker:
    def __init__(self, blobs: dict[str, bytes], *, fail_copy: bool = False,
                 fail_cleanup: bool = False):
        self.blobs = blobs
        self.fail_copy = fail_copy
        self.fail_cleanup = fail_cleanup
        self.calls: list[list[str]] = []
        self.out_files: list[Path] = []

    def __call__(self, argv: list[str]) -> bytes:
        self.calls.append(list(argv))
        assert argv[0] == "docker"
        if argv[1:3] == ["image", "inspect"]:
            return (parity.IMAGE.partition("@")[2] + "|linux|amd64\n").encode()
        if argv[1] == "create":
            return b"a" * 64 + b"\n"
        if argv[1] == "cp":
            if self.fail_copy:
                raise parity.ParityDenied("copy_failed")
            name = argv[2].partition(":/opt/hermes/")[2]
            target = Path(argv[3])
            target.write_bytes(self.blobs[name])
            self.out_files.append(target)
            return b""
        if argv[1] == "rm":
            if self.fail_cleanup:
                raise parity.ParityDenied("rm_failed")
            return b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        raise AssertionError("unexpected_Docker_command")


class ImageSubsetParityTest(unittest.TestCase):
    def fixture(self):
        blobs = {
            "plugins/cron_providers/chronos/verify.py": b"synthetic upstream source\n",
            "pyproject.toml": b"synthetic dependency pin\n",
        }
        expected = {name: parity._blob_hash(data) for name, data in blobs.items()}
        return blobs, expected

    def test_exact_allowlisted_files_are_checked_and_removed(self):
        blobs, expected = self.fixture()
        client = DummyDocker(blobs)
        with patch.dict(parity.EXPECTED, expected, clear=True):
            result = parity.audit(client)
        self.assertEqual(result["status"], "AUTH_SUBSET_PARITY_OBSERVED")
        self.assertEqual(result["source_files_matching_upstream"], 2)
        self.assertEqual(result["source_files_checked"], 2)
        self.assertFalse(result["resident_agent_allowed"])
        self.assertFalse(result["signed_source_to_image_provenance_verified"])
        self.assertFalse(result["complete_image_parity_verified"])
        self.assertFalse(result["docker_container_started"])
        self.assertTrue(result["temporary_container_removed"])
        self.assertEqual(sum(call[1] == "create" for call in client.calls), 1)
        self.assertEqual(sum(call[1] == "cp" for call in client.calls), 2)
        self.assertEqual(sum(call[1] == "rm" for call in client.calls), 1)
        self.assertTrue(all(not file.exists() for file in client.out_files))
        for argv in client.calls:
            self.assertFalse(any(x in argv for x in ("start", "run", "exec",
                                                     "--publish", "--privileged")))
        create = next(args for args in client.calls if args[1] == "create")
        for flag in ("--pull", "never", "--network", "none", "--read-only",
                     "--cap-drop", "ALL", "--security-opt", "no-new-privileges"):
            self.assertIn(flag, create)

    def test_mismatched_source_is_explicitly_not_passed(self):
        blobs, expected = self.fixture()
        blobs["pyproject.toml"] = b"tampered data"
        client = DummyDocker(blobs)
        with patch.dict(parity.EXPECTED, expected, clear=True):
            result = parity.audit(client)
        self.assertEqual(result["status"], "AUTH_SUBSET_MISMATCH")
        self.assertEqual(result["source_files_matching_upstream"], 1)
        self.assertFalse(result["resident_agent_allowed"])

    def test_failed_copy_still_removes_static_container(self):
        blobs, expected = self.fixture()
        client = DummyDocker(blobs, fail_copy=True)
        with patch.dict(parity.EXPECTED, expected, clear=True):
            with self.assertRaises(parity.ParityDenied):
                parity.audit(client)
        self.assertEqual(sum(call[1] == "rm" for call in client.calls), 1)

    def test_failed_container_cleanup_is_inconclusive(self):
        blobs, expected = self.fixture()
        client = DummyDocker(blobs, fail_cleanup=True)
        with patch.dict(parity.EXPECTED, expected, clear=True):
            with self.assertRaisesRegex(parity.ParityDenied,
                                        "temporary_container_cleanup_unverified"):
                parity.audit(client)

    def test_unexpected_image_identity_prevents_create(self):
        blobs, expected = self.fixture()
        client = DummyDocker(blobs)
        def spoof(argv):
            if argv[1:3] == ["image", "inspect"]:
                return b"sha256:" + b"b" * 64 + b"|linux|amd64"
            return client(argv)
        with patch.dict(parity.EXPECTED, expected, clear=True):
            with self.assertRaisesRegex(parity.ParityDenied,
                                        "unexpected_image_identity"):
                parity.audit(spoof)
        self.assertEqual(client.calls, [])

    def test_no_execute_default_does_not_touch_docker(self):
        with patch.object(parity, "audit", side_effect=AssertionError("called")):
            with patch("sys.stdout", new_callable=io.StringIO) as buf:
                self.assertEqual(parity.main([]), 0)
                self.assertEqual(json.loads(buf.getvalue())["status"], "NOT_EXECUTED")
                self.assertFalse(json.loads(buf.getvalue())["resident_agent_allowed"])

    def test_exec_errors_are_sanitized_and_no_go(self):
        with patch.object(parity, "audit", side_effect=parity.ParityDenied("mock_fail")):
            with patch("sys.stdout", new_callable=io.StringIO) as buf:
                self.assertEqual(parity.main(["--execute"]), 2)
                data = json.loads(buf.getvalue())
                self.assertEqual(data["status"], "INCONCLUSIVE")
                self.assertFalse(data["resident_agent_allowed"])
                self.assertNotIn("mock_fail", buf.getvalue())

    def test_git_blob_digest_definition(self):
        self.assertEqual(parity._blob_hash(b"hello\n"),
                         __import__("hashlib").sha1(b"blob 6\0hello\n").hexdigest())


if __name__ == "__main__":
    unittest.main()
