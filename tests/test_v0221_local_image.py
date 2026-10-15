"""Pinned v0.22.1 image evidence is offline, read-only and never grants GO."""
from __future__ import annotations
import io
import json
import unittest
from unittest.mock import Mock, patch

from scripts import verify_v0221_local_image as audit

META = json.dumps([audit.IMAGE]).encode() + b"|amd64"


def record(commit=audit.SOURCE_SHA):
    return json.dumps({
        "schema": "hermes-v0221-offline-inspector-v1",
        "embedded_commit": commit,
        "embedded_version": "0.22.1",
        "embedded_distribution": "docker",
        "os_packages": [
            {"name": "base-files", "version": "13.8+deb13u1"},
            {"name": "libc6:amd64", "version": "2.41-12"},
        ],
        "python_packages": [
            {"name": "hermes-agent", "version": "0.0.0"},
            {"name": "Hermes_Agent", "version": "0.0.0"},
            {"name": "httpx", "version": "0.28.1"},
        ],
    }).encode()


class LocalImageContracts(unittest.TestCase):
    def test_dry_run_never_touches_docker(self):
        with patch.object(audit, "observe") as observer:
            with patch("sys.stdout", new_callable=io.StringIO) as out:
                self.assertEqual(audit.main([]), 0)
            observer.assert_not_called()
        self.assertIn("NOT_EXECUTED", out.getvalue())

    def test_one_exact_pinned_image_and_no_host_mounts_network_or_root(self):
        inspect, run = audit.commands()
        self.assertIn(audit.IMAGE, inspect)
        self.assertIn(audit.IMAGE, run)
        self.assertEqual(inspect[:3], ["docker", "image", "inspect"])
        for required in ("--pull=never", "--network", "none", "--read-only",
                         "--cap-drop", "ALL", "--user", "65534:65534",
                         "--platform", "linux/amd64", "--memory", "256m",
                         "--pids-limit", "25", "/opt/hermes/.venv/bin/python"):
            self.assertIn(required, run)
        for forbidden in ("--privileged", "--volume", "--mount", "-v",
                          "--env-file", "push", "login"):
            self.assertNotIn(forbidden, run)
        self.assertEqual(run.count(audit.IMAGE), 1)

    def test_matching_embedded_stamp_is_not_image_attestation(self):
        result = audit.parse(META, record())
        self.assertEqual(result["status"], "EMBEDDED_STAMP_MATCH_IMAGE_UNATTESTED")
        self.assertEqual(result["os_package_entries"], 2)
        self.assertEqual(result["python_package_entries"], 3)
        self.assertEqual(result["duplicate_canonical_package_names"],
                         ["python-venv:hermes-agent"])
        self.assertTrue(result["embedded_stamp_matches_release_commit"])
        self.assertFalse(result["complete_sbom_verified"])
        self.assertFalse(result["source_to_image_parity_verified"])
        self.assertFalse(result["resident_agent_allowed"])

    def test_wrong_source_stamp_never_passes(self):
        result = audit.parse(META, record("0" * 40))
        self.assertEqual(result["status"], "EMBEDDED_STAMP_MISMATCH")
        self.assertFalse(result["embedded_stamp_matches_release_commit"])
        self.assertFalse(result["resident_agent_allowed"])

    def test_tampered_identity_is_rejected(self):
        for meta in (
            b'[]|amd64', json.dumps([audit.IMAGE]).encode() + b"|arm64",
            b'["evil:latest"]|amd64', b"NOT_JSON|amd64",
        ):
            with self.subTest(raw=meta):
                with self.assertRaises(audit.ImageEvidenceDenied):
                    audit.parse(meta, record())

    def test_malformed_and_poisoned_packages_never_pass(self):
        for change in (
            {"python_packages":[]},
            {"os_packages":[{"name":"token\nSECRET","version":"1"}]},
            {"python_packages":[{"name":"foo","version":"file:///secret"}]},
            {"python_packages":[{"name":"httpx","version":"1","url":"evil"}]},
        ):
            doc = json.loads(record())
            doc.update(change)
            with self.subTest(case=list(change)):
                with self.assertRaises(audit.ImageEvidenceDenied):
                    audit.parse(META, json.dumps(doc).encode())

    def test_only_two_local_commands_and_no_raw_stderr(self):
        calls = []
        def runner(command, **kwargs):
            calls.append(command)
            return Mock(
                returncode=0,
                stdout=META if len(calls) == 1 else record(),
                stderr=b"SECRET DO NOT PRINT",
            )
        result = audit.observe(runner=runner)
        self.assertEqual(calls, list(audit.commands()))
        self.assertNotIn("SECRET", str(result))

    def test_docker_failure_is_generic_no_new_pull(self):
        runner = Mock(return_value=Mock(returncode=1, stdout=b"", stderr=b"bearer TOKEN"))
        with self.assertRaisesRegex(audit.ImageEvidenceDenied,
                                    "pinned_image_not_loaded_locally"):
            audit.observe(runner=runner)
        self.assertEqual(runner.call_count, 1)
        with patch.object(audit, "observe",
                          side_effect=audit.ImageEvidenceDenied("SECRET_CREDENTIALS")):
            with patch("sys.stdout", new_callable=io.StringIO) as out:
                self.assertEqual(audit.main(["--execute"]), 2)
        self.assertNotIn("SECRET", out.getvalue())


if __name__ == "__main__":
    unittest.main()
