"""Pinned tools Git blobs match independently from unverified vendor runtimes."""
from __future__ import annotations

import io
import json
import unittest
from unittest.mock import Mock, patch

from scripts import verify_v0221_tools_python as audit
from scripts import verify_v0221_core_python as core

META = json.dumps([audit.IMAGE]).encode() + b"|amd64"


def packet(files, vendor=None):
    return json.dumps({
        "schema": "hermes-v0221-tools-image-sample-v1",
        "files": files,
        "vendor_python_file_counts": audit.VENDOR_COUNTS if vendor is None else vendor,
    }, separators=(",", ":")).encode()


def rows(entries):
    return [
        {"path": name, "git_blob_sha1": checksum, "size": size}
        for name, (checksum, size) in sorted(entries.items())
    ]


class PinnedToolsSampleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected = audit.manifest()

    def test_expected_source_tree_exactly_353(self):
        self.assertEqual(len(self.expected), audit.EXPECTED_FILES)
        self.assertIn("tools", {p.split("/")[0] for p in self.expected})

    def test_realistic_tools_sample_has_separate_vendor_counts(self):
        outcome = audit.parse(self.expected, packet(rows(self.expected)))
        self.assertEqual(outcome["status"], "TOOLS_PYTHON_BLOBS_MATCH_UNATTESTED")
        self.assertTrue(outcome["tools_scope_matches"])
        self.assertEqual(sum(outcome["vendor_python_file_counts"].values()), 1176)
        self.assertFalse(outcome["vendor_runtime_content_verified"])
        self.assertFalse(outcome["resident_agent_allowed"])

    def test_wrong_source_blob_is_mismatch(self):
        sample = rows(self.expected)
        sample[0]["git_blob_sha1"] = "0" * 40
        outcome = audit.parse(self.expected, packet(sample))
        self.assertEqual(outcome["different_count"], 1)
        self.assertFalse(outcome["tools_scope_matches"])

    def test_missing_or_extra_python_sources_denied(self):
        sample = rows(self.expected)
        missing = audit.parse(self.expected, packet(sample[:-1]))
        self.assertEqual(missing["missing_count"], 1)
        extra = audit.parse(self.expected, packet([
            *sample, {"path": "tools/extra_file.py", "git_blob_sha1": "0" * 40,
                      "size": 1},
        ]))
        self.assertEqual(extra["extra_count"], 1)

    def test_vendor_runtime_counts_are_not_content_attestation(self):
        observed = dict(audit.VENDOR_COUNTS)
        observed["python-3.14.7+20260901-linux-x64"] += 1
        outcome = audit.parse(self.expected, packet(rows(self.expected), observed))
        self.assertEqual(outcome["status"], "TOOLS_PYTHON_BLOBS_MISMATCH")
        self.assertTrue(outcome["vendor_file_count_drift"])
        self.assertFalse(outcome["vendor_runtime_content_verified"])

    def test_bogus_vendor_and_path_traversal_refused(self):
        bad_vendor = dict(audit.VENDOR_COUNTS)
        bad_vendor["unknown-runtime"] = 5
        with self.assertRaises(core.ParityDenied):
            audit.parse(self.expected, packet(rows(self.expected), bad_vendor))
        bad = rows(self.expected)
        bad[0]["path"] = "../outside.py"
        with self.assertRaises(core.ParityDenied):
            audit.parse(self.expected, packet(bad))

    def test_duplicate_file_and_source_url_data_are_rejected(self):
        bad = rows(self.expected)
        bad.append(bad[0])
        with self.assertRaises(core.ParityDenied):
            audit.parse(self.expected, packet(bad))
        with self.assertRaises(core.ParityDenied):
            audit.parse(self.expected, b'{"schema":"x","schema":"y","files":[]}')

    def test_exact_pinned_docker_without_mounts_or_network(self):
        inspect, container = audit.commands()
        self.assertEqual(inspect, core.commands()[0])
        self.assertEqual(container.count(audit.IMAGE), 1)
        for term in ("--pull=never", "--network", "none", "--read-only",
                     "--cap-drop", "ALL", "--user", "65534:65534",
                     "--cpus", "0.25", "--memory", "256m"):
            self.assertIn(term, container)
        for bad in ("--mount", "--volume", "--privileged", "--env-file", "-v"):
            self.assertNotIn(bad, container)
        self.assertIn("vendor[relative.parts[0]] += 1", audit.INSPECTOR)

    def test_wrong_image_identity_denied_before_container(self):
        runner = Mock(return_value=Mock(returncode=0, stdout=b"[]|amd64"))
        with self.assertRaises(core.ParityDenied):
            audit.observe(runner=runner)
        runner.assert_called_once()

    def test_only_two_fixed_docker_calls_with_no_raw_errors(self):
        calls = []
        def runner(command, **kw):
            calls.append(command)
            return Mock(returncode=0, stdout=META if len(calls) == 1
                        else packet(rows(self.expected)), stderr=b"SECRET_TOKEN")
        result = audit.observe(runner=runner)
        self.assertEqual(calls, list(audit.commands()))
        self.assertNotIn("SECRET_TOKEN", str(result))

    def test_explicit_flag_required_and_success_never_grants_go(self):
        with patch.object(audit, "observe") as observer:
            with patch("sys.stdout", new_callable=io.StringIO) as output:
                self.assertEqual(audit.main([]), 0)
        observer.assert_not_called()
        self.assertEqual(json.loads(output.getvalue())["status"], "NOT_EXECUTED")
        matched = audit.parse(self.expected, packet(rows(self.expected)))
        with patch.object(audit, "observe", return_value=matched):
            with patch("sys.stdout", new_callable=io.StringIO) as output:
                self.assertEqual(audit.main(["--execute"]), 2)
        self.assertFalse(json.loads(output.getvalue())["resident_agent_allowed"])


if __name__ == "__main__":
    unittest.main()
