"""H-01 sampled image/source parity never authorizes resident AI."""
from __future__ import annotations

import io
import json
import unittest
from unittest.mock import Mock, patch

from scripts import verify_v0221_source_sample as audit

META = json.dumps([audit.IMAGE]).encode() + b"|amd64"


def packet(blobs=None):
    return json.dumps({
        "schema": "hermes-v0221-git-blobs-v1",
        "blobs": audit.EXPECTED if blobs is None else blobs,
    }).encode()


class PinnedSourceSampleTests(unittest.TestCase):
    def test_dry_run_does_not_touch_docker(self):
        with patch.object(audit, "observe") as observer:
            with patch("sys.stdout", new_callable=io.StringIO) as out:
                self.assertEqual(audit.main([]), 0)
        observer.assert_not_called()
        self.assertEqual(json.loads(out.getvalue())["status"], "NOT_EXECUTED")

    def test_exact_image_and_locked_down_runtime(self):
        first, second = audit.commands()
        self.assertEqual(first[:3], ["docker", "image", "inspect"])
        self.assertEqual(second.count(audit.IMAGE), 1)
        for required in ("--pull=never", "--network", "none", "--read-only",
                         "--cap-drop", "ALL", "--user", "65534:65534",
                         "--memory", "256m", "--pids-limit", "25"):
            self.assertIn(required, second)
        for forbidden in ("--privileged", "--mount", "--volume", "-v",
                          "--env-file", "push", "login"):
            self.assertNotIn(forbidden, second)
        self.assertEqual(set(audit.EXPECTED), {
            "agent/auxiliary_fallback_recovery.py", "agent/billing_usage.py",
            "agent/tool_executor.py", "agent/tool_guardrails.py",
            "hermes_cli/main.py", "providers/base.py",
        })
        self.assertIn('file.is_symlink()', audit.INSPECTOR)
        self.assertIn('hashlib.sha1(b"blob "', audit.INSPECTOR)

    def test_six_matching_git_blobs_remain_no_go(self):
        result = audit.parse(META, packet())
        self.assertEqual(result["status"], "SAMPLED_GIT_BLOBS_MATCH_UNATTESTED")
        self.assertEqual(result["checked_files"], 6)
        self.assertEqual(result["mismatched_paths"], [])
        self.assertTrue(result["sample_byte_parity_verified"])
        self.assertFalse(result["full_source_parity_verified"])
        self.assertFalse(result["resident_agent_allowed"])

    def test_one_changed_source_file_is_not_reported_as_matching(self):
        modified = dict(audit.EXPECTED)
        modified["agent/tool_guardrails.py"] = "0" * 40
        result = audit.parse(META, packet(modified))
        self.assertEqual(result["status"], "SAMPLED_GIT_BLOBS_MISMATCH")
        self.assertEqual(result["mismatched_paths"], ["agent/tool_guardrails.py"])
        self.assertFalse(result["sample_byte_parity_verified"])

    def test_wrong_architecture_or_digest_rejected(self):
        for meta in (b"[]|amd64", b"[]|arm64", META.replace(b"amd64", b"arm64"),
                     b"UNTRUSTED|amd64"):
            with self.subTest(meta=meta), self.assertRaises(audit.SampleDenied):
                audit.parse(meta, packet())

    def test_untrusted_json_rejected(self):
        bad = [
            b"",
            b'{"schema":"hermes-v0221-git-blobs-v1","blobs":{}}',
            b'{"schema":"hermes-v0221-git-blobs-v1","schema":"a","blobs":{}}',
            b'{"schema":"hermes-v0221-git-blobs-v1","blobs":[]}',
            b'{"schema":"hermes-v0221-git-blobs-v1","blobs":{"secret":"bad"}}',
            b"X" * 4097,
        ]
        for raw in bad:
            with self.subTest(raw=raw[:40]), self.assertRaises(audit.SampleDenied):
                audit.parse(META, raw)

    def test_non_hex_and_extra_file_rejected(self):
        bad = dict(audit.EXPECTED)
        bad["agent/billing_usage.py"] = "private-token"
        with self.assertRaises(audit.SampleDenied):
            audit.parse(META, packet(bad))
        bad = dict(audit.EXPECTED)
        bad["/etc/passwd"] = "0" * 40
        with self.assertRaises(audit.SampleDenied):
            audit.parse(META, packet(bad))

    def test_observe_executes_two_commands_only_and_hides_stderr(self):
        calls = []
        def runner(command, **kwargs):
            calls.append(command)
            return Mock(returncode=0, stdout=META if len(calls) == 1 else packet(),
                        stderr=b"SECRET_NEVER_OUTPUT")
        result = audit.observe(runner=runner)
        self.assertEqual(calls, list(audit.commands()))
        self.assertNotIn("SECRET", str(result))

    def test_no_image_or_failed_container_fails_closed(self):
        for failing_call in (1, 2):
            calls = []
            def runner(command, **kwargs):
                calls.append(command)
                return Mock(returncode=1 if len(calls) == failing_call else 0,
                            stdout=META if len(calls) == 1 else packet(),
                            stderr=b"SECRET")
            with self.subTest(call=failing_call):
                with self.assertRaises(audit.SampleDenied):
                    audit.observe(runner=runner)
                self.assertEqual(len(calls), failing_call)

    def test_successful_sample_still_returns_exit_code_2(self):
        with patch.object(audit, "observe",
                          return_value=audit.parse(META, packet())):
            with patch("sys.stdout", new_callable=io.StringIO) as out:
                self.assertEqual(audit.main(["--execute"]), 2)
        self.assertFalse(json.loads(out.getvalue())["resident_agent_allowed"])


if __name__ == "__main__":
    unittest.main()
