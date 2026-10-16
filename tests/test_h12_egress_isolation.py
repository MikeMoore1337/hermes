"""Offline OS no-egress tests: strict claims and negative evidence handling."""
from __future__ import annotations

import json
import unittest
from unittest.mock import Mock, patch

from scripts import verify_h12_egress_isolation as iso
from scripts.verify_v0222_immutable import IMAGE

META = json.dumps([IMAGE]).encode("ascii") + b"|amd64"


def packet(override=None):
    checks = {name: True for name in iso.REQUIRED}
    if override is not None:
        checks.update(override)
    return json.dumps({"schema": iso.SCHEMA, "checks": checks}).encode()


class IsolatedEgressTests(unittest.TestCase):
    def test_default_does_not_start_docker(self):
        with patch.object(iso, "observe") as observe:
            self.assertEqual(iso.main([]), 0)
        observe.assert_not_called()

    def test_fixed_immutable_no_network_privilege_free_docker_command(self):
        inspect, run = iso.commands()
        self.assertIn(IMAGE, inspect)
        self.assertIn(IMAGE, run)
        for token in ("--pull=never", "--platform", "linux/amd64",
                      "--network", "none", "--read-only", "--cap-drop",
                      "ALL", "--security-opt", "no-new-privileges",
                      "--user", "65534:65534", "--memory", "256m",
                      "--pids-limit", "25"):
            self.assertIn(token, run)
        for forbidden in ("--privileged", "--network=host", "--mount",
                          "--volume", "-v", "--env-file", "--device",
                          "host", "bridge"):
            self.assertNotIn(forbidden, run)
        self.assertIn("169.254.169.254", iso.PROBE)
        self.assertIn("2001:db8::1", iso.PROBE)
        self.assertNotIn("http.client", iso.PROBE)

    def test_valid_positive_evidence_still_does_not_admit_live_network(self):
        result = iso.evaluate(packet())
        self.assertEqual(result["checks_passed"], 9)
        self.assertEqual(result["status"], "OFFLINE_NETWORK_NONE_OS_DENIALS_PASS")
        self.assertFalse(result["network_namespace_selective_allowlist_verified"])
        self.assertFalse(result["global_firewall_verified"])
        self.assertFalse(result["real_public_https_verified"])
        self.assertFalse(result["metadata_http_invoked"])
        self.assertFalse(result["resident_agent_allowed"])
        self.assertFalse(result["statejnik_live_network_allowed"])

    def test_false_check_fails_and_cannot_be_omitted(self):
        for name in iso.REQUIRED:
            with self.subTest(name=name):
                failed = iso.evaluate(packet({name: False}))
                self.assertEqual(failed["failed_checks"], [name])
                self.assertFalse(failed["ipv4_ipv6_egress_for_network_none_verified"])
                malformed = json.loads(packet())
                del malformed["checks"][name]
                with self.assertRaises(iso.EgressProbeDenied):
                    iso.evaluate(json.dumps(malformed).encode())

    def test_duplicate_fields_unknown_or_nonbool_never_pass(self):
        samples = (
            b"{}",
            b'{"schema":"x","checks":{}}',
            b'{"schema":"a","schema":"b","checks":{}}',
            packet({"some_new_rule": True}),
            packet({sorted(iso.REQUIRED)[0]: 1}),
            packet({sorted(iso.REQUIRED)[0]: "true"}),
            b"[]",
            b"null",
            b"not JSON",
        )
        for case in samples:
            with self.subTest(case=case[:35]), self.assertRaises(iso.EgressProbeDenied):
                iso.evaluate(case)

    def test_failed_digest_or_docker_process_produces_no_go(self):
        cases = (
            (b"invalid-image-identity", packet()),
            (META, b"{}"),
        )
        for identity, response in cases:
            call = [0]
            def runner(*_args, **_kwargs):
                call[0] += 1
                return Mock(stdout=identity if call[0] == 1 else response)
            with self.subTest(response=response[:18]), patch.object(
                    iso, "run_bounded", side_effect=runner):
                result = iso.observe()
                self.assertEqual(result["status"], "OFFLINE_EGRESS_EVIDENCE_UNAVAILABLE")
                self.assertFalse(result["resident_agent_allowed"])

    def test_mocked_two_step_success_no_live_or_cost_go(self):
        calls = []
        def runner(args, **_kwargs):
            calls.append(args)
            return Mock(stdout=META if len(calls) == 1 else packet())
        with patch.object(iso, "run_bounded", side_effect=runner):
            result = iso.observe()
        self.assertEqual(calls, list(iso.commands()))
        self.assertEqual(result["status"], "OFFLINE_NETWORK_NONE_OS_DENIALS_PASS")
        self.assertFalse(result["statejnik_live_network_allowed"])


if __name__ == "__main__":
    unittest.main()
