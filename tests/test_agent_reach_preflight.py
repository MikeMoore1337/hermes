"""Детерминированные негативные проверки интерфейса Agent Reach doctor."""

from __future__ import annotations

import json
import unittest

from content_research.agent_reach_preflight import (
    MAX_INPUT_BYTES,
    PreflightError,
    inspect_json,
    inspect_report,
)


class AgentReachPreflightTests(unittest.TestCase):
    def test_declared_web_backend_is_not_reported_as_verified_fetch(self):
        report = inspect_report({"web": {"status": "ok", "active_backend": "Jina Reader"}})
        web = next(item for item in report["channels"] if item["channel"] == "web")
        self.assertEqual(web["readiness"], "LOCAL_CHECK_ONLY")
        self.assertEqual(web["evidence"], "DECLARED_WITHOUT_NETWORK_CHECK")
        self.assertFalse(web["source_read_verified"])
        self.assertFalse(report["remote_read_verified"])
        self.assertFalse(report["production_integration_approved"])
        self.assertFalse(report["publication_allowed"])

    def test_configured_exa_is_not_mistaken_for_live_search(self):
        report = inspect_report({"exa_search": {"status": "warn", "message": "configured"}})
        exa = next(item for item in report["channels"] if item["channel"] == "exa_search")
        self.assertEqual(exa["readiness"], "NEEDS_MANUAL_CONFIGURATION_OR_PROBE")
        self.assertFalse(exa["source_read_verified"])

    def test_installed_github_tool_does_not_prove_authenticated_access(self):
        report = inspect_report({"github": {"status": "warn", "active_backend": None}})
        github = next(item for item in report["channels"] if item["channel"] == "github")
        self.assertEqual(github["evidence"], "LOCAL_TOOL_AUTH_UNVERIFIED")
        self.assertNotEqual(github["readiness"], "LOCAL_CHECK_ONLY")

    def test_absent_and_failed_channels_are_fail_closed(self):
        report = inspect_report({"rss": {"status": "error"}, "youtube": {"status": "off"}})
        by_name = {item["channel"]: item for item in report["channels"]}
        self.assertEqual(by_name["rss"]["readiness"], "UNAVAILABLE")
        self.assertEqual(by_name["youtube"]["readiness"], "UNAVAILABLE")
        self.assertEqual(by_name["web"]["readiness"], "NOT_IN_REPORT")

    def test_sensitive_messages_are_discarded_from_stdout_payload(self):
        marker = "secret-value-canary"
        report = {
            "web": {"status": "ok", "message": "token=" + marker},
            "twitter": {"status": "ok", "cookie": marker},
        }
        result = json.dumps(inspect_report(report))
        self.assertNotIn(marker, result)
        self.assertNotIn("twitter", result)
        self.assertNotIn("token", result)

    def test_malformed_channel_never_reflects_attacker_text(self):
        for bad in ({}, {"web": "token=leak"}, {"web": {"status": "PWN_TOKEN"}}):
            with self.subTest(bad=bad), self.assertRaises(PreflightError) as raised:
                inspect_report(bad if bad else ["invalid"])
            self.assertNotIn("TOKEN", str(raised.exception))
            self.assertNotIn("leak", str(raised.exception))

    def test_invalid_json_and_large_input_fail_without_echo(self):
        inputs = [b"", b"{", b"\xff", b"x" * (MAX_INPUT_BYTES + 1)]
        for payload in inputs:
            with self.subTest(length=len(payload)), self.assertRaises(PreflightError):
                inspect_json(payload)

    def test_valid_actual_doctor_shape_has_bounded_output(self):
        payload = json.dumps({
            "web": {
                "status": "ok", "name": "Any web", "message": "No network test",
                "tier": 0, "backends": ["Jina Reader"], "active_backend": "Jina Reader",
            },
            "youtube": {
                "status": "ok", "name": "YouTube", "message": "yt-dlp installed",
                "tier": 0, "backends": ["yt-dlp"], "active_backend": "yt-dlp",
            },
        }).encode()
        result = inspect_json(payload)
        self.assertEqual(result["schema"], "hermes-agent-reach-preflight-v1")
        self.assertEqual(result["channel_count"], 5)
        self.assertLess(len(json.dumps(result)), 1600)


if __name__ == "__main__":
    unittest.main()
