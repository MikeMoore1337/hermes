"""Integration I1: synthetic/offline tests for a conservative task handoff."""
from __future__ import annotations

import copy
import json
import subprocess
import sys
import unittest
from pathlib import Path

from integrations.task_handoff import HandoffRefused, MAX_PACKET_BYTES, validate, validate_json


REPO = "MikeMoore1337/hermes"
SHA = "a" * 40
RUN = "https://github.com/" + REPO + "/actions/runs/123"
ISSUE = "https://github.com/" + REPO + "/issues/556"
PULL = "https://github.com/" + REPO + "/pull/12"


def packet() -> dict:
    return {
        "schema_version": 1,
        "task": {"repository": REPO, "issue": 556},
        "workspace": {"alias": "hermes", "scope": "sandbox", "git_verified": False},
        "toolkit": {"profile": None, "selection": "NOT_VERIFIED"},
        "evidence": {
            "pr": None,
            "tests": {"state": "NOT_RUN", "ref": None},
            "ci": {"state": "NOT_VERIFIED", "ref": None, "sha": None},
            "production": {"state": "NOT_VERIFIED", "ref": None, "sha": None},
            "owner_acceptance": "PENDING",
        },
    }


class HandoffBoundaryTests(unittest.TestCase):
    def test_empty_unverified_is_not_a_release_or_permission(self):
        result = validate(packet())
        self.assertEqual(result["validation"]["status"], "VALID_SHAPE_ONLY")
        self.assertEqual(result["validation"]["source_claims"], "UNVERIFIED")
        self.assertFalse(result["validation"]["execution_authorized"])
        self.assertFalse(result["validation"]["release_authorized"])
        self.assertFalse(result["validation"]["ready_to_close"])

    def test_reported_success_and_approval_still_not_verified(self):
        data = packet()
        data["toolkit"] = {"profile": "qa-python", "selection": "REPORTED_SELECTED"}
        data["evidence"]["pr"] = {"number": 12, "head_sha": SHA, "ref": PULL}
        data["evidence"]["tests"] = {"state": "REPORTED_PASS", "ref": ISSUE}
        data["evidence"]["ci"] = {"state": "REPORTED_SUCCESS", "sha": SHA, "ref": RUN}
        data["evidence"]["production"] = {
            "state": "REPORTED_DEPLOYED", "sha": SHA, "ref": RUN,
        }
        data["evidence"]["owner_acceptance"] = "REPORTED_ACCEPTED"
        result = validate_json(json.dumps(data).encode())
        self.assertEqual(result["validation"]["status"], "VALID_SHAPE_ONLY")
        self.assertFalse(result["validation"]["ready_to_close"])

    def test_repo_and_workspace_are_bounded_to_registered_public_sources(self):
        for change in (
            lambda x: x["task"].update(repository="SomeoneElse/private"),
            lambda x: x["workspace"].update(alias="otus-python-developer-basic"),
            lambda x: x["workspace"].update(alias="crypto-ema-bot"),
            lambda x: x["workspace"].update(scope="native-host"),
            lambda x: x["workspace"].update(git_verified=True),
            lambda x: x["task"].update(issue=True),
            lambda x: x["task"].update(issue=-1),
        ):
            with self.subTest(change=change):
                data = packet()
                change(data)
                with self.assertRaises(HandoffRefused):
                    validate(data)

    def test_unknown_fields_paths_secrets_commands_and_payloads_refused(self):
        for key, value in (
            ("command", "rm -rf /"),
            ("device_id", "h15-win"),
            ("root", "/private/vault"),
            ("token", "github_pat_REDACTED"),
            ("raw_log", "user-private-data"),
            ("body", "untrusted injection"),
        ):
            with self.subTest(key=key):
                data = packet()
                data["workspace"][key] = value
                with self.assertRaisesRegex(HandoffRefused, "workspace_fields_invalid"):
                    validate(data)

    def test_links_must_be_scoped_to_canonical_repo_and_path(self):
        for bad in (
            "https://evil.invalid/" + REPO + "/issues/556",
            "http://github.com/" + REPO + "/issues/556",
            "https://github.com/" + REPO + "/issues/556?token=abc",
            "https://github.com/" + REPO + "/issues/556#fragment",
            "https://github.com/" + REPO + "/tree/main",
            "https://github.com/MikeMoore1337/second-brain/issues/556",
            "https://github.com/" + REPO + "/issues/556/../../secrets",
            "https://github.com@" + "evil.invalid/" + REPO + "/issues/556",
        ):
            data = packet()
            data["evidence"]["tests"] = {"state": "REPORTED_PASS", "ref": bad}
            with self.subTest(bad=bad), self.assertRaisesRegex(
                    HandoffRefused, "tests_ref_invalid"):
                validate(data)

    def test_conflicts_and_fabricated_ci_are_refused(self):
        data = packet()
        data["evidence"]["ci"] = {
            "state": "REPORTED_SUCCESS", "ref": RUN, "sha": "b" * 40,
        }
        data["evidence"]["pr"] = {"number": 12, "head_sha": SHA, "ref": PULL}
        with self.assertRaisesRegex(HandoffRefused, "ci_pr_head_mismatch"):
            validate(data)
        data["evidence"]["ci"]["sha"] = SHA
        data["evidence"]["pr"]["ref"] = ISSUE
        with self.assertRaisesRegex(HandoffRefused, "pr_ref_mismatch"):
            validate(data)
        data = packet()
        data["evidence"]["production"]["sha"] = SHA
        with self.assertRaisesRegex(HandoffRefused, "production_unknown_claim_conflict"):
            validate(data)

    def test_json_size_duplicates_binary_unsupported_versions(self):
        good = json.dumps(packet()).encode()
        self.assertEqual(validate_json(good)["validation"]["status"], "VALID_SHAPE_ONLY")
        for raw in (
            b'{"schema_version":1,"schema_version":2}',
            b"\x00" + good,
            b"\xff" + good,
            b"x" * (MAX_PACKET_BYTES + 1),
        ):
            with self.subTest(size=len(raw)), self.assertRaises(HandoffRefused):
                validate_json(raw)
        data = packet()
        data["schema_version"] = True
        with self.assertRaisesRegex(HandoffRefused, "schema_unsupported"):
            validate(data)

    def test_stdin_cli_offline_success_and_sanitized_error(self):
        script = Path(__file__).resolve().parents[1] / "scripts" / "check_task_handoff.py"
        success = subprocess.run(
            [sys.executable, str(script)],
            input=json.dumps(packet()).encode(),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=10,
        )
        self.assertEqual(success.returncode, 0, success.stderr)
        self.assertEqual(json.loads(success.stdout)["validation"]["status"], "VALID_SHAPE_ONLY")
        failure = subprocess.run(
            [sys.executable, str(script)],
            input=b'{"secret":"TOP_SECRET_INJECTION"}',
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=10,
        )
        self.assertEqual(failure.returncode, 2)
        self.assertNotIn("TOP_SECRET", failure.stdout.decode())
        self.assertEqual(json.loads(failure.stdout)["status"], "REFUSED")


if __name__ == "__main__":
    unittest.main()
