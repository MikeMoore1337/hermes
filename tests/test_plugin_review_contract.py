"""Issue #464: negative-only offline contract of plugin review metadata."""
from __future__ import annotations

from copy import deepcopy
import json
import socket
import subprocess
import unittest
from unittest.mock import patch

from hermes_toolperf.plugin_cases import load_cases, run_negative_corpus
from hermes_toolperf.plugin_review import (
    PIN, REVIEW, ReviewDenied, SyntheticReader, canonical, parse,
    sample_manifest, sha256, validate,
)


class PluginReviewContractTests(unittest.TestCase):
    def test_all_sixteen_pinned_negative_cases_have_no_effect(self):
        report = run_negative_corpus()
        self.assertEqual((report["passed"], report["total"]), (16, 16))
        self.assertEqual(len({r["case_sha256"] for r in report["results"]}), 16)
        self.assertFalse(report["runtime_plugins_installed"])
        self.assertFalse(report["external_source_verified"])
        self.assertEqual(load_cases()["schema_version"], 1)

    def test_valid_reviewed_fixture_has_exact_scope_and_no_effects(self):
        manifest = sample_manifest()
        validated = validate(manifest)
        self.assertEqual(validated["status"], "synthetic_review_match")
        self.assertEqual(validated["source_commit"], PIN)
        reader = SyntheticReader()
        output = reader.read(canonical(manifest).decode("utf-8"),
                             call_id="trial-one", fixture_id="research-record-v1")
        self.assertEqual(output["record_id"], "study-demo-01")
        self.assertEqual(output["source_kind"], "synthetic")
        self.assertEqual(reader.effects, [])
        output["record_id"] = "forged"
        again = SyntheticReader().read(canonical(manifest).decode("utf-8"),
                                       call_id="trial-new", fixture_id="research-record-v1")
        self.assertEqual(again["record_id"], "study-demo-01")

    def test_replay_is_refused_and_does_not_create_effect(self):
        reader = SyntheticReader()
        raw = canonical(sample_manifest()).decode("utf-8")
        reader.read(raw, call_id="trial-one", fixture_id="research-record-v1")
        with self.assertRaisesRegex(ReviewDenied, "DUPLICATE_CALL"):
            reader.read(raw, call_id="trial-one", fixture_id="research-record-v1")
        self.assertEqual(reader.effects, [])
        self.assertEqual(reader.calls, {"trial-one"})

    def test_disabled_and_unreviewed_policy_fails_closed(self):
        for changed, reason in (({"enabled": False}, "REVIEW_DISABLED"),
                                ({"reviewed": False}, "NOT_REVIEWED"),
                                ({"reviewed": 1}, "NOT_REVIEWED"),
                                ({"enabled": "yes"}, "REVIEW_DISABLED")):
            with self.subTest(changed=changed):
                review = {**deepcopy(REVIEW), **changed}
                reader = SyntheticReader(review=review)
                with self.assertRaisesRegex(ReviewDenied, reason):
                    reader.read(canonical(sample_manifest()).decode("utf-8"),
                                call_id="trial-one", fixture_id="research-record-v1")
                self.assertEqual(reader.effects, [])
                self.assertEqual(reader.calls, set())

    def test_review_pin_is_exact_commit_and_license_not_manifest_claim(self):
        for changed in (
            {"source_commit": "a" * 40},
            {"license": "Apache-2.0"},
            {"capabilities": ["qa.read"]},
            {"data_scope": "synthetic:private"},
        ):
            with self.subTest(changed=changed):
                policy = {**deepcopy(REVIEW), **changed}
                with self.assertRaisesRegex(ReviewDenied, "REVIEW_PIN_MISMATCH"):
                    validate(sample_manifest(), review=policy)

    def test_untrusted_readonlyhint_does_not_grant_permission(self):
        payload = {**sample_manifest(), "readOnlyHint": True}
        with self.assertRaisesRegex(ReviewDenied, "MANIFEST_SCHEMA"):
            validate(payload)
        payload = {**sample_manifest(), "side_effects": ["readOnlyHint=true", "write"]}
        with self.assertRaisesRegex(ReviewDenied, "SIDE_EFFECTS_DENIED"):
            validate(payload)

    def test_external_urls_private_scope_and_optional_installs_denied(self):
        for changed, reason in (
            ({"source_repo": "https://example.org/evil"}, "SOURCE_NOT_REVIEWED"),
            ({"data_scope": "second-brain:vault"}, "DATA_SCOPE_NOT_ALLOWLISTED"),
            ({"optional_dependencies": ["pip:requests"]}, "OPTIONAL_DEPENDENCIES_DENIED"),
        ):
            with self.subTest(changed=changed):
                with self.assertRaisesRegex(ReviewDenied, reason):
                    validate({**sample_manifest(), **changed})

    def test_unexpected_fixture_and_invalid_call_id_do_not_read(self):
        raw = canonical(sample_manifest()).decode("utf-8")
        for call_id, fixture_id, error in (
            ("trial-one", "../../private", "FIXTURE_OUT_OF_SCOPE"),
            ("bad/call", "research-record-v1", "INVALID_CALL_ID"),
            (None, "research-record-v1", "INVALID_CALL_ID"),
        ):
            reader = SyntheticReader()
            with self.subTest(call_id=call_id, fixture_id=fixture_id):
                with self.assertRaisesRegex(ReviewDenied, error):
                    reader.read(raw, call_id=call_id, fixture_id=fixture_id)
                self.assertEqual(reader.calls, set())
                self.assertFalse(reader.effects)

    def test_bad_json_unknown_keys_and_nonfinite_rejected(self):
        for text, reason in (
            ("{broken", "INVALID_JSON"),
            ("[]", "MANIFEST_NOT_OBJECT"),
            ('{"id":"x","id":"y"}', "DUPLICATE_KEY"),
            ('{"id":NaN}', "INVALID_NUMBER"),
            (" " * 4097, "INPUT_OVERSIZED"),
        ):
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(ReviewDenied, reason):
                    parse(text)

    def test_dataset_hash_changes_with_manifest_and_keeps_v1(self):
        dataset = load_cases()
        self.assertEqual(dataset["dataset"], "h464-review-manifest-negative-v1")
        modified = deepcopy(dataset)
        modified["cases"][0]["expected_reason"] = "forged"
        self.assertNotEqual(sha256(dataset), sha256(modified))

    def test_no_network_subprocess_or_runtime_plugin_import(self):
        with patch.object(socket.socket, "connect",
                          side_effect=AssertionError("unexpected network")), \
             patch.object(subprocess, "Popen",
                          side_effect=AssertionError("unexpected process")):
            report = run_negative_corpus()
            result = SyntheticReader().read(
                canonical(sample_manifest()).decode("utf-8"),
                call_id="trial-one", fixture_id="research-record-v1")
        self.assertEqual(report["passed"], 16)
        self.assertEqual(result["source_kind"], "synthetic")


if __name__ == "__main__":
    unittest.main()
