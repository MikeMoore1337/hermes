"""Pinned upstream release receipt mismatch: no side effects or false GO."""
from __future__ import annotations

import io
import json
import unittest
from unittest.mock import Mock, patch

from scripts.verify_upstream_release_receipt import (
    RECEIPT_DIGEST, RECEIPT_REF, VERSION_TAG, RELEASES,
    ReceiptDenied, check_once, classify, commands, main, read_arches,
)

CURRENT = "sha256:55e192fba0cd4fde61142abbff5adeacff40efdb482ccd0ff877924bd274f909"
RECEIPT_ARCHES = {
    "amd64": "sha256:ffa4fbb471c2bc8c85fbcfc629347585cc1586c86d2e6db465d01203ce696d95",
    "arm64": "sha256:7e36c10955df8bf957fbb034279770db17c5feab1733637608d1a1d9aceb8193",
}
CURRENT_ARCHES = {
    "amd64": "sha256:32d095e84190ae7266afbb361579e6921f2c633e899f5eacfb88111b9c851a22",
    "arm64": "sha256:93b295a42bdb6003e06fb9ce316bd6d4f4c09a93a7a89d263701ec6b1a79b208",
}


def manifest(arches=None):
    arches = arches if arches is not None else CURRENT_ARCHES
    return json.dumps({
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
        "manifests": [
            {"mediaType": "application/vnd.docker.distribution.manifest.v2+json",
             "digest": digest, "size": 500,
             "platform": {"architecture": arch, "os": "linux"}}
            for arch, digest in arches.items()
        ],
    }, separators=(",", ":")).encode()


class ReceiptGateContracts(unittest.TestCase):
    def test_newest_rc5_signed_claim_and_exact_registry_receipt(self):
        expected="sha256:861c9756ed6c558530c73d5c27860343b00c0d5efd6997a1d8ec6416c8a2b485"
        arches={
            "amd64":"sha256:cd9cb455576d27c9b6311de1104494ad7e221b6e68dc77e9ac2a8af661a4dc21",
            "arm64":"sha256:f24de2fd617c0bef83a8fcec4cda996aaa463705f8097e62ec4fb60eb2618d6b",
        }
        self.assertEqual(RELEASES["v0.22.1"]["receipt"],expected)
        self.assertTrue(RELEASES["v0.22.1"]["claim_tag_signature_verified"])
        self.assertIsNone(RELEASES["v0.22.1"]["claim_skip_tests"])
        result=classify(expected,arches,arches,release="v0.22.1")
        self.assertEqual(result["status"],"MATCHED_BUT_PROVENANCE_UNVERIFIED")
        self.assertTrue(result["manifest_digest_equal"])
        self.assertTrue(result["architecture_manifests_equal"])
        self.assertTrue(result["claim_tag_signature_verified"])
        self.assertFalse(result["supplier_signature_verified"])
        self.assertFalse(result["resident_agent_allowed"])
        self.assertEqual(result["release_commit"],
            "297552a9d646119871391d202509822cd86330df")

    def test_new_candidate_does_only_three_fixed_registry_reads(self):
        paths=commands("v0.22.1")
        self.assertEqual(len(paths),3)
        self.assertEqual(paths[0][4],"nousresearch/hermes-agent:v0.22.1")
        self.assertEqual(paths[1][-1],"--raw")
        self.assertIn(RELEASES["v0.22.1"]["receipt"],paths[2][4])
        for path in paths:
            self.assertEqual(path[:4],("docker","buildx","imagetools","inspect"))
            self.assertNotIn("pull",path)
            self.assertNotIn("run",path)
            self.assertNotIn("push",path)

    def test_release_is_strict_allowlist(self):
        for release in ("latest", ":main", "v0.22.2", "../secret", None, 1, []):
            with self.subTest(release=repr(release)):
                with self.assertRaisesRegex(ReceiptDenied,"release_not_allowlisted"):
                    commands(release)
                with self.assertRaisesRegex(ReceiptDenied,"release_not_allowlisted"):
                    classify(CURRENT,CURRENT_ARCHES,RECEIPT_ARCHES,release=release)

    def test_real_observed_mismatch_never_permits_agent(self):
        report = classify(CURRENT, CURRENT_ARCHES, RECEIPT_ARCHES)
        self.assertEqual(report["status"], "RELEASE_RECEIPT_MISMATCH")
        self.assertFalse(report["manifest_digest_equal"])
        self.assertFalse(report["architecture_manifests_equal"])
        self.assertFalse(report["resident_agent_allowed"])
        self.assertFalse(report["supplier_signature_verified"])
        self.assertFalse(report["complete_sbom_verified"])
        self.assertTrue(report["claim_skip_tests"])

    def test_even_equal_digests_not_sufficient_for_resident_agent(self):
        result = classify(RECEIPT_DIGEST, RECEIPT_ARCHES, RECEIPT_ARCHES)
        self.assertEqual(result["status"], "MATCHED_BUT_PROVENANCE_UNVERIFIED")
        self.assertTrue(result["manifest_digest_equal"])
        self.assertFalse(result["resident_agent_allowed"])
        self.assertFalse(result["reproducible_source_build_verified"])

    def test_no_execute_means_no_subprocess_or_api(self):
        with patch("scripts.verify_upstream_release_receipt.check_once") as c:
            with patch("sys.stdout", new_callable=io.StringIO) as stream:
                self.assertEqual(main([]), 0)
            c.assert_not_called()
        self.assertIn("NOT_EXECUTED", stream.getvalue())

    def test_commands_are_fixed_public_metadata_only(self):
        observed = commands()
        self.assertEqual(len(observed), 3)
        self.assertEqual(observed[0][-3], VERSION_TAG)
        self.assertIn(RECEIPT_REF, observed[2])
        for cmd in observed:
            self.assertEqual(cmd[:4], ("docker", "buildx", "imagetools", "inspect"))
            self.assertNotIn("pull", cmd)
            self.assertNotIn("build", cmd)
            self.assertNotIn("push", cmd)
            self.assertNotIn("run", cmd)
            self.assertNotIn("--raw-file", cmd)
            self.assertNotIn("login", cmd)
            self.assertNotIn("--env-file", cmd)

    def test_one_version_digest_and_exact_two_manifest_reads(self):
        calls = []
        fixtures = [
            json.dumps(CURRENT).encode(),
            manifest(CURRENT_ARCHES),
            manifest(RECEIPT_ARCHES),
        ]
        def runner(cmd, **kwargs):
            calls.append(cmd)
            self.assertEqual(kwargs["timeout"], 18)
            self.assertFalse(kwargs["check"])
            return Mock(returncode=0, stdout=fixtures[len(calls)-1], stderr=b"SECRET")
        report = check_once(runner=runner)
        self.assertEqual(calls, list(commands()))
        self.assertEqual(report["current_tag_manifest_digest"], CURRENT)
        self.assertEqual(report["receipt_architecture_digests"], RECEIPT_ARCHES)
        self.assertEqual(report["status"], "RELEASE_RECEIPT_MISMATCH")
        self.assertNotIn("SECRET", str(report))

    def test_network_failure_stops_remaining_calls(self):
        calls = []
        def broken(cmd, **kwargs):
            calls.append(cmd)
            return Mock(returncode=403, stdout=b"", stderr=b"Bearer github_pat_ABC")
        with self.assertRaisesRegex(ReceiptDenied, "public_registry_read_unavailable"):
            check_once(runner=broken)
        self.assertEqual(len(calls), 1)

    def test_untrusted_manifest_data_never_gets_promoted(self):
        bad = [
            b"",
            b'x' * 24577,
            b"not-json",
            b'{"schemaVersion":2,"schemaVersion":2}',
            json.dumps({"schemaVersion":2,"mediaType":"invalid","manifests":[]}).encode(),
            manifest({"amd64":CURRENT_ARCHES["amd64"]}),
            manifest({"amd64":CURRENT_ARCHES["amd64"],"unknown":CURRENT_ARCHES["arm64"]}),
            manifest({"amd64":"https://private.invalid","arm64":CURRENT_ARCHES["arm64"]}),
            manifest({"amd64":CURRENT_ARCHES["amd64"],"arm64":CURRENT_ARCHES["amd64"]}),
        ]
        for raw in bad:
            with self.subTest(size=len(raw)):
                with self.assertRaises(ReceiptDenied):
                    read_arches(raw)

    def test_non_boolean_sha_digest_and_arch_map_fail_closed(self):
        for digest in ("", True, None, "sha256:a", "https://malicious.invalid"):
            with self.subTest(digest=str(digest)):
                with self.assertRaisesRegex(ReceiptDenied, "registry_digest_invalid"):
                    classify(digest, CURRENT_ARCHES, RECEIPT_ARCHES)
        with self.assertRaisesRegex(ReceiptDenied,"registry_arch_map_invalid"):
            classify(CURRENT, {"amd64":"bad"}, RECEIPT_ARCHES)

    def test_execute_returns_nonzero_even_when_equal(self):
        valid = classify(RECEIPT_DIGEST,RECEIPT_ARCHES,RECEIPT_ARCHES)
        with patch("scripts.verify_upstream_release_receipt.check_once",
                   return_value=valid):
            with patch("sys.stdout",new_callable=io.StringIO) as out:
                self.assertEqual(main(["--execute"]),2)
        self.assertFalse(json.loads(out.getvalue())["resident_agent_allowed"])

    def test_execute_api_failure_is_unknown_with_no_secrets(self):
        with patch("scripts.verify_upstream_release_receipt.check_once",
                   side_effect=ReceiptDenied("Secret bearer-private")):
            with patch("sys.stdout",new_callable=io.StringIO) as out:
                self.assertEqual(main(["--execute"]),2)
        response=json.loads(out.getvalue())
        self.assertEqual(response["status"],"UNKNOWN")
        self.assertFalse(response["resident_agent_allowed"])
        self.assertNotIn("Secret",out.getvalue())


if __name__ == "__main__":
    unittest.main()
