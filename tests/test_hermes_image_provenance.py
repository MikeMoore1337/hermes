"""The approved pinned Hermes digest is not release-parity verified."""
from __future__ import annotations
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class HermessImagePinContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = json.loads((ROOT / "deploy/hermes-image-provenance.json").read_text())

    def test_immutable_digest_is_not_latest(self) -> None:
        data = self.manifest
        self.assertRegex(data["image"], r"^nousresearch/hermes-agent@sha256:[0-9a-f]{64}$")
        self.assertEqual(data["observed_image_id"], "sha256:" + data["image"].rsplit(":", 1)[-1])
        self.assertEqual(data["architecture"], "amd64")

    def test_official_registry_v0216_amd64_artifact_matches_pin(self) -> None:
        data = self.manifest
        self.assertEqual(
            data["published_registry_tag"],
            "nousresearch/hermes-agent:v0.21.6",
        )
        self.assertTrue(data["published_tag_amd64_match_verified"])
        self.assertEqual(
            data["published_tag_linux_amd64_digest"],
            data["observed_image_id"],
        )
        self.assertEqual(data["registry_manifest_inspected_date"], "2026-10-14")

    def test_source_commit_mismatch_keeps_resident_agent_disallowed(self) -> None:
        data = self.manifest
        self.assertNotEqual(data["reported_embedded_commit"], data["upstream_release_tag_commit"])
        self.assertEqual(data["known_commits_behind_release"], 39)
        self.assertFalse(data["source_release_parity_verified"])
        self.assertFalse(data["permanent_agent_runtime_approved"])

    def test_explicit_oci_sbom_and_attestation_absence_does_not_unlock_agent(self) -> None:
        data = self.manifest
        self.assertEqual(data["observed_oci_attestation_entries"], 0)
        self.assertIs(data["observed_oci_sbom_published"], False)
        self.assertIs(data["observed_oci_provenance_published"], False)
        self.assertIs(data["verified_full_sbom"], False)
        self.assertIs(data["permanent_agent_runtime_approved"], False)

    def test_local_image_file_samples_match_embedded_revision_but_not_tag(self) -> None:
        data = self.manifest
        self.assertEqual(len(data["verified_image_source_blobs"]), 4)
        self.assertEqual(data["verified_image_source_matches_embedded_count"], 4)
        self.assertEqual(data["verified_image_source_sample_date"], "2026-10-15")
        self.assertIs(data["source_release_parity_verified"], False)
        self.assertEqual(data["local_dpkg_package_count"], 274)
        self.assertRegex(data["local_dpkg_inventory_sha256"], r"^[0-9a-f]{64}$")

    def test_sampled_safe_stress_does_not_claim_burnin_or_unlock_agent(self) -> None:
        data = self.manifest
        self.assertEqual(data["last_bounded_text_turn"]["status"], "pass")
        self.assertEqual(data["last_bounded_text_turn"]["elapsed_seconds"], 113.4)
        stress = data["isolated_cpu_stress"]
        self.assertEqual(stress["samples"], 48)
        self.assertGreater(stress["load1_max"], 1.3)
        self.assertEqual(stress["swap_used_max_mib"], 0)
        self.assertTrue(stress["news_and_ops_timers_healthy"])
        self.assertIs(data["permanent_agent_runtime_approved"], False)

    def test_bounded_agent_uses_exact_pinned_digest(self) -> None:
        source = (ROOT / "scripts/agent_turn_probe.py").read_text()
        self.assertIn(self.manifest["image"], source)
        self.assertIn("--pull=never", source)
        self.assertIn("hermes-agent-test", source)
        self.assertIn("--cap-drop", source)
        self.assertNotIn(":latest", source)

    def test_documented_approval_flag_risk_and_release_history(self) -> None:
        report = (ROOT / "docs/audits/H-01-image-provenance-2026-10-14.md").read_text()
        self.assertIn("tools/approval_yolo.py", report)
        self.assertIn("39", report)
        self.assertIn("NO-GO", report)


if __name__ == "__main__":
    unittest.main()
