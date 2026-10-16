"""Synthetic fixtures exercise the Syft v1.54.1 and Trivy v0.76.0 native JSON.
No Docker, network, scanner binaries, credentials, or real image payload.
"""
from __future__ import annotations

import hashlib
import json
import unittest

from scripts import review_syft_trivy_evidence as review
from tests.test_h18_syft_trivy_evidence import payload


def modern_fixture():
    info, syft, trivy = payload("CRITICAL")
    pinned = review.IMAGE.partition("@")[2]
    # Syft 1.54.1 uses metadata rather than source.target. Its local
    # manifestDigest can differ from Docker RepoDigests for the same image.
    local = "sha256:" + "b" * 64
    syft["source"] = {
        "id": local[7:], "name": review.IMAGE.partition("@")[0],
        "version": pinned, "type": "image",
        "metadata": {
            "userInput": review.IMAGE, "repoDigests": [review.IMAGE],
            "architecture": "amd64", "os": "linux", "manifestDigest": local,
        },
    }
    trivy["Metadata"] = {"Reference": review.IMAGE, "RepoDigests": [review.IMAGE]}
    trivy["Trivy"] = {"Version": "0.69.0"}
    return info, syft, trivy


def encoded(info, syft, trivy):
    raw_syft = json.dumps(syft, sort_keys=True).encode()
    raw_trivy = json.dumps(trivy, sort_keys=True).encode()
    info["syft_sha256"] = hashlib.sha256(raw_syft).hexdigest()
    info["trivy_sha256"] = hashlib.sha256(raw_trivy).hexdigest()
    return json.dumps(info).encode(), raw_syft, raw_trivy


class NativeSchemaTest(unittest.TestCase):
    def test_real_native_schema_is_accepted_but_no_go(self):
        report = review.assess(*encoded(*modern_fixture()))
        self.assertEqual(report["status"], "HIGH_CVE_REVIEW")
        self.assertEqual(report["trivy_unique_vulnerability_ids"], 1)
        self.assertEqual(report["trivy_severity_counts"], {"CRITICAL": 1})
        self.assertFalse(report["syft_local_manifest_matches_pinned_repo_digest"])
        self.assertFalse(report["source_to_image_provenance_verified"])
        self.assertFalse(report["complete_sbom_verified"])
        self.assertFalse(report["resident_agent_allowed"])

    def test_matching_native_manifest_still_never_grants_go(self):
        info, syft, trivy = modern_fixture()
        pinned = review.IMAGE.partition("@")[2]
        syft["source"]["metadata"]["manifestDigest"] = pinned
        syft["source"]["id"] = pinned[7:]
        report = review.assess(*encoded(info, syft, trivy))
        self.assertTrue(report["syft_local_manifest_matches_pinned_repo_digest"])
        self.assertFalse(report["resident_agent_allowed"])

    def test_syft_identity_mutations_are_rejected(self):
        cases = (
            ("repoDigest", lambda s: s["source"]["metadata"].update(repoDigests=["other"])),
            ("platform", lambda s: s["source"]["metadata"].update(architecture="arm64")),
            ("os", lambda s: s["source"]["metadata"].update(os="windows")),
            ("userInput", lambda s: s["source"]["metadata"].update(userInput="mutable:latest")),
            ("name", lambda s: s["source"].update(name="attacker/image")),
            ("version", lambda s: s["source"].update(version="mutable:latest")),
            ("manifest", lambda s: s["source"]["metadata"].update(manifestDigest="invalid")),
            ("source_id", lambda s: s["source"].update(id="0"*64)),
        )
        for key, change in cases:
            with self.subTest(key=key):
                info, syft, trivy = modern_fixture()
                change(syft)
                with self.assertRaises(review.ScanEvidenceDenied):
                    review.assess(*encoded(info, syft, trivy))

    def test_trivy_identity_mutations_are_rejected(self):
        cases = (
            lambda t: t["Trivy"].update(Version="0.1.0"),
            lambda t: t["Metadata"].update(Reference="other"),
            lambda t: t["Metadata"].update(RepoDigests=["other"]),
        )
        for change in cases:
            info, syft, trivy = modern_fixture()
            change(trivy)
            with self.assertRaises(review.ScanEvidenceDenied):
                review.assess(*encoded(info, syft, trivy))

    def test_bad_type_ids_and_severities_rejected_not_logged(self):
        for change in (
            lambda f: f.update(VulnerabilityID=["CVE-EXAMPLE"]),
            lambda f: f.update(Severity=["CRITICAL"]),
            lambda f: f.update(VulnerabilityID=""),
        ):
            info, syft, trivy = modern_fixture()
            change(trivy["Results"][0]["Vulnerabilities"][0])
            with self.assertRaises(review.ScanEvidenceDenied):
                review.assess(*encoded(info, syft, trivy))


if __name__ == "__main__":
    unittest.main()
