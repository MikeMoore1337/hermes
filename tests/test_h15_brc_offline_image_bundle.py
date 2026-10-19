"""H-15 source-to-container transfer provenance: negative digest and manifest gates."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts.h15_brc_offline_image_bundle import BundleDenied, build, verify, digest_file


ROOT = Path(__file__).resolve().parents[1]


class OfflineBundleTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.image_id = "sha256:" + "a" * 64
        self.hermes_sha = "b" * 40
        self.payload = self.root / "brc-relay.docker.tar.zst"
        self.payload.write_bytes(b"offline-only-ci-dummy-byte-stream")
        self.sbom = self.root / "sbom.cdx.json"
        self.sbom.write_text(json.dumps({"bomFormat": "CycloneDX", "components": [{"name": "pkg"}]}))
        self.os_sbom = self.root / "os-packages.cdx.json"
        self.os_sbom.write_text(json.dumps({
            "bomFormat": "CycloneDX", "specVersion": "1.5",
            "metadata": {"component": {"type": "container", "version": self.image_id}},
            "components": [
                {"type": "library", "bom-ref": f"pkg:deb/debian/lib{i}@1?arch=amd64",
                 "purl": f"pkg:deb/debian/lib{i}@1?arch=amd64",
                 "name": f"lib{i}", "version": "1"}
                for i in range(40)
            ],
        }))
        self.receipt = self.root / "OCI_RECEIPT.json"
        self.receipt.write_text(json.dumps({
            "status": "CI_IMAGE_VERIFIED_NOT_DEPLOYABLE",
            "production_deployment": "NOT_AUTHORIZED",
            "owner_device_execution": "NOT_ENABLED",
            "upstream_sha": "cbe511702dd0147650353c29ac6ab1decd8afda1",
            "hermes_commit": self.hermes_sha, "image_id": self.image_id,
            "image_user": "65534:65534", "application_license": "MIT",
            "sbom_format": "CycloneDX", "sbom_component_count": 15,
            "cyclonedx_sha256": digest_file(self.sbom),
        }))
        self.inspect = self.root / "inspect.json"
        self.inspect.write_text(json.dumps([{
            "Id": self.image_id, "Os": "linux", "Architecture": "amd64",
            "Config": {"User": "65534:65534"},
        }]))
        self.archive_sha = digest_file(self.payload)

    def create_and_verify(self):
        receipt = build(directory=self.root, inspect=self.inspect)
        result = verify(
            directory=self.root,
            expected_archive_sha=self.archive_sha,
            expected_image_id=self.image_id,
            expected_hermes_sha=self.hermes_sha,
        )
        self.assertEqual(result, receipt)
        return result

    def test_strict_build_verify_and_non_deploy_claim(self):
        result = self.create_and_verify()
        self.assertFalse(result["owner_agents_paired"])
        self.assertFalse(result["production_mcp_enabled"])
        self.assertEqual(result["status"], "OFFLINE_IMAGE_EXPORT_NOT_DEPLOYED")

    def test_reject_mismatched_independent_hash(self):
        build(directory=self.root, inspect=self.inspect)
        with self.assertRaisesRegex(BundleDenied, "manifest_independent_pin_mismatch"):
            verify(directory=self.root, expected_archive_sha="f" * 64,
                   expected_image_id=self.image_id, expected_hermes_sha=self.hermes_sha)

    def test_reject_modified_os_sbom(self):
        self.create_and_verify()
        doc = json.loads(self.os_sbom.read_text())
        doc["components"][0]["version"] = "fake"
        self.os_sbom.write_text(json.dumps(doc))
        with self.assertRaisesRegex(BundleDenied, "bundle_payload_digest_mismatch"):
            verify(directory=self.root, expected_archive_sha=self.archive_sha,
                   expected_image_id=self.image_id, expected_hermes_sha=self.hermes_sha)

    def test_reject_os_sbom_with_wrong_image_id(self):
        data = json.loads(self.os_sbom.read_text())
        data["metadata"]["component"]["version"] = "sha256:" + "f" * 64
        self.os_sbom.write_text(json.dumps(data))
        with self.assertRaisesRegex(BundleDenied, "unverified_os_package_inventory"):
            build(directory=self.root, inspect=self.inspect)

    def test_reject_modified_archive(self):
        self.create_and_verify()
        self.payload.write_bytes(b"modified")
        with self.assertRaisesRegex(BundleDenied, "bundle_payload_digest_mismatch"):
            verify(directory=self.root, expected_archive_sha=self.archive_sha,
                   expected_image_id=self.image_id, expected_hermes_sha=self.hermes_sha)

    def test_reject_tampered_signed_source_receipt(self):
        self.create_and_verify()
        doc = json.loads(self.receipt.read_text())
        doc["production_deployment"] = "AUTHORIZED"
        self.receipt.write_text(json.dumps(doc))
        with self.assertRaisesRegex(BundleDenied, "unapproved_oci_source_receipt"):
            verify(directory=self.root, expected_archive_sha=self.archive_sha,
                   expected_image_id=self.image_id, expected_hermes_sha=self.hermes_sha)

    def test_reject_architecture_mismatch(self):
        content = json.loads(self.inspect.read_text())
        content[0]["Architecture"] = "arm64"
        self.inspect.write_text(json.dumps(content))
        with self.assertRaisesRegex(BundleDenied, "incorrect_linux_amd64_image"):
            build(directory=self.root, inspect=self.inspect)

    def test_reject_symlinked_archive(self):
        self.payload.unlink()
        real = self.root / "external"
        real.write_bytes(b"symlink-target")
        self.payload.symlink_to(real)
        with self.assertRaisesRegex(BundleDenied, "unsafe_bundle_file"):
            build(directory=self.root, inspect=self.inspect)

    def test_reject_empty_oci_sbom(self):
        doc = json.loads(self.receipt.read_text())
        doc["sbom_component_count"] = 0
        self.receipt.write_text(json.dumps(doc))
        with self.assertRaisesRegex(BundleDenied, "unapproved_oci_source_receipt"):
            build(directory=self.root, inspect=self.inspect)

    def test_reject_extra_manifest_fields(self):
        self.create_and_verify()
        path = self.root / "IMAGE_BUNDLE.json"
        doc = json.loads(path.read_text())
        doc["invented_production_authorization"] = True
        path.write_text(json.dumps(doc))
        with self.assertRaisesRegex(BundleDenied, "unexpected_manifest_schema"):
            verify(directory=self.root, expected_archive_sha=self.archive_sha,
                   expected_image_id=self.image_id, expected_hermes_sha=self.hermes_sha)

    def test_shell_loader_syntax(self):
        p = ROOT / "deploy/h15/load-verified-image.sh"
        r = subprocess.run(["bash", "-n", str(p)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_shell_loader_rejects_tag_before_touching_docker(self):
        p = ROOT / "deploy/h15/load-verified-image.sh"
        r = subprocess.run(["bash", str(p), "verify", str(self.root),
                            "f" * 64, "latest", self.hermes_sha],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)
        self.assertIn("INVALID_IMAGE_PIN", r.stderr)


if __name__ == "__main__":
    unittest.main()
