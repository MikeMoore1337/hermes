"""Negative tests for H-15 pinned OCI receipt (no Docker/API required)."""
import json
from pathlib import Path
import tempfile
import unittest

from scripts.h15_brc_oci_receipt import BASE_REF, UPSTREAM_SHA, ReceiptDenied, build_receipt


class OCIReceiptTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.dockerfile = self.root / "Dockerfile"
        self.image = self.root / "inspect.json"
        self.sbom = self.root / "sbom.json"
        self.audit = self.root / "audit.json"
        self.dockerfile.write_text(
            "FROM " + BASE_REF + " AS builder\nFROM " + BASE_REF + " AS runtime\n"
        )
        self.data = [{
            "Id": "sha256:" + "f" * 64,
            "Config": {
                "User": "65534:65534",
                "Cmd": ["node", "packages/relay/dist/cli.js"],
                "Env": ["NODE_ENV=production", "HOME=/tmp"],
                "Labels": {
                    "org.opencontainers.image.revision": UPSTREAM_SHA,
                    "org.opencontainers.image.licenses": "MIT",
                },
            },
        }]
        self.image.write_text(json.dumps(self.data))
        self.sbom.write_text(json.dumps({
            "bomFormat": "CycloneDX", "specVersion": "1.7",
            "components": [{"name": f"dep-{i}", "version": "1"} for i in range(15)],
        }))
        self.audit.write_text(json.dumps({
            "status": "SOURCE_PIN_VERIFIED", "sha": UPSTREAM_SHA,
            "live_execution": "DENIED", "production_ready": False,
        }))

    def check(self):
        return build_receipt(
            dockerfile=self.dockerfile, inspect_json=self.image,
            sbom_file=self.sbom, source_audit=self.audit, git_sha="a" * 40,
        )

    def test_valid_receipt_is_explicitly_not_deployable(self):
        actual = self.check()
        self.assertEqual(actual["status"], "CI_IMAGE_VERIFIED_NOT_DEPLOYABLE")
        self.assertEqual(actual["owner_device_execution"], "NOT_ENABLED")
        self.assertEqual(actual["production_deployment"], "NOT_AUTHORIZED")
        self.assertEqual(actual["sbom_component_count"], 15)
        self.assertEqual(len(actual["cyclonedx_sha256"]), 64)

    def test_unpinned_second_base_denied(self):
        self.dockerfile.write_text("FROM " + BASE_REF + " AS builder\nFROM node:24-bookworm-slim AS runtime")
        with self.assertRaisesRegex(ReceiptDenied, "unapproved_or_unpinned_oci_base"):
            self.check()

    def test_root_image_denied(self):
        self.data[0]["Config"]["User"] = "root"
        self.image.write_text(json.dumps(self.data))
        with self.assertRaisesRegex(ReceiptDenied, "oci_runtime_principal_not_nonroot"):
            self.check()

    def test_baked_secret_denied(self):
        self.data[0]["Config"]["Env"].append("BRC_ADMIN_PASSWORD=never-store")
        self.image.write_text(json.dumps(self.data))
        with self.assertRaisesRegex(ReceiptDenied, "secret_bearing_image_environment"):
            self.check()

    def test_wrong_command_denied(self):
        self.data[0]["Config"]["Cmd"] = ["sh", "-c", "anything"]
        self.image.write_text(json.dumps(self.data))
        with self.assertRaisesRegex(ReceiptDenied, "unexpected_runtime_command"):
            self.check()

    def test_empty_sbom_denied(self):
        self.sbom.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.7", "components": []}))
        with self.assertRaisesRegex(ReceiptDenied, "invalid_or_empty_dependency_sbom"):
            self.check()

    def test_unverified_upstream_denied(self):
        self.audit.write_text(json.dumps({
            "status": "SOURCE_PIN_VERIFIED", "sha": UPSTREAM_SHA,
            "live_execution": "ENABLED", "production_ready": True,
        }))
        with self.assertRaisesRegex(ReceiptDenied, "upstream_provenance_unverified"):
            self.check()


if __name__ == "__main__":
    unittest.main()
