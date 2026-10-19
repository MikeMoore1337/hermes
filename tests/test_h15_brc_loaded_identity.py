"""H-15 offline OCI Docker identity verification regression tests (no Docker needed)."""
import hashlib
import io
import json
import tarfile
import unittest

from scripts.h15_brc_loaded_identity import (
    LoadedImageDenied, OCI_MANIFEST, UPSTREAM_SHA, verify_loaded_tar,
)


class LoadedImageIdentityTests(unittest.TestCase):
    def setUp(self):
        self.tag = "hermes-brc-relay-eval:b22ee6c64019"
        self.layers = ["sha256:" + "e" * 64]
        self.config = {
            "User": "65534:65534",
            "Cmd": ["node", "packages/relay/dist/cli.js"],
            "Env": ["NODE_ENV=production"],
            "WorkingDir": "/app",
            "Labels": {
                "org.opencontainers.image.revision": UPSTREAM_SHA,
                "org.opencontainers.image.licenses": "MIT",
            },
        }
        self.image_config = {
            "os": "linux", "architecture": "amd64", "config": self.config,
            "rootfs": {"type": "layers", "diff_ids": self.layers},
        }
        config_raw = json.dumps(self.image_config, sort_keys=True).encode()
        self.config_id = "sha256:" + hashlib.sha256(config_raw).hexdigest()
        oci_manifest = {
            "schemaVersion": 2,
            "mediaType": OCI_MANIFEST,
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                       "digest": self.config_id, "size": len(config_raw)},
            "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar",
                        "digest": self.layers[0], "size": 123}],
        }
        manifest_raw = json.dumps(oci_manifest, sort_keys=True).encode()
        self.manifest_id = "sha256:" + hashlib.sha256(manifest_raw).hexdigest()
        index_raw = json.dumps({
            "schemaVersion": 2, "manifests": [
                {"mediaType": OCI_MANIFEST, "digest": self.manifest_id,
                 "size": len(manifest_raw)},
            ],
        }).encode()
        docker_manifest_raw = json.dumps([
            {"Config": "blobs/sha256/" + self.config_id[7:],
             "RepoTags": [self.tag], "Layers": []},
        ]).encode()
        self.tar_entries = {
            "blobs/sha256/" + self.config_id[7:]: config_raw,
            "blobs/sha256/" + self.manifest_id[7:]: manifest_raw,
            "index.json": index_raw,
            "manifest.json": docker_manifest_raw,
        }
        self.inspect = {
            "Id": self.manifest_id, "Os": "linux", "Architecture": "amd64",
            "RepoTags": [self.tag], "Config": self.config,
            "RootFS": {"Layers": self.layers},
            "Descriptor": {"digest": self.manifest_id, "mediaType": OCI_MANIFEST},
        }

    def archive(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            for name, raw in self.tar_entries.items():
                item = tarfile.TarInfo(name)
                item.size = len(raw)
                tf.addfile(item, io.BytesIO(raw))
        buf.seek(0)
        return buf

    def verify(self):
        return verify_loaded_tar(self.archive(), self.inspect, self.config_id, self.tag)

    def test_containerd_manifest_digest_is_valid(self):
        self.assertEqual(
            self.verify(), (self.manifest_id, "containerd_manifest")
        )

    def test_classic_config_digest_is_valid(self):
        self.inspect["Id"] = self.config_id
        self.inspect.pop("Descriptor")
        self.assertEqual(self.verify(), (self.config_id, "classic_config"))

    def test_reject_unrelated_imported_image(self):
        self.inspect["Id"] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(LoadedImageDenied, "unrecognized_imported_image_id"):
            self.verify()

    def test_reject_containerd_descriptor_tampering(self):
        self.inspect["Descriptor"]["digest"] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(LoadedImageDenied, "containerd_descriptor_mismatch"):
            self.verify()

    def test_reject_changed_rootfs_even_with_expected_descriptor(self):
        self.inspect["RootFS"]["Layers"] = ["sha256:" + "c" * 64]
        with self.assertRaisesRegex(LoadedImageDenied, "imported_rootfs_layers_mismatch"):
            self.verify()

    def test_reject_changed_runtime_config(self):
        self.inspect["Config"] = {**self.config, "User": "0:0"}
        with self.assertRaisesRegex(LoadedImageDenied, "imported_config_mismatch_User"):
            self.verify()

    def test_reject_wrong_archive_config_reference(self):
        self.config_id = "sha256:" + "d" * 64
        with self.assertRaisesRegex(LoadedImageDenied, "unexpected_oci_config_reference"):
            self.verify()

    def test_reject_corrupt_manifest_blob(self):
        self.tar_entries["blobs/sha256/" + self.manifest_id[7:]] += b" "
        with self.assertRaisesRegex(LoadedImageDenied, "oci_blob_digest_mismatch"):
            self.verify()

    def test_reject_different_repository_tag(self):
        self.inspect["RepoTags"] = ["unrelated:latest"]
        with self.assertRaisesRegex(LoadedImageDenied, "wrong_imported_tag"):
            self.verify()

    def test_reject_missing_index(self):
        self.tar_entries.pop("index.json")
        with self.assertRaises(KeyError):
            self.verify()


if __name__ == "__main__":
    unittest.main()
