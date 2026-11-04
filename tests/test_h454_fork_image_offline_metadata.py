"""H-454 fork OCI image metadata precheck: offline, no Docker or owner state."""
from copy import deepcopy
import unittest

from scripts.h454_fork_image_offline_metadata import (
    ForkImageDenied, verify_fork_image_metadata,
)

SHA = "sha256:" + "a" * 64
COMMIT = "b" * 40
SOURCE = "https://github.com/MikeMoore1337/hermes-remote-commander"


def image():
    return {
        "Id": SHA, "Os": "linux", "Architecture": "amd64",
        "Config": {
            "Labels": {
                "org.opencontainers.image.source": SOURCE,
                "org.opencontainers.image.revision": COMMIT,
            },
            "User": "rdp", "Cmd": ["node", "dist/cli.js"], "WorkingDir": "/app",
            "Volumes": None, "ExposedPorts": {"3000/tcp": {}},
            "Env": ["NODE_VERSION=24.12.0", "NODE_ENV=production", "PORT=3000",
                    "HOST=0.0.0.0", "BRC_DB=/data/relay.sqlite"],
        },
    }


class ForkImageMetadataGate(unittest.TestCase):
    def verify(self, obj=None, *, expected_image=SHA, expected_source_commit=COMMIT):
        return verify_fork_image_metadata(
            image() if obj is None else obj, expected_image=expected_image,
            expected_source_commit=expected_source_commit,
        )

    def reject(self, obj, code, **pins):
        with self.assertRaisesRegex(ForkImageDenied, "^" + code + "$"):
            self.verify(obj, **pins)

    def test_good_fork_metadata_is_not_a_deployment_approval(self):
        result = self.verify()
        self.assertEqual(result["status"], "OFFLINE_IMAGE_METADATA_MATCH_ONLY")
        self.assertFalse(result["legacy_hermes_operator_compatible"])
        self.assertFalse(result["sqlite_migration_verified"])
        self.assertFalse(result["owner_production_cutover_authorized"])

    def test_refuses_untrusted_independent_pins(self):
        for pin in ("brc/relay:ci", "sha256:" + "f" * 63, "", None):
            with self.subTest(pin=pin):
                self.reject(image(), "UNTRUSTED_EXPECTED_IDENTITY", expected_image=pin)
        for pin in ("unverified", "b" * 39, "", None):
            with self.subTest(pin=pin):
                self.reject(image(), "UNTRUSTED_EXPECTED_IDENTITY",
                            expected_source_commit=pin)

    def test_wrong_image_id_platform_or_absent_record(self):
        for key, val in (("Id", "sha256:" + "c" * 64), ("Os", "windows"),
                         ("Architecture", "arm64")):
            obj = image()
            obj[key] = val
            with self.subTest(field=key):
                self.reject(obj, "FORK_IMAGE_ID_OR_PLATFORM_MISMATCH")
        self.reject(None, "FORK_IMAGE_ID_OR_PLATFORM_MISMATCH")

    def test_labels_must_match_the_fork_and_pinned_source(self):
        for key, val in (
            ("org.opencontainers.image.source", "https://github.com/upstream/example"),
            ("org.opencontainers.image.revision", "unverified"),
            ("org.opencontainers.image.revision", "c" * 40),
        ):
            obj = image()
            obj["Config"]["Labels"][key] = val
            with self.subTest(key=key, value=val):
                self.reject(obj, "FORK_SOURCE_LABEL_MISMATCH")
        obj = image()
        obj["Config"]["Labels"] = None
        self.reject(obj, "FORK_SOURCE_LABEL_MISMATCH")

    def test_refuses_root_old_entrypoint_wrong_workdir_and_hidden_volume(self):
        for key, val, expected in (
            ("User", "root", "FORK_IMAGE_RUNTIME_MISMATCH"),
            ("User", "65534:65534", "FORK_IMAGE_RUNTIME_MISMATCH"),
            ("Cmd", ["node", "packages/relay/dist/cli.js"], "FORK_IMAGE_RUNTIME_MISMATCH"),
            ("WorkingDir", "/state", "FORK_IMAGE_RUNTIME_MISMATCH"),
            ("Volumes", {"/data": {}}, "FORK_IMPLICIT_VOLUME_NOT_ALLOWED"),
            ("ExposedPorts", {"3000/tcp": {}, "22/tcp": {}}, "FORK_EXPOSED_PORT_MISMATCH"),
        ):
            obj = image()
            obj["Config"][key] = val
            with self.subTest(field=key, value=val):
                self.reject(obj, expected)

    def test_refuses_baked_secrets_duplicated_keys_and_malformed_env(self):
        for env, code in (
            (["BRC_SESSION_SECRET=test"], "FORK_ENV_FORBIDDEN_OR_DUPLICATED"),
            (["brc_admin_password=fake"], "FORK_ENV_FORBIDDEN_OR_DUPLICATED"),
            (["BRC_DB=/tmp/relay.sqlite"], "FORK_ENV_FORBIDDEN_OR_DUPLICATED"),
            (["MALFORMED"], "FORK_ENV_INVALID"),
            ([None], "FORK_ENV_INVALID"),
        ):
            obj = image()
            obj["Config"]["Env"].extend(env)
            with self.subTest(env=env):
                self.reject(obj, code)
        obj = image()
        obj["Config"]["Env"] = ["NODE_ENV=production"]
        self.reject(obj, "FORK_ENV_RUNTIME_MISMATCH")
        obj = image()
        obj["Config"]["Env"] = "PORT=3000"
        self.reject(obj, "FORK_ENV_INVALID")

    def test_missing_config_refused(self):
        obj = image()
        obj["Config"] = None
        self.reject(obj, "FORK_CONFIG_MISSING")


if __name__ == "__main__":
    unittest.main()
