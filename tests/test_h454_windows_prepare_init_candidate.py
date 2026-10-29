"""H454 no-network owner-Windows candidate preparer regression tests.

Synthetic Docker inspect only. No real Docker, credential, or Windows access.
"""
from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import h454_windows_prepare_init_candidate as prep  # noqa: E402
from test_h454_windows_candidate_contract import pair  # noqa: E402


def samples():
    old, candidate = pair()
    old["Config"]["Cmd"] = None
    old["HostConfig"]["NanoCpus"] = 1_000_000_000
    old["Mounts"][0]["Source"] = str(Path.home() / "Hermes-H15-Test")
    old["Config"]["Labels"] = {
        "com.hermes.source.toolkit": "pinned-demo",
        "com.hermes.scope": prep.SCOPE,
    }
    image = {
        "Id": prep.IMAGE_ID,
        "Config": {
            "Env": old["Config"]["Env"].copy(),
            "Entrypoint": old["Config"]["Entrypoint"].copy(),
            "Cmd": None,
            "Labels": {
                "com.hermes.source.toolkit": "pinned-demo",
                "com.hermes.scope": "h15-windows-owner-sandbox",
            },
        },
    }
    return old, image


class TestCandidatePreparer(unittest.TestCase):
    def valid(self, original=None, image=None):
        orig, img = samples()
        if original is not None:
            orig = original
        if image is not None:
            img = image
        with patch.object(Path, "is_dir", return_value=True):
            return prep.check_original(orig, img)

    def hold(self, expected, mutate):
        orig, img = samples()
        mutate(orig, img)
        with patch.object(Path, "is_dir", return_value=True):
            with self.assertRaises(prep.ContractHold) as exc:
                prep.check_original(orig, img)
        self.assertEqual(str(exc.exception), expected)

    def test_valid_pinned_source(self):
        source = self.valid()
        self.assertTrue(source.endswith("Hermes-H15-Test"))

    def test_missing_tmpfs(self):
        self.hold("TMPFS", lambda orig, img: orig["HostConfig"]["Tmpfs"].pop("/tmp"))

    def test_tmpfs_weak_mode(self):
        self.hold("TMPFS", lambda orig, img: orig["HostConfig"]["Tmpfs"].__setitem__("/run/brc", "rw,size=8m"))

    def test_no_entrypoint_change(self):
        self.hold("ENTRYPOINT", lambda orig, img: orig["Config"].__setitem__("Entrypoint", ["/bin/sh", "/evil"]))

    def test_no_credential_env_override(self):
        self.hold("ENV_NOT_IMAGE_DEFAULT", lambda orig, img: orig["Config"]["Env"].append("TOKEN=sensitive"))

    def test_no_label_change(self):
        self.hold("LABELS_NOT_IMAGE_DEFAULT", lambda orig, img: orig["Config"]["Labels"].__setitem__("sensitive", "1"))

    def test_wrong_workspace_source(self):
        self.hold("BIND_SOURCE_NOT_OWNER_WORKSPACE", lambda orig, img: orig["Mounts"][0].__setitem__("Source", "/tmp/other"))

    def test_docker_desktop_wsl_mount_translation(self):
        orig, img = samples()
        orig["Mounts"][0]["Source"] = "/run/desktop/mnt/host/c/Users/Mike/Hermes-H15-Test"
        with patch.object(Path, "home", return_value=Path("C:/Users/Mike")), patch.object(Path, "is_dir", return_value=True):
            src = prep.check_original(orig, img)
        self.assertEqual(src, "C:/Users/Mike/Hermes-H15-Test")

    def test_docker_desktop_legacy_mount_translation(self):
        orig, img = samples()
        orig["Mounts"][0]["Source"] = "/host_mnt/c/Users/Mike/Hermes-H15-Test"
        with patch.object(Path, "home", return_value=Path("C:/Users/Mike")), patch.object(Path, "is_dir", return_value=True):
            src = prep.check_original(orig, img)
        self.assertEqual(src, "C:/Users/Mike/Hermes-H15-Test")

    def test_unknown_translated_mount_denied(self):
        orig, img = samples()
        orig["Mounts"][0]["Source"] = "/run/desktop/mnt/host/d/Users/Mike/Hermes-H15-Test"
        with patch.object(Path, "home", return_value=Path("C:/Users/Mike")), patch.object(Path, "is_dir", return_value=True):
            with self.assertRaises(prep.ContractHold) as exc:
                prep.check_original(orig, img)
        self.assertEqual(str(exc.exception), "BIND_SOURCE_NOT_OWNER_WORKSPACE")

    def test_wrong_cpu_limit(self):
        self.hold("CPU_LIMIT", lambda orig, img: orig["HostConfig"].__setitem__("NanoCpus", 0))

    def test_wrong_pid_limit(self):
        self.hold("LIMITS", lambda orig, img: orig["HostConfig"].__setitem__("PidsLimit", 96))

    def test_wrong_security(self):
        self.hold("SECURITY_OPTS", lambda orig, img: orig["HostConfig"].__setitem__("SecurityOpt", []))

    def test_unsafe_orig_privileged(self):
        self.hold("ISOLATION", lambda orig, img: orig["HostConfig"].__setitem__("Privileged", True))

    def test_disallow_original_replacement(self):
        self.hold("ORIGINAL_NOT_RUNNING", lambda orig, img: orig["State"].__setitem__("Running", False))

    def test_image_pin(self):
        self.hold("IMAGE_IDENTITY", lambda orig, img: img.__setitem__("Id", "sha256:" + "0" * 64))

    def test_mount_source_is_symlink(self):
        orig, img = samples()
        with patch.object(Path, "is_dir", return_value=True):
            with patch.object(Path, "is_symlink", return_value=True):
                with self.assertRaises(prep.ContractHold) as exc:
                    prep.check_original(orig, img)
        self.assertEqual(str(exc.exception), "BIND_SOURCE_NOT_DIRECTORY")

    def test_create_command_includes_both_tmpfs_and_init(self):
        args = prep.build_create_args("C:\\Synthetic\\Hermes-H15-Test")
        self.assertEqual(args[:2], ["container", "create"])
        self.assertEqual(args.count("--init"), 1)
        self.assertEqual(args.count("--tmpfs"), 2)
        self.assertEqual(args.count("--mount"), 1)
        self.assertEqual(args[-1], prep.IMAGE_ID)
        self.assertIn("--read-only", args)
        self.assertNotIn("--privileged", args)
        self.assertNotIn("--env", args)
        self.assertNotIn("--env-file", args)
        self.assertNotIn("--rm", args)
        self.assertNotIn("run", args)
        self.assertNotIn("start", args)

    def test_create_command_has_unique_pinned_target(self):
        args = prep.build_create_args("C:\\Synthetic\\Hermes-H15-Test")
        self.assertEqual(args[args.index("--name") + 1], prep.CANDIDATE)
        self.assertEqual(args[args.index("--pids-limit") + 1], "128")
        self.assertEqual(args[args.index("--user") + 1], "65534:65534")
        self.assertEqual(args[args.index("--network") + 1], "bridge")

    def test_no_cred_stage_or_ssh_in_candidate(self):
        args = prep.build_create_args("C:\\Synthetic\\Hermes-H15-Test")
        self.assertFalse(any("ssh" in value.lower() for value in args))
        self.assertFalse(any("device.json" in value.lower() for value in args))
        self.assertFalse(any("brc_dev_" in value.lower() for value in args))


if __name__ == "__main__":
    unittest.main()
