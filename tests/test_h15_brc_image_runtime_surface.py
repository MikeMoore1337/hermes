"""H-15: negative tests for actual isolated OCI reachability observation."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts.h15_brc_image_runtime_surface import review

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/h15_brc_image_runtime_surface.py"
WORKFLOW = ROOT / ".github/workflows/h15-remote-commander-candidate.yml"
NODE_SOURCE = ROOT / "scripts/h15_brc_image_runtime_surface.cjs"


def fixture():
    binary_names = ("mount", "umount", "nsenter", "unshare", "fdisk", "sfdisk",
                    "infocmp", "gzip", "perl", "setfacl", "getfacl")
    probe = {
        "schema": "hermes-h15-oci-runtime-surface-v1",
        "uid": 65534, "gid": 65534,
        "cap_eff_hex": "0000000000000000", "cap_bnd_hex": "0000000000000000",
        "no_new_privs": 1, "seccomp_mode": 2, "root_write_denied": True,
        "block_devices": [], "observed_binaries": {key: False for key in binary_names},
        "observed_systemd_homed_binary": False,
        "observed_perl_archive_tar_module": False,
        "scope_limit": "BINARY_PRESENCE_ONLY_NOT_EXPLOITABILITY",
        "release_approved": False,
    }
    inspect = {
        "Image": "sha256:" + "a" * 64,
        "HostConfig": {
            "NetworkMode": "none", "ReadonlyRootfs": True,
            "Privileged": False, "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges"],
            "Binds": None, "Mounts": None, "Devices": None, "PortBindings": {},
        },
        "Config": {"User": "65534:65534"},
        "State": {"ExitCode": 0},
    }
    return probe, inspect


class RuntimeApplicabilityTests(unittest.TestCase):
    def test_disposable_probe_never_proclaims_reachability_or_release(self):
        probe, inspect = fixture()
        r = review(probe, inspect)
        self.assertEqual(r["kernel_isolation"], "CI_PASS")
        self.assertEqual(r["observed_binaries"]["mount"], False)
        self.assertFalse(r["exploitability_assessed"])
        self.assertFalse(r["release_approved"])
        self.assertFalse(r["public_mcp_enabled"])
        self.assertFalse(r["device_commands_enabled"])

    def test_kernel_or_privileged_config_changes_fail_closed(self):
        for key, value in (
            ("uid", 0), ("gid", 0), ("cap_eff_hex", "0000000000000001"),
            ("cap_bnd_hex", "0000000000000001"), ("no_new_privs", 0),
            ("seccomp_mode", 0), ("root_write_denied", False),
            ("block_devices", ["loop0"]), ("release_approved", True),
            ("scope_limit", "RELEASE_ALLOWED"),
        ):
            probe, inspect = fixture()
            probe[key] = value
            with self.subTest(field=key), self.assertRaises(ValueError):
                review(probe, inspect)
        for key, value in (
            ("NetworkMode", "host"), ("ReadonlyRootfs", False),
            ("Privileged", True), ("CapDrop", []), ("SecurityOpt", []),
            ("Binds", ["/etc:/etc"]), ("Devices", [{"PathOnHost": "/dev/sda"}]),
            ("PortBindings", {"3000/tcp": [{"HostPort": "3000"}]}),
            ("PidMode", "host"), ("CgroupnsMode", "host"),
        ):
            probe, inspect = fixture()
            inspect["HostConfig"][key] = value
            with self.subTest(field=key), self.assertRaises(ValueError):
                review(probe, inspect)

    def test_non_boolean_or_incomplete_binary_inventory_denied(self):
        probe, inspect = fixture()
        probe["observed_binaries"]["mount"] = "false"
        with self.assertRaises(ValueError):
            review(probe, inspect)
        probe, inspect = fixture()
        del probe["observed_binaries"]["mount"]
        with self.assertRaises(ValueError):
            review(probe, inspect)

    def test_cli_no_overwrite_and_no_risky_path_diagnostics(self):
        probe, inspect = fixture()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            src = path / "sensitive-container-probe.json"
            cfg = path / "inspect.json"
            out = path / "review.json"
            src.write_text(json.dumps(probe))
            cfg.write_text(json.dumps([inspect]))
            cmd = ["python3", str(SCRIPT), "--probe", str(src),
                   "--inspect", str(cfg), "--out", str(out)]
            done = subprocess.run(cmd, text=True, capture_output=True)
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertIn("H15_RUNTIME_SCOPE=CI_ISOLATED_NO_RELEASE", done.stdout)
            original = out.read_bytes()
            again = subprocess.run(cmd, text=True, capture_output=True)
            self.assertEqual(again.returncode, 2)
            self.assertEqual(out.read_bytes(), original)
            self.assertNotIn("sensitive-container", done.stdout + done.stderr)

    def test_real_image_not_injected_with_instrumentation(self):
        workflow = WORKFLOW.read_text()
        anchor = workflow.index("      - name: Observe actual OCI kernel scope")
        tail = workflow.index("      - name: Inventory built OCI Debian packages", anchor)
        section = workflow[anchor:tail]
        for required in (
            "--network none", "--read-only", "--user 65534:65534",
            "--cap-drop ALL", "--security-opt no-new-privileges",
            "--entrypoint node", "docker start --attach --interactive",
            "scripts/h15_brc_image_runtime_surface.cjs",
            "runtime-surface.raw.json", "runtime-surface.json",
            "H15_RUNTIME_RELEASE_GO=NO",
        ):
            self.assertIn(required, section)
        for forbidden in ("--network host", "--privileged", "/var/run/docker.sock", "--publish"):
            self.assertNotIn(forbidden, section)
        self.assertIn("runtime-surface.json", WORKFLOW.read_text())
        self.assertTrue(NODE_SOURCE.exists())


if __name__ == "__main__":
    unittest.main()
