"""H-15 observed OCI OS-package SBOM. Offline negative tests."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts.h15_brc_os_inventory import OsInventoryDenied, UPSTREAM_SHA, inventory

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/h15_brc_os_inventory.py"
WORKFLOW = ROOT / ".github/workflows/h15-remote-commander-candidate.yml"


def fixture(count=40):
    raw = "".join(
        f"lib{i}\t1:2.3.4-1+deb12u2\tamd64\n" for i in range(count)
    ).encode()
    image = json.dumps([{
        "Id": "sha256:" + "c" * 64,
        "Os": "linux",
        "Architecture": "amd64",
        "Config": {
            "User": "65534:65534",
            "Labels": {
                "org.opencontainers.image.revision": UPSTREAM_SHA,
            },
        },
    }]).encode()
    return raw, image


class OsInventoryTests(unittest.TestCase):
    def test_realistic_dpkg_rows_generate_deterministic_cyclonedx(self):
        raw, image = fixture()
        first = inventory(raw, image)
        second = inventory(raw, image)
        self.assertEqual(first, second)
        self.assertEqual(first["bomFormat"], "CycloneDX")
        self.assertEqual(first["specVersion"], "1.5")
        self.assertEqual(len(first["components"]), 40)
        self.assertEqual(first["metadata"]["component"]["version"], "sha256:" + "c" * 64)
        self.assertEqual(len({x["bom-ref"] for x in first["components"]}), 40)
        self.assertIn("arch=amd64", first["components"][0]["purl"])
        self.assertNotIn("vulnerabilities", first)

    def test_bad_or_malicious_dpkg_rows_fail_closed(self):
        cases = [
            b"",
            b"bad\tversion\n",
            b"two\tv\tamd64\textra\n" * 40,
            b"x\tv\tamd64\n" * 40,
            b"foo\tver sion\tamd64\n" * 40,
            b"../etc\t1\tamd64\n" * 40,
            b"\xff" * 200,
            b"x\t1\tamd64\n",
        ]
        _, image = fixture()
        for case in cases:
            with self.subTest(case=case[:15]):
                with self.assertRaises(OsInventoryDenied):
                    inventory(case, image)

    def test_changed_id_platform_user_or_source_refused(self):
        raw, image = fixture()
        orig = json.loads(image)
        cases = [
            ("Id", "latest"),
            ("Os", "windows"),
            ("Architecture", "arm64"),
        ]
        for key, value in cases:
            with self.subTest(key=key):
                modified = json.loads(image)
                modified[0][key] = value
                with self.assertRaises(OsInventoryDenied):
                    inventory(raw, json.dumps(modified).encode())
        for key, value in [("User", "0:0"), ("Labels", {"org.opencontainers.image.revision": "0" * 40})]:
            modified = json.loads(image)
            modified[0]["Config"][key] = value
            with self.subTest(key=key):
                with self.assertRaises(OsInventoryDenied):
                    inventory(raw, json.dumps(modified).encode())
        with self.assertRaises(OsInventoryDenied):
            inventory(raw, b"{}")

    def test_cli_writes_exact_once_without_overwrite(self):
        raw, image = fixture()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            dpkg = root / "dpkg.tsv"
            docker = root / "inspect.json"
            out = root / "sbom.json"
            dpkg.write_bytes(raw)
            docker.write_bytes(image)
            cmd = ["python3", str(SCRIPT), "--dpkg-list", str(dpkg),
                   "--docker-inspect", str(docker), "--output", str(out)]
            first = subprocess.run(cmd, text=True, capture_output=True)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertIn("H15_OS_INVENTORY=PASS", first.stdout)
            self.assertIn("H15_OS_RELEASE_APPROVED=NO", first.stdout)
            original = out.read_bytes()
            second = subprocess.run(cmd, text=True, capture_output=True)
            self.assertEqual(second.returncode, 2)
            self.assertEqual(out.read_bytes(), original)

    def test_workflow_has_no_live_device_or_public_port_for_uid_smoke(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        start = workflow.index("      - name: Verify dedicated owner UID/GID image runtime")
        end = workflow.index("      - name:", start + 14)
        smoke = workflow[start:end]
        for required in (
            "--network none", "--read-only", "--user 979:975",
            "--cap-drop ALL", "--security-opt no-new-privileges",
            "--tmpfs /state:", "H15_BRC_UID_979_975=PASS",
        ):
            self.assertIn(required, smoke)
        for forbidden in ("--publish", "-p 3000", "/var/lib/hermes-brc-relay",
                          "/var/run/docker.sock", "--network host", "--privileged"):
            self.assertNotIn(forbidden, smoke)
        self.assertIn("h15_brc_os_inventory.py", workflow)
        self.assertIn("H15_OS_VULNERABILITY_SCAN=NOT_PERFORMED", workflow)
        self.assertIn("os-packages.cdx.json", workflow)


if __name__ == "__main__":
    unittest.main()
