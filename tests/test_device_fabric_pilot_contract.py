"""Contract and offline owner-preparation checks for approved #297 loopback pilot."""
from pathlib import Path
import asyncio
import os
import shutil
import subprocess
import tempfile
import unittest

from device_fabric.owner_smoke import provision
from device_fabric.presence import DeviceRegistry
from device_fabric.service import run

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deploy" / "h15-device-fabric-pilot-setup.sh"
UNIT = ROOT / "deploy" / "hermes-device-fabric-pilot.service.in"


class FabricPilotContractTests(unittest.TestCase):
    def test_setup_syntax_and_modes(self):
        if not shutil.which("bash"):
            self.skipTest("bash unavailable")
        subprocess.run(["bash", "-n", str(SCRIPT)], check=True)
        script = SCRIPT.read_text(encoding="utf-8")
        for fragment in (
            "prepare|enable|smoke|status|rollback",
            'PILOT_SERVICE_NOT_STARTED_BY_PREPARE=YES',
            'systemctl enable --now "$UNIT"',
            'systemctl disable --now "$UNIT"',
            'REMOTE_COMMAND_EXECUTION=NOT_IMPLEMENTED',
            'hermes-device-fabric',
            'websockets==16.0',
            '127.0.0.1:',
            'PILOT_PORT_IN_USE',
            'systemd-analyze verify',
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, script)
        self.assertNotIn("hermes-h01-ops-agent.service", script)
        self.assertNotIn("hermes-desktop-commander.service", script)
        self.assertNotIn("ssh ", script)
        self.assertNotIn("curl ", script)
        self.assertNotIn("chmod 0777", script)

    def test_service_is_loopback_and_non_privileged(self):
        unit = UNIT.read_text(encoding="utf-8")
        for fragment in (
            "User=hermes-device-fabric",
            "Group=hermes-device-fabric",
            "WorkingDirectory=@SOURCE@",
            "--port 38177",
            "NoNewPrivileges=true",
            "ProtectSystem=strict",
            "ProtectHome=true",
            "IPAddressDeny=any",
            "IPAddressAllow=localhost",
            "MemoryMax=192M",
            "CPUQuota=25%",
            "CapabilityBoundingSet=",
            "StartLimitIntervalSec=60s",
            "StartLimitBurst=3",
            "WantedBy=multi-user.target",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, unit)
        self.assertNotIn("0.0.0.0", unit)
        self.assertNotIn("ExecStartPre=", unit)
        self.assertNotIn("User=root", unit)

    def test_manual_identity_provision_idempotent_and_no_token_logging(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            registry = DeviceRegistry(root / "devices.sqlite3")
            token_file = root / "secret_token"
            provision(registry, token_file)
            token = token_file.read_text().strip()
            self.assertGreaterEqual(len(token), 40)
            self.assertEqual(token_file.stat().st_mode & 0o777, 0o600)
            self.assertTrue(registry.authenticated("pilot-sim", token))
            self.assertNotIn(token, str(registry.list_devices()))
            provision(registry, token_file)
            self.assertEqual(token_file.read_text().strip(), token)
            token_file.write_text("invalid")
            with self.assertRaises(ValueError):
                provision(registry, token_file)

    def test_service_entry_refuses_unprepared_and_bad_port(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for port in (0, 1023, 65536):
                with self.subTest(port=port), self.assertRaises(ValueError):
                    asyncio.run(run(database=root / "none.db", cert=root / "none.crt",
                                    key=root / "none.key", port=port))
            with self.assertRaises(ValueError):
                asyncio.run(run(database=root / "none.db", cert=root / "none.crt",
                                key=root / "none.key", port=38177))


if __name__ == "__main__":
    unittest.main()
