"""No-network contract checks for owner-paired Windows/Linux presence devices (#276)."""
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from device_fabric.device_agent import InvalidAgentConfig, load_config
from device_fabric.owner_enrollment import enroll
from device_fabric.presence import DeviceRegistry
from device_fabric.ssh_tunnel import ssh_arguments


class RealDeviceOnboardingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.db = DeviceRegistry(self.folder / "private" / "devices.sqlite3")
        self.db.initialize()
        self.ca = self.folder / "test_cert.pem"
        if not shutil.which("openssl"):
            self.skipTest("openssl unavailable; WSS CI has real TLS coverage")
        key = self.folder / "ephemeral_key.pem"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-days", "1", "-subj", "/CN=localhost",
             "-addext", "subjectAltName=DNS:localhost",
             "-keyout", str(key), "-out", str(self.ca)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def bundle(self, identity="windows-pc", port=38178):
        return enroll(self.db, identity, f"Simulated {identity}", self.ca,
                      self.folder / "private" / "export", port)

    def test_owner_enroll_two_independent_devices_and_revoke(self):
        first = self.bundle()
        second = self.bundle("linux-vps", port=38179)
        self.assertEqual(first.stat().st_mode & 0o777, 0o600)
        self.assertEqual(second.stat().st_mode & 0o777, 0o600)
        self.assertEqual(first.parent.stat().st_mode & 0o777, 0o700)
        c1, c2 = load_config(first), load_config(second)
        self.assertNotEqual(c1["token"], c2["token"])
        self.assertEqual(c1["endpoint"], "wss://localhost:38178")
        self.assertEqual(c2["endpoint"], "wss://localhost:38179")
        self.assertTrue(self.db.authenticated("windows-pc", c1["token"]))
        self.assertFalse(self.db.authenticated("linux-vps", c1["token"]))
        self.assertEqual({d["status"] for d in self.db.list_devices()}, {"offline"})
        self.db.revoke("windows-pc")
        self.assertFalse(self.db.authenticated("windows-pc", c1["token"]))
        self.assertTrue(self.db.authenticated("linux-vps", c2["token"]))
        self.assertEqual(self.db.get_device_status("windows-pc")["status"], "revoked")
        self.assertNotIn(c1["token"], str(self.db.list_devices()))

    def test_bundle_created_only_once_and_no_stdout_secret(self):
        with contextlib.redirect_stdout(io.StringIO()) as capture:
            bundle = self.bundle()
        self.assertEqual(capture.getvalue(), "")
        with self.assertRaises(ValueError):
            self.bundle()
        self.assertEqual(bundle.stat().st_mode & 0o777, 0o600)

    def test_config_rejects_external_endpoint_and_insecure_permissions(self):
        bundle = self.bundle()
        data = json.loads(bundle.read_text())
        data["endpoint"] = "wss://public.example:443"
        bundle.write_text(json.dumps(data))
        bundle.chmod(0o600)
        with self.assertRaises(InvalidAgentConfig):
            load_config(bundle)
        data["endpoint"] = "ws://localhost:38178"
        bundle.write_text(json.dumps(data))
        with self.assertRaises(InvalidAgentConfig):
            load_config(bundle)
        data["endpoint"] = "wss://localhost:38178"
        data["server_ca_pem"] = "invalid"
        bundle.write_text(json.dumps(data))
        with self.assertRaises(InvalidAgentConfig):
            load_config(bundle)
        data["server_ca_pem"] = self.ca.read_text()
        data["unexpected_execution_tool"] = "start_process"
        bundle.write_text(json.dumps(data))
        with self.assertRaises(InvalidAgentConfig):
            load_config(bundle)
        data.pop("unexpected_execution_tool")
        bundle.write_text(json.dumps(data))
        bundle.chmod(0o644)
        if os.name != "nt":
            with self.assertRaises(InvalidAgentConfig):
                load_config(bundle)
        bundle.chmod(0o600)
        self.assertEqual(load_config(bundle)["device_id"], "windows-pc")

    def test_symlink_and_path_traversal_fail_closed(self):
        with self.assertRaises(ValueError):
            self.bundle("../escape")
        real = self.bundle()
        link = self.folder / "follow-me.json"
        link.symlink_to(real)
        with self.assertRaises(InvalidAgentConfig):
            load_config(link)
        with self.assertRaises(ValueError):
            enroll(self.db, "another", "Another", self.ca,
                   self.folder / "private" / "export", 8080)

    def test_ssh_tunnel_only_local_forward_and_strict_host_identity(self):
        if not shutil.which("ssh"):
            self.skipTest("OpenSSH client unavailable")
        key, known = self.folder / "key", self.folder / "known_hosts"
        key.write_text("mock-key")
        known.write_text("mock-knownhost")
        args = ssh_arguments(remote_host="hermes.example", remote_user="device-tunnel",
                             ssh_key=key, known_hosts=known, local_port=38178)
        self.assertEqual(args[0], "ssh")
        self.assertEqual(args[-1], "device-tunnel@hermes.example")
        self.assertIn("-N", args)
        self.assertIn("-T", args)
        self.assertIn("StrictHostKeyChecking=yes", args)
        self.assertIn("BatchMode=yes", args)
        self.assertIn("ForwardAgent=no", args)
        self.assertIn("127.0.0.1:38178:127.0.0.1:38177", args)
        self.assertIn("25566", args)
        self.assertNotIn("-R", args)
        for host in ("-oBad", "a;echo secret", ""):
            with self.assertRaises(ValueError):
                ssh_arguments(remote_host=host, remote_user="device-tunnel",
                              ssh_key=key, known_hosts=known, local_port=38178)
        with self.assertRaises(ValueError):
            ssh_arguments(remote_host="hermes.example", remote_user="../root",
                          ssh_key=key, known_hosts=known, local_port=38178)


if __name__ == "__main__":
    unittest.main()
