"""Hermes-only bridge and Cloudflare CONNECT allowlisting."""

from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.cloudflare_connect_proxy import permitted_connect
from scripts.agent_turn_probe import docker_args

ROOT = Path(__file__).resolve().parents[1]


class CloudflareIsolationTests(unittest.TestCase):
    def test_connect_authority_is_exact(self) -> None:
        self.assertTrue(permitted_connect(b"CONNECT api.cloudflare.com:443 HTTP/1.1", "172.29.250.2"))
        for line, addr in (
            (b"CONNECT example.com:443 HTTP/1.1", "172.29.250.2"),
            (b"CONNECT 169.254.169.254:80 HTTP/1.1", "172.29.250.2"),
            (b"CONNECT api.cloudflare.com:443 HTTP/1.1", "172.29.250.3"),
            (b"GET http://api.cloudflare.com HTTP/1.1", "172.29.250.2"),
        ):
            with self.subTest(line=line, addr=addr):
                self.assertFalse(permitted_connect(line, addr))

    def test_dedicated_network_and_drop_rules(self) -> None:
        script = (ROOT / "deploy/setup-cloudflare-egress.sh").read_text()
        self.assertIn("--internal", script)
        self.assertIn('iifname "br-hcf-agent" drop', script)
        self.assertIn("tcp dport 18573 accept", script)
        self.assertNotIn("flush ruleset", script)
        self.assertNotIn("hermes_egress", script)

    @patch("scripts.agent_turn_probe.pwd.getpwnam")
    def test_agent_uses_only_private_proxy(self, account) -> None:
        account.return_value.pw_uid = 988
        account.return_value.pw_gid = 981
        args = docker_args()

        expected = {
            "--network": "hermes-agent-isolated",
            "--ip": "172.29.250.2",
            "--cpus": "0.30",
            "--memory": "640m",
            "--env-file": "/var/lib/hermes-agent/.env",
        }
        for name, value in expected.items():
            with self.subTest(argument=name):
                self.assertIn(name, args)
                self.assertEqual(args[args.index(name) + 1], value)
        self.assertIn("-z", args)
        self.assertIn("todo", args)
        self.assertIn("no-new-privileges", args)
        for forbidden in ("host", "--privileged", "docker.sock", "second-brain-vault"):
            self.assertNotIn(forbidden, args)


if __name__ == "__main__":
    unittest.main()
