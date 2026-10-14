"""Hermes-only bridge and Cloudflare CONNECT allowlisting."""

from __future__ import annotations

import unittest
from pathlib import Path

from scripts.cloudflare_connect_proxy import permitted_connect

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

    def test_agent_uses_only_private_proxy(self) -> None:
        script = (ROOT / "scripts/agent_turn_probe.py").read_text()
        for required in ("--network hermes-agent-isolated", "--ip 172.29.250.2",
                         "--read-only", "--cap-drop ALL", "--memory", "\"640m\"", "--cpus", "\"0.30\"",
                         "--env-file", "HTTPS_PROXY=http://172.29.250.1:18573",
                         "\"-z\"", "\"-t\"", "todo"):
            self.assertIn(required, script)
        for forbidden in ("--network host", "--privileged", "docker.sock", "second-brain-vault"):
            self.assertNotIn(forbidden, script)


if __name__ == "__main__":
    unittest.main()
