"""Проверки безопасного локального ввода Cloudflare Workers Free без токенов."""

from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class CloudflareCredentialsScriptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script = (ROOT / "deploy/set-cloudflare-free-credentials.sh").read_text(encoding="utf-8")

    def test_requires_real_terminal_and_hidden_token_input(self) -> None:
        self.assertIn("-t 0", self.script)
        self.assertIn("-t 1", self.script)
        self.assertIn("read -r -s -p", self.script)

    def test_refuses_overwrites_and_uses_atomic_creation(self) -> None:
        self.assertIn('if [ -e "$STATE/.env" ]', self.script)
        self.assertIn('ln -T "$tmp" "$STATE/.env"', self.script)
        self.assertIn("chmod 0600", self.script)
        self.assertIn("hermes-agent", self.script)
        self.assertIn("umask 077", self.script)

    def test_requires_explicit_free_plan_confirmation(self) -> None:
        self.assertIn("Workers Free", self.script)
        self.assertIn('if [ "$confirmation" != FREE ]', self.script)

    def test_no_automatic_side_effects_or_secrets_in_logs(self) -> None:
        for forbidden in ("systemctl ", "docker run", "curl ", "wget ", "echo $token", "set -x", "gh api", "/etc/hermes", "docker.sock"):
            with self.subTest(fragment=forbidden):
                self.assertNotIn(forbidden, self.script)

    def test_cloudflare_endpoint_is_the_official_account_scoped_url(self) -> None:
        self.assertIn("https://api.cloudflare.com/client/v4/accounts/%s/ai/v1", self.script)
        self.assertIn("CLOUDFLARE_WORKERS_AI_API_TOKEN", self.script)
        self.assertIn("CLOUDFLARE_WORKERS_AI_BASE_URL", self.script)


if __name__ == "__main__":
    unittest.main()
