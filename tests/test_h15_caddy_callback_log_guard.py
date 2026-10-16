"""Caddy callback log hardening must never weaken Basic Auth or proxy."""
import unittest

from scripts.h15_caddy_callback_log_guard import render, CaddyGuardError

FIXTURE = """# synthetic, not production secrets
https://hermes.mikemoore.top:8444 {
    tls /etc/caddy/certs/hermes.mikemoore.top.pem /etc/caddy/certs/hermes.mikemoore.top.key
    basic_auth {
        hermes SYNTHETIC_TEST_BCRYPT_HASH
    }
    reverse_proxy 127.0.0.1:9133 {
        header_up Host hermes.mikemoore.top
    }
}
http://hermes.mikemoore.top {
    redir https://hermes.mikemoore.top{uri} 308
}
"""


class CaddyCallbackTests(unittest.TestCase):
    def test_hardening_both_http_and_https(self):
        out=render(FIXTURE)
        self.assertEqual(out.count("    log_skip /auth/github/callback*"),2)
        self.assertIn("    basic_auth {",out)
        self.assertIn("    reverse_proxy 127.0.0.1:9133 {",out)
        self.assertIn("https://hermes.mikemoore.top{uri} 308",out)
        # No global skip, no wildcards broader than callback path.
        self.assertNotIn("    log_skip\n",out)
        self.assertNotIn("log_skip /auth/*",out)

    def test_invalid_or_already_modified_config_denied(self):
        for bad in (
            FIXTURE.replace("    basic_auth {","    # removed_basic_auth {"),
            FIXTURE.replace("127.0.0.1:9133","127.0.0.1:9999"),
            FIXTURE.replace("http://hermes.mikemoore.top {",""),
            FIXTURE.replace("https://hermes.mikemoore.top:8444 {",""),
            FIXTURE.replace("    basic_auth {","    log_skip /auth/github/callback*\n    basic_auth {"),
            FIXTURE + FIXTURE,
        ):
            with self.subTest(length=len(bad)), self.assertRaises(CaddyGuardError):
                render(bad)

    def test_no_second_install_or_secret_transformation(self):
        rendered=render(FIXTURE)
        with self.assertRaises(CaddyGuardError):
            render(rendered)
        self.assertEqual(rendered.count("SYNTHETIC_TEST_BCRYPT_HASH"),1)


if __name__=="__main__":
    unittest.main()
