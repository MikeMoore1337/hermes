"""Credential loader must fail closed and never interpret shell syntax."""
import os
from pathlib import Path
import tempfile
import unittest

from control_center.credentials import load_runtime_credentials
from control_center.auth import AuthConfig, AuthError, GitHubProvider, OAuthService
from control_center.oauth_broker import BrokerConfig

BROKER={
    "HERMES_OAUTH_CLIENT_ID":"Ov23abcdefghijk",
    "HERMES_OAUTH_CLIENT_SECRET":"random-very-long-test-client-secret",
    "HERMES_OAUTH_ALLOWED_GITHUB_ID":"42142321",
    "HERMES_OAUTH_SOCKET":"/run/hermes-oauth/broker.sock",
}
WEB={
    "HERMES_CC_AUTH_MODE":"github",
    "HERMES_CC_PUBLIC_ORIGIN":"https://hermes.mikemoore.top",
    "HERMES_CC_GITHUB_CLIENT_ID":"Ov23abcdefghijk",
    "HERMES_CC_ALLOWED_GITHUB_ID":"42142321",
    "HERMES_CC_SESSION_SECRET":"this-test-session-secret-is-long-enough",
    "HERMES_CC_OAUTH_BROKER_SOCKET":"/run/hermes-oauth/broker.sock",
}


class CredentialTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.folder=Path(self.temp.name)
    def tearDown(self):
        self.temp.cleanup()
    def emit(self,filename,values):
        (self.folder/filename).write_text("".join(f"{k}={v}\n" for k,v in values.items()),encoding="utf8")
    def read(self,name):
        return load_runtime_credentials(name,{"CREDENTIALS_DIRECTORY":str(self.folder)})

    def test_missing_systemd_directory_fails_safe_for_github(self):
        self.assertIsNone(load_runtime_credentials("web.env",{}))
        with self.assertRaises(ValueError):
            load_runtime_credentials("unknown.env",{})
        with self.assertRaises(ValueError):
            load_runtime_credentials("web.env",{"CREDENTIALS_DIRECTORY":"relative"})

    def test_secrets_separated_by_process(self):
        self.emit("web.env",WEB)
        self.emit("broker.env",BROKER)
        web=AuthConfig.from_env(self.read("web.env"))
        broker=BrokerConfig.from_env(self.read("broker.env"))
        self.assertEqual(web.client_secret,"")
        self.assertEqual(web.owner_id,broker.owner_id)
        self.assertEqual(web.client_id,broker.client_id)
        self.assertTrue(broker.client_secret)
        self.assertNotIn("HERMES_OAUTH_CLIENT_SECRET",self.read("web.env"))

    def test_direct_oauth_uses_both_separate_credentials(self):
        self.emit("web.env", WEB)
        self.emit("broker.env", BROKER)
        web = self.read("web.env")
        identity = self.read("broker.env")
        config = AuthConfig.from_direct_credentials(web, identity)
        self.assertTrue(config.client_secret)
        self.assertEqual(config.owner_id, 42142321)
        self.assertIsInstance(OAuthService(config).provider, GitHubProvider)
        self.assertNotIn("HERMES_OAUTH_CLIENT_SECRET", web)

    def test_direct_oauth_rejects_mismatch_and_missing_secret(self):
        for changed in (
            {**BROKER, "HERMES_OAUTH_CLIENT_ID": "Ov23mismatch12345"},
            {**BROKER, "HERMES_OAUTH_ALLOWED_GITHUB_ID": "123456"},
            {**BROKER, "HERMES_OAUTH_CLIENT_SECRET": ""},
            {**BROKER, "HERMES_OAUTH_SOCKET": "/tmp/invalid.sock"},
        ):
            with self.subTest(changed=set(changed.items()) - set(BROKER.items())):
                with self.assertRaises(AuthError):
                    AuthConfig.from_direct_credentials(WEB, changed)
        with self.assertRaises(AuthError):
            AuthConfig.from_direct_credentials(WEB, {})

    def test_reject_unknown_duplicates_oversize_and_shell_lines(self):
        for source in [
            "HERMES_OAUTH_CLIENT_ID=good\nHERMES_OAUTH_CLIENT_ID=bad\n",
            "HERMES_OAUTH_CLIENT_ID=$(id)\n",
            "# comment\n",
            "A="+("x"*5000),
            "HERMES_CC_AUTH_MODE=github\n",
        ]:
            with self.subTest(source=source[:40]):
                (self.folder/"broker.env").write_text(source)
                with self.assertRaises(ValueError):
                    self.read("broker.env")

    def test_web_refuses_broker_secret_even_if_misfiled(self):
        self.emit("web.env",{**WEB,"HERMES_OAUTH_CLIENT_SECRET":"improper"})
        with self.assertRaises(ValueError):
            self.read("web.env")


if __name__=="__main__":
    unittest.main()
