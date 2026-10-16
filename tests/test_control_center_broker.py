"""Offline tests for owner-only Unix broker: exact operations, peer, rate limit."""
import json
import os
from pathlib import Path
import socket
import tempfile
from threading import Thread
import unittest
from unittest.mock import patch

from control_center.auth import AuthConfig, AuthError, LocalBrokerProvider
from control_center.oauth_broker import BrokerConfig, IdentityBroker, parse_request, MAX_ATTEMPTS


class FakeGitHub:
    def __init__(self):
        self.calls=0
    def identify(self, config, code, verifier):
        self.calls+=1
        return config.owner_id


class BrokerContractTests(unittest.TestCase):
    def test_request_schema_denies_urls_and_other_actions(self):
        correct={"action":"identify","code":"code-token-123456","verifier":"v"*55}
        self.assertEqual(parse_request((json.dumps(correct)+"\n").encode()),(correct["code"],correct["verifier"]))
        for update in (
            {"url":"https://evil.example"}, {"action":"fetch"}, {"verifier":"invalid"},
            {"code":"x"}, {"headers":{"Authorization":"Bearer secret"}},
            {"path":"/repos"}, {"method":"POST"}
        ):
            with self.subTest(update=update),self.assertRaises(AuthError):
                parse_request((json.dumps({**correct,**update})+"\n").encode())
        for raw in (b"{}", b"x"*2050, b"{\"action\":\"identify\"}\n\n"):
            with self.assertRaises(AuthError):parse_request(raw)

    def test_broker_configuration_rejects_untrusted_origin(self):
        cfg={"HERMES_OAUTH_CLIENT_ID":"Ov23abcdefghijk",
             "HERMES_OAUTH_CLIENT_SECRET":"valid-test-broker-secret-value",
             "HERMES_OAUTH_ALLOWED_GITHUB_ID":"42142321"}
        self.assertEqual(BrokerConfig.from_env(cfg).owner_id,42142321)
        for key,bad in (("HERMES_OAUTH_CLIENT_SECRET",""),
                        ("HERMES_OAUTH_ALLOWED_GITHUB_ID","MikeMoore1337"),
                        ("HERMES_OAUTH_SOCKET","/tmp/evil.sock")):
            with self.subTest(key=key),self.assertRaises(AuthError):
                BrokerConfig.from_env({**cfg,key:bad})

    @unittest.skipUnless(hasattr(socket,"SO_PEERCRED"),"SO_PEERCRED requires Linux")
    def test_unix_socket_roundtrip_only_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            path=str(Path(directory)/"broker.sock")
            fake=FakeGitHub()
            config=BrokerConfig("Ov23abcdefghijk","valid-test-broker-secret-value",42142321,path)
            with IdentityBroker(config,provider=fake,allowed_uid=os.getuid()) as broker:
                thread=Thread(target=broker.serve_forever,daemon=True)
                thread.start()
                try:
                    with patch("control_center.auth.BROKER_SOCKET",path):
                        result=LocalBrokerProvider().identify(
                            AuthConfig(mode="github",broker_socket=path),
                            "code-token-123456","v"*55)
                    self.assertEqual(result,42142321)
                    self.assertEqual(fake.calls,1)
                    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
                        conn.connect(path)
                        conn.sendall(b'{"action":"arbitrary","url":"https://evil.example"}\n')
                        response=conn.recv(200)
                    self.assertEqual(json.loads(response),{"ok":False})
                    self.assertEqual(fake.calls,1)
                finally:
                    broker.shutdown()
                    thread.join(timeout=3)
            self.assertFalse(Path(path).exists())

    def test_rate_limit_bounded(self):
        # No socket or GitHub network needed: test quota via a small object stand-in.
        broker=object.__new__(IdentityBroker)
        from collections import deque
        broker.attempts=deque()
        now=[1000.]
        broker.clock=lambda:now[0]
        self.assertTrue(all(broker.consume_attempt() for _ in range(MAX_ATTEMPTS)))
        self.assertFalse(broker.consume_attempt())
        now[0]+=3601
        self.assertTrue(broker.consume_attempt())


if __name__=="__main__":
    unittest.main()
