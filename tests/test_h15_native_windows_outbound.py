"""Offline transport contract for a separate Windows read-only BRC device (#454).

No socket, original file, host process or credentials are used in these tests.
"""
from __future__ import annotations

import base64
import hashlib
import json
import unittest
from unittest.mock import patch

from scripts import h15_native_windows_outbound as outbound
from scripts import h15_native_windows_mcp_stdio as mcp


def settings():
    return outbound.parse_settings(
        "wss://hermes.mikemoore.top/ws",
        "h15-native-readonly-12345",
        "a" * 48,
    )


def welcome():
    return {"type": "welcome", "protocol": 1, "relayVersion": "v1", "serverTime": 1792745662222}


def call(ident="call-1", name="native_file_read",
         project="hermes", relative="README.md"):
    return {"type": "call", "id": ident, "tool": name,
            "args": {"project": project, "relative": relative}}


def payload(project="hermes", relative="README.md", operation="read"):
    value = {"status": "ok", "project": project, "relative": relative,
             "action": operation, "kind": "file", "size_bytes": 3}
    if operation == "read":
        value.update({"encoding": "base64", "data": base64.b64encode(b"abc").decode(),
                      "sha256": hashlib.sha256(b"abc").hexdigest()})
    return value


class FakeWebSocket:
    def __init__(self, inbound):
        self.inbound = list(inbound)
        self.sent = []
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.closed = True

    def send(self, message):
        self.sent.append(json.loads(message))

    def recv(self, timeout=None):
        if not self.inbound:
            raise TimeoutError
        msg = self.inbound.pop(0)
        return json.dumps(msg) if isinstance(msg, dict) else msg


class FakeConnector:
    def __init__(self, inbound):
        self.ws = FakeWebSocket(inbound)
        self.invocations = []

    def __call__(self, url, **kwargs):
        self.invocations.append((url, kwargs))
        return self.ws


class OutboundReadOnlyTests(unittest.TestCase):
    def test_outbound_wss_hello_auth_and_real_mcp_dispatch(self):
        connector = FakeConnector([welcome(), {"type": "ping", "ts": 7},
                                   call(), call("call-2", name="native_file_stat")])
        seen = []
        def fake(project, relative, operation):
            seen.append((project, relative, operation))
            return payload(project, relative, operation)
        with patch.object(mcp.native, "handle_native_request", side_effect=fake):
            reason = outbound.run_session(settings(), connector)
        self.assertEqual(reason, "idle_timeout")
        self.assertTrue(connector.ws.closed)
        self.assertEqual(seen, [
            ("hermes", "README.md", "read"), ("hermes", "README.md", "stat")])
        url, params = connector.invocations[0]
        self.assertEqual(url, "wss://hermes.mikemoore.top/ws")
        self.assertEqual(params["additional_headers"]["Authorization"], "Bearer " + "a"*48)
        self.assertEqual(params["additional_headers"]["X-BRC-Protocol"], "1")
        self.assertIsNone(params["compression"])
        self.assertIsNone(params["proxy"])
        self.assertEqual(params["max_size"], outbound.MAX_INCOMING)
        self.assertEqual([x["type"] for x in connector.ws.sent],
                         ["hello", "pong", "result", "result"])
        h = connector.ws.sent[0]
        self.assertEqual(h["protocol"], 1)
        self.assertEqual(h["device"]["platform"], "win32")
        self.assertEqual(h["device"]["name"], outbound.DEVICE_NAME)
        self.assertEqual([x["name"] for x in h["tools"]],
                         ["native_file_stat", "native_file_read"])
        self.assertNotIn("start_process", json.dumps(h))
        self.assertNotIn("write_file", json.dumps(h))
        self.assertNotIn("a"*48, json.dumps(connector.ws.sent))
        self.assertEqual(json.loads(connector.ws.sent[2]["result"]["content"][0]["text"]),
                         payload())
        self.assertEqual(json.loads(connector.ws.sent[3]["result"]["content"][0]["text"]),
                         payload(operation="stat"))

    def test_refuses_plaintext_ws_credentials_in_url_and_foreign_relay(self):
        for url in [
            "ws://hermes.mikemoore.top/ws",
            "wss://foreign.test/ws",
            "wss://hermes.mikemoore.top:444/ws",
            "wss://hermes.mikemoore.top/mcp",
            "wss://me:password@hermes.mikemoore.top/ws",
            "wss://hermes.mikemoore.top/ws?token=a",
            "wss://hermes.mikemoore.top/ws#frag",
            "wss://hermes.mikemoore.top.evil.net/ws",
            "file:///ws", "", None,
        ]:
            with self.subTest(url=url), self.assertRaises(outbound.NativeTransportDenied):
                outbound.parse_settings(url, "h15-native-readonly-12345", "a"*48)

    def test_refuses_bad_device_tokens_and_ids(self):
        for device, token in [
            ("", "a"*48), ("../../something", "a"*48),
            ("h15-native-readonly-12345", ""),
            ("h15-native-readonly-12345", "secret\nAuthorization:evil"),
            ("h15-native-readonly-12345", "abc"),
            ("h15-native-readonly-12345", "a"*1025),
        ]:
            with self.subTest(device=device, token=token[:8]):
                with self.assertRaises(outbound.NativeTransportDenied):
                    outbound.parse_settings("wss://hermes.mikemoore.top/ws", device, token)

    def test_not_accepts_commands_or_vault_via_websocket(self):
        messages = [welcome(),
                    call("bad-1", "start_process"),
                    call("bad-2", "write_file"),
                    call("bad-3", "native_file_read", "hermes", "..\\private.md"),
                    call("bad-4", "native_file_read", "second-brain", "vault\\secret.md"),
                    call("bad-5", "native_file_read", "unknown", "README.md"),
                    call("good-1", "native_file_stat")]
        connector = FakeConnector(messages)
        def fake(project, relative, operation):
            mcp.native.build_request(project, relative, operation)
            return payload(project, relative, operation)
        with patch.object(mcp.native, "handle_native_request", side_effect=fake) as run:
            outbound.run_session(settings(), connector)
        answers = [x for x in connector.ws.sent if x["type"] == "result"]
        self.assertEqual(len(answers), 4)
        self.assertTrue(all(x["result"]["isError"] for x in answers[:3]))
        self.assertEqual(answers[3]["id"], "good-1")
        self.assertFalse(answers[3]["result"]["isError"])
        self.assertEqual(run.call_count, 4)
        self.assertNotIn("secret.md", json.dumps(answers))

    def test_requires_welcome_before_read(self):
        connector = FakeConnector([call()])
        with patch.object(mcp.native, "handle_native_request") as run:
            with self.assertRaises(outbound.NativeTransportDenied):
                outbound.run_session(settings(), connector)
        run.assert_not_called()
        self.assertTrue(connector.ws.closed)

    def test_replay_id_rejected_no_second_read(self):
        connector = FakeConnector([welcome(), call("same"), call("same")])
        with patch.object(mcp.native, "handle_native_request",
                          return_value=payload()) as run:
            outbound.run_session(settings(), connector)
        self.assertEqual(run.call_count, 1)
        replies = [x for x in connector.ws.sent if x["type"] == "result"]
        self.assertEqual(len(replies), 1)

    def test_session_caps_native_operations(self):
        connector = FakeConnector([welcome()] +
                                  [call("id-"+str(i)) for i in range(20)])
        with patch.object(mcp.native, "handle_native_request",
                          return_value=payload()) as run:
            stop = outbound.run_session(settings(), connector)
        self.assertEqual(stop, "read_budget_exhausted")
        self.assertEqual(run.call_count, outbound.MAX_CALLS)
        self.assertTrue(connector.ws.closed)

    def test_protocol_rejects_wrong_welcome_and_oversized_frame(self):
        for frame in [
            {"type": "welcome", "protocol": 3, "relayVersion": "bad", "serverTime": 1},
            {"type": "call", "id": "before-welcome", "args": {}, "tool": "native_file_read"},
            {"type": "error", "fatal": True, "code": "DENIED"},
            b"x"*(outbound.MAX_INCOMING+1),
        ]:
            with self.subTest(frame=str(frame)[:30]):
                connector = FakeConnector([frame])
                with patch.object(mcp.native, "handle_native_request") as run:
                    with self.assertRaises(outbound.NativeTransportDenied):
                        outbound.run_session(settings(), connector)
                run.assert_not_called()

    def test_no_sensitive_transport_exception_leak(self):
        class FailConnect:
            def __call__(self, *_args, **_kwargs):
                raise RuntimeError("token=" + "a"*48 + " and C:\\private")
        with self.assertRaisesRegex(outbound.NativeTransportDenied, "^transport_failed$"):
            outbound.run_session(settings(), FailConnect())

    def test_linux_does_not_activate_agent(self):
        if outbound.os.name != "nt":
            self.assertEqual(outbound.main(["--single-session"]), 2)
        self.assertEqual(outbound.main([]), 2)


if __name__ == "__main__":
    unittest.main()
