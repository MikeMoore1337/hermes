"""H454: real-kernel disposable Linux files over offline BRC WSS fixtures.

No external network, paid API, owner host paths, real pairing credentials,
MCP registration, processes, production artifacts or host services.
"""
from __future__ import annotations

import base64
import hashlib
import json
import platform
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from device_fabric.linux_native_files import LinuxNativeFiles
from device_fabric.linux_native_read_dispatch import LinuxOriginalReadDispatcher
from device_fabric import linux_native_outbound as native


DEVICE = "h454-linux-hermes-" + "a" * 16
TOKEN = "synthetic-not-a-real-owner-token-" + "x" * 40


def welcome():
    return {
        "type": "welcome", "protocol": 1,
        "relayVersion": "h454-test", "serverTime": 1794250000000,
    }


def call(tool="native_file_read", ident="call-one", *,
         project="hermes", relative="README.md",
         query="TODO", mode="content", relative_root=""):
    args = (
        {"project": project, "relative": relative}
        if tool in {"native_file_stat", "native_file_read", "native_file_list"}
        else {"project": project, "query": query,
              "mode": mode, "relative_root": relative_root}
    )
    return {"type": "call", "id": ident, "tool": tool, "args": args}


class FakeSocket:
    def __init__(self, incoming):
        self.incoming = list(incoming)
        self.outgoing = []
        self.closed = False
        self.timeouts = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.closed = True

    def recv(self, timeout=None):
        self.timeouts.append(timeout)
        if not self.incoming:
            raise TimeoutError
        item = self.incoming.pop(0)
        return json.dumps(item, ensure_ascii=True) if type(item) is dict else item

    def send(self, message):
        self.outgoing.append(json.loads(message))


class FakeConnector:
    def __init__(self, incoming):
        self.socket = FakeSocket(incoming)
        self.calls = []

    def __call__(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.socket


def config():
    return native.local_config(
        target="hermes-vps", device_id=DEVICE, token=TOKEN)


class NativeLinuxOutboundPureTests(unittest.TestCase):
    def test_hello_declares_only_four_readonly_original_tools(self):
        h = native.hello(config())
        self.assertEqual(h["protocol"], 1)
        self.assertEqual(h["device"]["platform"], "linux")
        self.assertEqual(h["device"]["deviceId"], DEVICE)
        self.assertEqual(h["device"]["name"],
                         "H454 Hermes VPS native read-only")
        self.assertEqual({v["name"] for v in h["tools"]}, {
            "native_file_stat", "native_file_read",
            "native_file_list", "native_file_search"})
        self.assertTrue(all(t["annotations"]["readOnlyHint"] for t in h["tools"]))
        self.assertFalse(any("start_process" in t["name"] for t in h["tools"]))
        self.assertNotIn(TOKEN, str(h))
        h["tools"][0]["name"] = "write_file"
        self.assertNotIn("write_file", str(native.hello(config())))

    def test_exact_native_device_config_target_cannot_impersonate_sandbox(self):
        for ident in (
            "h15-hermes-ab005bc0e0ea", "h15-yfc-c6ee0d53e858",
            "h454-win-01335a1f6e6705b4", "h454-linux-yfc-" + "a"*16,
            "h454-linux-hermes-" + "Z"*16, "not-native",
        ):
            with self.subTest(ident=ident), self.assertRaises(native.LinuxOutboundDenied):
                native.local_config(target="hermes-vps",
                                    device_id=ident, token=TOKEN)
        for target in ("win32", "hermes", "user", ""):
            with self.assertRaises(native.LinuxOutboundDenied):
                native.local_config(target=target, device_id=DEVICE, token=TOKEN)
        good = native.local_config(
            target="yfc-vps", device_id="h454-linux-yfc-" + "b"*16,
            token=TOKEN)
        self.assertEqual(good.target, "yfc-vps")

    def test_rejects_foreign_url_plaintext_or_credentials_in_query(self):
        for url in (
            "", "ws://hermes.mikemoore.top/ws",
            "wss://other.example/ws", "wss://hermes.mikemoore.top/mcp",
            "wss://hermes.mikemoore.top:443/ws",
            "wss://hermes.mikemoore.top/ws?key=abc",
            "wss://user:pass@hermes.mikemoore.top/ws",
            "wss://hermes.mikemoore.top/ws#frag",
            "ws://127.0.0.1:38183/ws",
            "wss://hermes.mikemoore.top.evil/ws",
        ):
            with self.subTest(url=url), self.assertRaises(native.LinuxOutboundDenied):
                native.local_config(target="hermes-vps",
                                    device_id=DEVICE, token=TOKEN,
                                    url=url)

    def test_bad_credentials_and_noncanonical_identity_denied(self):
        for token in ("", "too-short", "x" * 39, "a" * 257,
                      "secret with space", "abc?token=other"):
            with self.subTest(token=token), self.assertRaises(native.LinuxOutboundDenied):
                native.local_config(
                    target="hermes-vps", device_id=DEVICE, token=token)

    def test_duplicate_and_oversize_relay_messages_denied(self):
        invalid = (
            b"", b"{}", b"[]", b"\xff",
            b'{"type":"welcome","type":"welcome"}',
            b'{"type": "ping","ts":NaN}', b'{"type":"call","args":' + b"x"*8192,
        )
        for payload in invalid:
            with self.subTest(payload=payload[:30]):
                with self.assertRaises(native.LinuxOutboundDenied):
                    native.decode_message(payload)

    def test_bad_outbound_response_is_replaced_with_sanitized_denial(self):
        msg = json.loads(native._result_frame(
            "call123", {"status":"ok", "data":"x" * (512*1024)}))
        self.assertTrue(msg["result"]["isError"])
        self.assertIn("native_linux_read_denied",
                      msg["result"]["content"][0]["text"])
        self.assertNotIn("xxx", str(msg))


@unittest.skipUnless(
    sys.platform == "linux" and platform.machine().lower() in ("x86_64", "aarch64"),
    "real Linux original-style fixture and openat2 required")
class NativeLinuxOutboundRealKernelTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="h454-native-linux-wss-ci-")
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.root = base / "original"
        self.root.mkdir()
        (self.root / "docs").mkdir()
        (self.root / "README.md").write_bytes(b"# Hermes\nTODO smoke\n")
        (self.root / "docs" / "notes.md").write_bytes(b"read only\n")
        (self.root / ".env").write_bytes(b"PRIVATE_TEST_PASSWORD=NO_LEAK")
        self.outside = base / "secret.txt"
        self.outside.write_bytes(b"PRIVATE_TEST_SECRET")
        (self.root / "redirection.md").symlink_to(self.outside)
        self.files = LinuxNativeFiles(root=self.root, project="hermes")
        self.addCleanup(self.files.close)
        self.broker = LinuxOriginalReadDispatcher(
            device_id=DEVICE, local_roots={"hermes": self.files},
            is_device_revoked=lambda: False)

    def run_messages(self, messages, *, dispatcher=None, monotonic=None):
        connector = FakeConnector(messages)
        kwargs = {}
        if monotonic is not None:
            kwargs["monotonic"] = monotonic
        reason = native.run_session(
            config(), self.broker if dispatcher is None else dispatcher,
            connector, **kwargs)
        return reason, connector

    def test_actual_kernel_read_and_existing_relay_wire(self):
        messages = [
            welcome(), {"type": "ping", "ts": 1794250000000},
            call(), call("native_file_stat", "stat-1"),
            call("native_file_list", "list-1", relative="docs"),
            call("native_file_search", "search-1", query="todo"),
        ]
        reason, client = self.run_messages(messages)
        self.assertEqual(reason, "idle_timeout")
        self.assertTrue(client.socket.closed)
        self.assertEqual(
            [x["type"] for x in client.socket.outgoing],
            ["hello", "pong", "result", "result", "result", "result"])
        self.assertEqual(len(client.calls), 1)
        url, options = client.calls[0]
        self.assertEqual(url, native.ENDPOINT)
        self.assertEqual(
            options["additional_headers"]["Authorization"],
            "Bearer " + TOKEN)
        self.assertEqual(options["additional_headers"]["X-BRC-Protocol"], "1")
        self.assertIsNone(options["proxy"])
        self.assertIsNone(options["compression"])
        self.assertEqual(options["max_size"], native.MAX_INBOUND)
        body = json.loads(
            client.socket.outgoing[2]["result"]["content"][0]["text"])
        data = base64.b64decode(body["data"], validate=True)
        self.assertEqual(data, b"# Hermes\nTODO smoke\n")
        self.assertEqual(body["sha256"], hashlib.sha256(data).hexdigest())
        searched = json.loads(
            client.socket.outgoing[-1]["result"]["content"][0]["text"])
        self.assertEqual(searched["matches"], [{"path":"README.md","line":2}])
        self.assertNotIn(TOKEN, str(client.socket.outgoing))
        self.assertNotIn(str(self.root), str(client.socket.outgoing))

    def test_no_processing_call_before_authenticated_welcome(self):
        conn = FakeConnector([call()])
        with patch.object(self.broker, "call") as calling:
            with self.assertRaises(native.LinuxOutboundDenied):
                native.run_session(config(), self.broker, conn)
            calling.assert_not_called()
        self.assertTrue(conn.socket.closed)

    def test_tampered_or_duplicate_welcome_is_fatal(self):
        for bad in (
            dict(welcome(), protocol=2),
            dict(welcome(), protocol=True),
            dict(welcome(), unexpected="x"),
            dict(welcome(), serverTime="0"),
            dict(welcome(), relayVersion=""),
        ):
            with self.subTest(bad=bad), self.assertRaises(native.LinuxOutboundDenied):
                self.run_messages([bad, call()])
        with self.assertRaises(native.LinuxOutboundDenied):
            self.run_messages([welcome(), welcome(), call()])

    def test_relay_failure_is_fatal_with_no_automatic_reconnect(self):
        conn = FakeConnector([welcome(), {"type":"error", "fatal":True}])
        with self.assertRaises(native.LinuxOutboundDenied):
            native.run_session(config(), self.broker, conn)
        self.assertEqual(len(conn.calls), 1)
        self.assertTrue(conn.socket.closed)

    def test_unknown_write_process_and_foreign_scope_never_invoked(self):
        messages = [
            welcome(),
            call("start_process", "bad-1"),
            call("write_file", "bad-2"),
            call("native_file_delete", "bad-3"),
            call("native_file_read", "bad-4", relative=".env"),
            call("native_file_read", "bad-5", relative="../secret"),
            call("native_file_read", "bad-6", project="foreign"),
            call("native_file_read", "bad-7", relative="redirection.md"),
            call("native_file_read", "bad-8"),
        ]
        _, conn = self.run_messages(messages)
        self.assertEqual([x["id"] for x in conn.socket.outgoing if x["type"]=="result"],
                         ["bad-6", "bad-7", "bad-8"])
        self.assertNotIn("PRIVATE", str(conn.socket.outgoing))
        for item in conn.socket.outgoing:
            if item["type"]=="result" and item["id"] in ("bad-6","bad-7"):
                self.assertTrue(item["result"]["isError"])

    def test_duplicate_id_cannot_read_twice_or_retry_scope(self):
        _, conn = self.run_messages([
            welcome(), call(ident="same"),
            call("native_file_stat", ident="same"),
            call("native_file_read", ident="next")])
        self.assertEqual(
            [x["id"] for x in conn.socket.outgoing if x["type"]=="result"],
            ["same", "next"])

    def test_remote_boolean_and_device_overrides_do_not_reach_originals(self):
        altered = call()
        altered["owner_approved"] = True
        another = call(ident="bad-2")
        another["args"]["device_id"] = "h15-hermes-ab005bc0e0ea"
        with patch.object(self.files, "read_file") as reader:
            _, conn = self.run_messages([welcome(), altered, another])
            reader.assert_not_called()
        self.assertEqual([r["type"] for r in conn.socket.outgoing], ["hello"])

    def test_revocation_at_original_read_returns_generic_error(self):
        state = iter((False, True))
        broker = LinuxOriginalReadDispatcher(
            device_id=DEVICE, local_roots={"hermes": self.files},
            is_device_revoked=lambda: next(state))
        _, conn = self.run_messages(
            [welcome(), call()], dispatcher=broker)
        self.assertEqual(conn.socket.outgoing[-1]["type"], "result")
        self.assertTrue(conn.socket.outgoing[-1]["result"]["isError"])
        self.assertIn("native_linux_read_denied",
                      conn.socket.outgoing[-1]["result"]["content"][0]["text"])
        self.assertNotIn(TOKEN, str(conn.socket.outgoing))

    def test_exclusive_call_budget_terminates_session(self):
        reqs = [welcome()] + [
            call("native_file_stat", f"call-{index}")
            for index in range(native.MAX_TOOL_CALLS)]
        reason, conn = self.run_messages(reqs)
        self.assertEqual(reason, "session_call_budget")
        self.assertEqual(len([x for x in conn.socket.outgoing
                              if x["type"]=="result"]), native.MAX_TOOL_CALLS)

    def test_synthetic_session_deadline_does_not_read(self):
        times = iter((0.0, 241.0))
        conn = FakeConnector([welcome(), call()])
        with patch.object(self.files, "read_file") as reader:
            reason = native.run_session(
                config(), self.broker, conn,
                monotonic=lambda: next(times))
            reader.assert_not_called()
        self.assertEqual(reason, "session_deadline")
        self.assertEqual([x["type"] for x in conn.socket.outgoing], ["hello"])

    def test_wrong_device_dispatcher_never_opens_websocket(self):
        broker = LinuxOriginalReadDispatcher(
            device_id="h454-linux-hermes-" + "b"*16,
            local_roots={"hermes": self.files},
            is_device_revoked=lambda: False)
        conn = FakeConnector([welcome()])
        with self.assertRaises(native.LinuxOutboundDenied):
            native.run_session(config(), broker, conn)
        self.assertEqual(conn.calls, [])

    def test_bounded_bad_relay_frames_refuse_without_os_traceback(self):
        for msg in (
            {"type":"ping","ts":True},
            {"type":"ping","ts":float("nan")},
            {"type":"ping","ts":"secret"},
        ):
            with self.subTest(msg=msg):
                conn = FakeConnector([welcome(), msg])
                with self.assertRaisesRegex(
                    native.LinuxOutboundDenied, "^native_linux_transport_denied$"):
                    native.run_session(config(), self.broker, conn)

    def test_no_process_or_network_side_effect_from_local_dispatch(self):
        with patch("subprocess.Popen", side_effect=AssertionError("shell forbidden")):
            reason, conn = self.run_messages([welcome(), call("native_file_stat")])
        self.assertEqual(reason, "idle_timeout")
        self.assertEqual(len(conn.calls), 1)


if __name__ == "__main__":
    unittest.main()
