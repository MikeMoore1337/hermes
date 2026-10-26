"""Native ChatGPT first-level discovery: deny-by-default MCP/WSS contracts.

Runs on Linux CI with a simulated checked Win32 adapter. Actual Win32 handle
and WebSocket in-process synthetic tests live on the isolated Windows runner.
"""
from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from scripts import h15_native_windows_mcp_stdio as mcp
from scripts import h15_native_windows_outbound as outbound


def list_payload(entries=None):
    return {"status": "ok", "project": "hermes", "relative": "",
            "action": "list", "kind": "directory", "entries": entries or [
                {"name": "README.md", "kind": "file"},
                {"name": "src", "kind": "directory"}],
            "truncated": False}


def call(relative=""):
    return {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "native_file_list",
                       "arguments": {"project": "hermes", "relative": relative}}}


class NativeListContract(unittest.TestCase):
    def session(self):
        session = mcp.McpSession()
        init = session.handle({"jsonrpc": "2.0", "id": 1,
                               "method": "initialize",
                               "params": {"protocolVersion": mcp.PROTOCOL,
                                          "capabilities": {}, "clientInfo": {}}})
        self.assertIn("result", init)
        return session

    def test_mcp_list_is_discovered_with_no_content_or_commands(self):
        sess = self.session()
        tools = sess.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/list"})[
            "result"]["tools"]
        self.assertEqual({tool["name"] for tool in tools},
                         {"native_file_read", "native_file_stat", "native_file_list"})
        definition = next(t for t in tools if t["name"] == "native_file_list")
        self.assertEqual(definition["inputSchema"]["properties"]["relative"]["enum"], [""])
        self.assertTrue(definition["annotations"]["readOnlyHint"])
        self.assertFalse(definition["annotations"]["destructiveHint"])
        self.assertFalse(definition["annotations"]["openWorldHint"])

    def test_list_dispatches_only_checked_root_to_broker(self):
        session = self.session()
        with patch.object(mcp.native, "handle_native_list", return_value=list_payload()) as listing:
            result = session.handle(call())
        self.assertFalse(result["result"]["isError"])
        self.assertEqual(json.loads(result["result"]["content"][0]["text"]),
                         list_payload())
        listing.assert_called_once_with("hermes", "")

    def test_relative_directory_and_new_privilege_are_refused(self):
        sess = self.session()
        with patch.object(mcp.native, "handle_native_list") as listing:
            self.assertTrue(sess.handle(call("src"))["result"]["isError"])
            attack = call()
            attack["params"]["arguments"]["ownerApproved"] = True
            self.assertTrue(sess.handle(attack)["result"]["isError"])
            listing.assert_not_called()

    def test_sanitizer_refuses_secret_names_wrong_kind_and_metadata(self):
        invalid = [
            list_payload([{"name": ".env", "kind": "file"}]),
            list_payload([{"name": ".git", "kind": "directory"}]),
            list_payload([{"name": "private-vault", "kind": "directory"}]),
            list_payload([{"name": "README.md", "kind": "command"}]),
            list_payload([{"name": "binary.exe", "kind": "file"}]),
            list_payload([{"name": "..\\private.md", "kind": "file"}]),
            list_payload([{"name": "src", "kind": "directory"},
                          {"name": "SRC", "kind": "directory"}]),
            dict(list_payload(), data="secret"),
            dict(list_payload(), truncated="no"),
            dict(list_payload(), relative="src"),
            dict(list_payload(), entries=[{"name": "README.md", "kind": "file",
                                           "path": "D:\\private"}]),
            dict(list_payload(), entries=[{"name": "src", "kind": "directory"}] * 65),
        ]
        session = self.session()
        with patch.object(mcp.native, "handle_native_list", side_effect=invalid) as listing:
            for case in invalid:
                with self.subTest(case=str(case)[:80]):
                    result = session.handle(call())
                    self.assertTrue(result["result"]["isError"])
                    self.assertNotIn("private", json.dumps(result).lower())
        self.assertEqual(listing.call_count, len(invalid))

    def test_transport_rejects_nonroot_and_preserves_replay_id(self):
        seen = set()
        session = self.session()
        request = {"type": "call", "id": "root-1", "tool": "native_file_list",
                   "args": {"project": "hermes", "relative": ""}}
        with patch.object(mcp.native, "handle_native_list", return_value=list_payload()) as listing:
            self.assertIsNotNone(outbound.safe_call(session, request, seen))
            self.assertIsNone(outbound.safe_call(session, request, seen))
            self.assertIsNone(outbound.safe_call(session, dict(request, id="root-2",
                            args={"project": "hermes", "relative": "src"}), seen))
        listing.assert_called_once()
        self.assertEqual(seen, {"root-1"})

    def test_readonly_reconnect_catalog_still_refuses_effectful_tool(self):
        for catalog in [
            mcp.TOOLS + ({"name": "native_file_write"},),
            ({"name": "native_file_list"},),
        ]:
            with patch.object(outbound, "TOOLS", catalog):
                with self.assertRaisesRegex(outbound.NativeTransportDenied,
                                            "reconnect_requires_readonly_catalog"):
                    outbound.run_bounded_reconnect(
                        outbound.parse_settings("wss://hermes.mikemoore.top/ws",
                                                "h454-device-test-abc", "a"*48),
                        lambda *_: None, pause=lambda _: None)


if __name__ == "__main__":
    unittest.main()
