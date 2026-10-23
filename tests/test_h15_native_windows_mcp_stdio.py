"""Offline, fail-closed MCP stdio original Windows read integration tests (#454).

No owner Windows commands, files, listener, or Git checkout mutations.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import unittest
from unittest.mock import patch

from scripts import h15_native_windows_mcp_stdio as mcp
from scripts import h15_native_windows_read as native


def rpc(identifier, method, params=None):
    result = {"jsonrpc": "2.0", "id": identifier, "method": method}
    if params is not None:
        result["params"] = params
    return result


def initialization(identifier=1):
    return rpc(identifier, "initialize", {
        "protocolVersion": mcp.PROTOCOL,
        "capabilities": {},
        "clientInfo": {"name": "test", "version": "1.0"},
    })


def invoke(identifier, name, project="hermes", relative="README.md"):
    return rpc(identifier, "tools/call", {
        "name": name,
        "arguments": {"project": project, "relative": relative},
    })


def native_fixture(project="hermes", relative="README.md", operation="read"):
    core = {"status": "ok", "project": project, "relative": relative,
            "action": operation, "kind": "file", "size_bytes": 3}
    if operation == "read":
        core.update({"encoding": "base64", "data": base64.b64encode(b"abc").decode(),
                     "sha256": hashlib.sha256(b"abc").hexdigest()})
    return core


def serve(*messages):
    incoming = io.BytesIO(b"".join(
        (json.dumps(m, ensure_ascii=True).encode("utf-8") if isinstance(m, dict) else m)
        + b"\n" for m in messages
    ))
    output = io.BytesIO()
    rc = mcp.serve(incoming, output)
    records = [json.loads(line) for line in output.getvalue().splitlines()]
    return rc, records


class NativeWindowsMcpStdioTests(unittest.TestCase):
    def test_one_approved_file_read_over_actual_jsonrpc_stdio(self):
        seen = []
        def fake(project, relative, operation):
            seen.append((project, relative, operation))
            return native_fixture(project, relative, operation)
        with patch.object(mcp.native, "handle_native_request", side_effect=fake):
            rc, records = serve(initialization(), {"jsonrpc": "2.0",
                "method": "notifications/initialized"},
                rpc(2, "tools/list"), invoke(3, "native_file_read"))
        self.assertEqual(rc, 0)
        self.assertEqual(len(records), 3)
        self.assertEqual(records[0]["result"]["protocolVersion"], "2025-06-18")
        self.assertEqual([v["name"] for v in records[1]["result"]["tools"]],
                         ["native_file_stat", "native_file_read"])
        for tool in records[1]["result"]["tools"]:
            self.assertTrue(tool["annotations"]["readOnlyHint"])
            self.assertFalse(tool["annotations"]["destructiveHint"])
            self.assertFalse(tool["annotations"]["openWorldHint"])
            self.assertFalse(tool["inputSchema"]["additionalProperties"])
        self.assertFalse(records[2]["result"]["isError"])
        self.assertEqual(json.loads(records[2]["result"]["content"][0]["text"]),
                         native_fixture())
        self.assertEqual(seen, [("hermes", "README.md", "read")])

    def test_metadata_only_no_file_contents(self):
        with patch.object(mcp.native, "handle_native_request",
                          return_value=native_fixture(operation="stat")) as fake:
            _, data = serve(initialization(), invoke(9, "native_file_stat"))
        outcome = json.loads(data[1]["result"]["content"][0]["text"])
        self.assertEqual(outcome["size_bytes"], 3)
        self.assertNotIn("data", outcome)
        fake.assert_called_once_with("hermes", "README.md", "stat")

    def test_not_initialized_unknown_and_no_shell_methods(self):
        with patch.object(mcp.native, "handle_native_request") as native_call:
            rc, data = serve(
                invoke(1, "native_file_read"),
                initialization(),
                rpc(2, "tools/call", {"name": "start_process",
                                      "arguments": {"command": "powershell"}}),
                rpc(3, "tools/call", {"name": "write_file", "arguments": {}}),
                rpc(4, "tools/call", {"name": "set_config_value", "arguments": {}}),
                rpc(5, "resources/read", {"uri": "D:\\private"}),
                rpc(6, "ping"),
            )
        self.assertEqual(rc, 0)
        self.assertEqual(data[0]["error"]["code"], -32000)
        self.assertEqual(data[2]["result"]["isError"], True)
        self.assertEqual(data[3]["result"]["isError"], True)
        self.assertEqual(data[4]["result"]["isError"], True)
        self.assertEqual(data[5]["error"]["code"], -32601)
        self.assertEqual(data[6]["result"], {})
        native_call.assert_not_called()

    def test_unrecognized_notifications_do_not_execute(self):
        with patch.object(mcp.native, "handle_native_request") as run:
            rc, data = serve(initialization(), {"jsonrpc": "2.0",
                "method": "tools/call", "params": {"name": "native_file_read",
                "arguments": {"project": "hermes", "relative": "README.md"}}})
        self.assertEqual(rc, 0)
        self.assertEqual(len(data), 1)
        run.assert_not_called()

    def test_read_scope_is_never_widened_by_client_arguments(self):
        malformed = [
            {"name": "native_file_read", "arguments": {
                "project": "hermes", "relative": "..\\private.md"}},
            {"name": "native_file_read", "arguments": {
                "project": "hermes", "relative": "README.md", "approved": True}},
            {"name": "native_file_read", "arguments": {
                "project": "hermes", "relative": 1}},
            {"name": "native_file_read", "arguments": {
                "project": "hermes", "relative": "README.md", "action": "execute"}},
            {"name": "native_file_read", "arguments": {
                "project": "second-brain-workspace", "relative": "secret.md"}},
            {"name": "native_file_read", "arguments": {
                "project": "second-brain", "relative": "vault\\secret.md"}},
            {"name": "native_file_stat", "arguments": {
                "project": "hermes", "relative": "D:\\Windows"}},
            {"name": "native_file_read", "arguments": {
                "project": "hermes", "relative": ".env"}},
            {"name": "native_file_read", "arguments": {
                "project": "hermes", "relative": "a"*2000}},
        ]
        def policy_fake(project, relative, operation):
            native.build_request(project, relative, operation)
            return native_fixture(project, relative, operation)
        with patch.object(mcp.native, "handle_native_request", side_effect=policy_fake):
            _, data = serve(initialization(), *(
                rpc(i + 2, "tools/call", candidate) for i, candidate in enumerate(malformed)))
        self.assertEqual(len(data), 1 + len(malformed))
        self.assertTrue(all(resp["result"]["isError"] for resp in data[1:]))
        self.assertNotIn("private", json.dumps(data))
        self.assertNotIn(".env", json.dumps(data))

    def test_content_integrity_and_forbidden_extra_response_fields(self):
        base = native_fixture()
        altered = [
            dict(base, data="AAAA"),
            dict(base, sha256="f"*64),
            dict(base, size_bytes=500000),
            dict(base, path="C:\\private"),
            dict(base, action="execute"),
            dict(base, project="second-brain"),
            dict(base, encoding="utf8"),
            dict(base, data="invalid@"),
            dict(base, kind="directory"),
        ]
        for result in altered:
            with self.subTest(result=result):
                with patch.object(mcp.native, "handle_native_request", return_value=result):
                    _, data = serve(initialization(), invoke(2, "native_file_read"))
                self.assertTrue(data[1]["result"]["isError"])
                self.assertNotIn("C:\\private", json.dumps(data))

    def test_strict_jsonrpc_field_and_duplicate_rejection(self):
        suspicious = [
            b'{"jsonrpc":"2.0","id":1,"method":"ping","method":"tools/call"}',
            b'{"jsonrpc":"2.0","id":1,"method":"ping","root":"D:\\\\secret"}',
            b'{"jsonrpc":"2.0","id":null,"method":"ping"}',
            b'{"jsonrpc":"2.0","id":true,"method":"ping"}',
            b'{"jsonrpc":"2.0","id":1,"method":"ping","params":[]}',
            b'{"jsonrpc":"2.0","id":1,"method":500}',
            b'{"jsonrpc":"2.0","id":1,"method":"ping","params":{"a":1,"a":2}}',
            b'not-json',
        ]
        for line in suspicious:
            with self.subTest(line=line):
                rc, data = serve(line)
                self.assertEqual(rc, 0)
                self.assertEqual(len(data), 1)
                self.assertEqual(data[0]["error"]["code"], -32700)

    def test_invalid_initialize_and_unknown_version_cannot_enable_reads(self):
        messages = [
            rpc(1, "initialize", {"protocolVersion": "2024-11-05",
                "capabilities": {}, "clientInfo": {}}),
            rpc(2, "tools/list"),
        ]
        rc, data = serve(*messages)
        self.assertEqual(rc, 0)
        self.assertEqual(data[0]["error"]["code"], -32602)
        self.assertEqual(data[1]["error"]["code"], -32000)

    def test_reads_are_limited_per_session(self):
        with patch.object(mcp.native, "handle_native_request",
                          side_effect=lambda p,r,o: native_fixture(p,r,o)) as run:
            messages = [initialization()] + [
                invoke(i+2, "native_file_read") for i in range(mcp.MAX_READS+4)]
            rc, data = serve(*messages)
        self.assertEqual(rc, 0)
        self.assertEqual(run.call_count, mcp.MAX_READS)
        self.assertEqual(sum(v["result"].get("isError") is True for v in data[1:]), 4)

    def test_oversized_line_stops_connection_before_dispatch(self):
        stdin = io.BytesIO(b" " * (mcp.MAX_REQUEST_BYTES+9) + b"\n")
        output = io.BytesIO()
        with patch.object(mcp.native, "handle_native_request") as run:
            self.assertEqual(mcp.serve(stdin, output), 2)
        self.assertEqual(output.getvalue(), b"")
        run.assert_not_called()

    def test_linux_invocation_refuses_host_activation(self):
        if mcp.os.name != "nt":
            self.assertEqual(mcp.main(["--serve-stdio"]), 2)
        self.assertEqual(mcp.main([]), 2)

    def test_only_owner_listed_projects_and_ops_are_exposed(self):
        self.assertEqual(set(mcp.native.READ_ROOTS), {
            "ai-development-toolkit", "hermes", "second-brain", "your-fitness-coach"})
        self.assertEqual(len(mcp.TOOLS), 2)
        self.assertEqual({t["name"] for t in mcp.TOOLS},
                         {"native_file_read", "native_file_stat"})
        self.assertNotIn("execute", json.dumps(mcp.TOOLS))
        self.assertNotIn("write", json.dumps(mcp.TOOLS))


if __name__ == "__main__":
    unittest.main()
