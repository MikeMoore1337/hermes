"""Actual Windows handle tests on disposable project fixtures."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import h15_native_windows_read as native
from scripts import h454_native_windows_search as search
from scripts import h15_native_windows_mcp_stdio as mcp
from scripts import h15_native_windows_outbound as outbound


@unittest.skipUnless(os.name == "nt", "Win32 handles required")
class WindowsSearchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="h454-search-")
        base = Path(self.tmp.name).resolve(strict=True)
        self.root = base / "hermes-code"
        self.root.mkdir()
        self.code = self.root / "src"
        self.code.mkdir()
        (self.code / "safe.py").write_bytes(b"first\nFind-Needle\nlast\n")
        (self.code / "binary.md").write_bytes(b"\x00Needle")
        (self.root / ".env").write_text("private", encoding="utf-8")
        (self.root / "vault").mkdir()
        (self.root / "vault" / "secret.py").write_text("Needle", encoding="utf-8")
        self.outside = base / "outside.py"
        self.outside.write_text("Needle", encoding="utf-8")
        os.link(self.outside, self.root / "hardlink.py")
        self.patcher = patch.dict(native.READ_ROOTS, {"hermes": str(self.root)}, clear=True)
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        self.tmp.cleanup()

    def test_names_and_content_are_bounded_and_do_not_expose_private_data(self):
        names = search.search("hermes", "safe", mode="names", relative_root="")
        self.assertEqual(names["matches"], [{"path": r"src\safe.py", "kind": "file"}])
        content = search.search("hermes", "needle", mode="content", relative_root="")
        self.assertEqual(content["matches"], [{"path": r"src\safe.py", "line": 2}])
        self.assertEqual(content["bytes_scanned"], len(b"first\nFind-Needle\nlast\n") + len(b"\x00Needle"))
        self.assertNotIn("private", repr(content))

    def test_invalid_roots_and_queries_are_refused(self):
        for query, mode, root in (("", "names", ""), ("a\n", "names", ""),
                                  ("x" * 97, "names", ""), ("x", "regex", ""),
                                  ("x", "names", r"..\outside"), ("x", "names", "vault")):
            with self.subTest(query=query, root=root), self.assertRaises(native.NativeReadRefused):
                search.search("hermes", query, mode=mode, relative_root=root)

    def test_junction_to_outside_is_never_traversed(self):
        outside = Path(self.tmp.name) / "outside-dir"
        outside.mkdir()
        (outside / "leak.py").write_text("needle", encoding="utf-8")
        junction = self.root / "linked"
        subprocess.run(["cmd.exe", "/d", "/c", "mklink", "/J", str(junction), str(outside)],
                       check=True, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        result = search.search("hermes", "needle", mode="content", relative_root="")
        self.assertEqual(result["matches"], [{"path": r"src\safe.py", "line": 2}])
        with self.assertRaises(native.NativeReadRefused):
            search.search("hermes", "needle", mode="content", relative_root="linked")

    def test_entry_budget_and_partial_read_failure_stop_safely(self):
        with patch.object(search, "MAX_ENTRIES", 2):
            result = search.search("hermes", "safe", mode="names", relative_root="")
        self.assertTrue(result["truncated"])
        self.assertEqual(result["entries_scanned"], 2)
        with patch.object(native, "handle_native_request", side_effect=native.NativeReadRefused("busy")) as read:
            result = search.search("hermes", "needle", mode="content", relative_root="")
        self.assertTrue(result["truncated"])
        read.assert_called_once()

    def test_ancestor_cannot_be_renamed_during_content_read(self):
        original = native.handle_native_request
        moved = self.root.with_name("moved-code")
        attempts = []
        def guarded(*args, **kwargs):
            with self.assertRaises(OSError):
                os.rename(self.root, moved)
            attempts.append(True)
            return original(*args, **kwargs)
        with patch.object(native, "handle_native_request", side_effect=guarded):
            result = search.search("hermes", "needle", mode="content", relative_root="")
        self.assertTrue(attempts)
        self.assertEqual(result["matches"], [{"path": r"src\safe.py", "line": 2}])

    def test_search_reaches_win32_handles_through_transport_and_mcp(self):
        session = mcp.McpSession()
        session.handle({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
            "protocolVersion": mcp.PROTOCOL, "capabilities": {}, "clientInfo": {}}})
        message = {"type": "call", "id": "search-1", "tool": "native_file_search", "args": {
            "project": "hermes", "query": "needle", "mode": "content", "relative_root": "src"}}
        result = outbound.safe_call(session, message, set())
        self.assertFalse(result["result"]["isError"])
        import json
        body = json.loads(result["result"]["content"][0]["text"])
        self.assertEqual(body["matches"], [{"path": r"src\safe.py", "line": 2}])
        self.assertNotIn("Find-Needle", repr(body))

    def test_mcp_rejects_forged_outside_path(self):
        fake = {"status": "ok", "project": "hermes", "relative_root": "src", "mode": "names",
                "matches": [{"path": r"outside\data.py", "kind": "file"}],
                "truncated": False, "entries_scanned": 1, "bytes_scanned": 0}
        with self.assertRaises(mcp.ProtocolRefused):
            mcp._sanitized_search(fake, "hermes", "src", "names")
