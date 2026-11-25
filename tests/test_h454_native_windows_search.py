"""Actual Windows handle tests on disposable project fixtures."""
from __future__ import annotations

import os
import json
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

    def test_paged_search_reaches_more_than_512_entries(self):
        for index in range(550):
            (self.code / f'needle-{index:04}.py').write_bytes(b'')
        cursor = ''
        seen = set()
        session = mcp.McpSession()
        session.handle({'jsonrpc':'2.0', 'id':0, 'method':'initialize', 'params':{
            'protocolVersion':mcp.PROTOCOL, 'capabilities':{}, 'clientInfo':{}}})
        ids = set()
        for index in range(15):
            message = {'type':'call', 'id':f'page-{index}', 'tool':'native_file_search',
                'args':{'project':'hermes', 'query':'needle', 'mode':'names',
                        'relative_root':'src', 'cursor':cursor}}
            response = outbound.safe_call(session, message, ids)
            self.assertFalse(response['result']['isError'])
            result = json.loads(response['result']['content'][0]['text'])
            seen.update(row['path'] for row in result['matches'])
            cursor = result['next_cursor']
            if not cursor:
                break
        self.assertEqual(cursor, '')
        self.assertEqual(len(seen), 550)

    def test_paged_content_search_resumes_inside_one_file(self):
        (self.code / 'many.py').write_text('needle\n' * 150, encoding='utf-8')
        cursor = ''
        lines = []
        for _ in range(10):
            result = search.search('hermes', 'needle', mode='content', relative_root='src', cursor=cursor)
            lines.extend(row['line'] for row in result['matches'] if row['path'] == r'src\many.py')
            cursor = result['next_cursor']
            if not cursor:
                break
        self.assertEqual(cursor, '')
        self.assertEqual(lines, list(range(1, 151)))

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

    def test_content_matches_stop_at_budget(self):
        (self.code / "many.py").write_text("needle\n" * (search.MAX_MATCHES + 3), encoding="utf-8")
        result = search.search("hermes", "needle", mode="content", relative_root="src")
        self.assertTrue(result["truncated"])
        self.assertEqual(len(result["matches"]), search.MAX_MATCHES)

    def test_search_reaches_a_safe_file_beyond_four_levels(self):
        current = self.code
        for index in range(7):
            current = current / f"level{index}"
            current.mkdir()
        (current / "deep-match.py").write_text("deep-needle\n", encoding="utf-8")
        result = search.search("hermes", "deep-needle", mode="content", relative_root="src")
        expected = str((current / "deep-match.py").relative_to(self.root))
        self.assertEqual(result["matches"], [{"path": expected, "line": 1}])
        self.assertFalse(result["truncated"])

    def test_deep_junction_does_not_escape_project(self):
        current = self.code
        for index in range(7):
            current = current / f"level{index}"
            current.mkdir()
        outside = Path(self.tmp.name) / "outside-dir"
        outside.mkdir()
        (outside / "leak.py").write_text("outside-needle", encoding="utf-8")
        subprocess.run(["cmd.exe", "/d", "/c", "mklink", "/J", str(current / "linked"), str(outside)],
                       check=True, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        result = search.search("hermes", "outside-needle", mode="content", relative_root="src")
        self.assertEqual(result["matches"], [])
        self.assertNotIn("leak.py", repr(result))

    def test_directory_handle_budget_stops_before_descending(self):
        with patch.object(search, "MAX_DIRECTORY_HANDLES", 1):
            result = search.search("hermes", "safe", mode="names", relative_root="")
        self.assertTrue(result["truncated"])
        self.assertEqual(result["matches"], [])

    def test_sixty_nested_directories_fit_the_handle_budget(self):
        current = self.code
        for _ in range(60):
            current = current / "a"
            current.mkdir()
        (current / "deep-marker.py").write_text("safe", encoding="utf-8")
        result = search.search("hermes", "deep-marker", mode="names", relative_root="src")
        self.assertEqual(result["matches"], [{"path": str((current / "deep-marker.py").relative_to(self.root)), "kind": "file"}])
        self.assertFalse(result["truncated"])
        cursor = ''
        matches = []
        for _ in range(40):
            result = search.search("hermes", "deep-marker", mode="names", relative_root="src", cursor=cursor)
            matches.extend(result['matches'])
            cursor = result['next_cursor']
            if not cursor:
                break
        self.assertEqual(cursor, '')
        self.assertEqual(matches, [{"path": str((current / "deep-marker.py").relative_to(self.root)), "kind": "file"}])

    def test_skipped_oversize_file_does_not_hide_queued_directory(self):
        (self.root / "a-oversize.txt").write_bytes(b"x" * (native.MAX_FILE_BYTES + 1))
        result = search.search("hermes", "needle", mode="content", relative_root="")
        self.assertTrue(result["truncated"])
        self.assertIn({"path": r"src\safe.py", "line": 2}, result["matches"])

    def test_depth_truncation_does_not_hide_other_queued_directories(self):
        (self.root / "aaa").mkdir()
        (self.root / "aaa" / "deep").mkdir()
        with patch.object(search, "MAX_DEPTH", 1):
            result = search.search("hermes", "needle", mode="content", relative_root="")
        self.assertTrue(result["truncated"])
        self.assertIn({"path": r"src\safe.py", "line": 2}, result["matches"])

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

    def test_search_shares_mcp_read_budget(self):
        session = mcp.McpSession()
        session.initialized = True
        session.read_calls = mcp.MAX_READS
        request = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
            "name": "native_file_search", "arguments": {"project": "hermes", "query": "safe",
            "mode": "names", "relative_root": ""}}}
        with patch.object(search, "search") as invoke:
            response = session.handle(request)
        self.assertTrue(response["result"]["isError"])
        invoke.assert_not_called()


def load_tests(loader, tests, pattern):
    return tests if os.name == "nt" else unittest.TestSuite()
