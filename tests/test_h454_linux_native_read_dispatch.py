"""Hermes #454: original Linux local read dispatcher on disposable files.

Tests prove only local source-code contract with actual Linux openat2
handles. No agent is registered in Hermes MCP, no original owner host
is mounted, and no production process/credential is accessed.
"""
from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import platform
import sys
import tempfile
import unittest
from unittest.mock import patch

from device_fabric.linux_native_read_dispatch import (
    LinuxOriginalReadDispatcher, NativeLinuxReadDenied,
    MAX_SESSION_READS, MAX_SESSION_SEARCHES, MAX_SESSION_CALLS,
    parse_call, READ, LIST, STAT, SEARCH,
)
from device_fabric.linux_native_files import LinuxNativeFiles

DEVICE = "h454-linux-read-ci"


def frame(tool: str, *, uid: str = "request-001", project: str = "hermes",
          relative: str = "README.md", query: str = "TODO",
          mode: str = "content", relative_root: str = "") -> bytes:
    args = ({"project": project, "relative": relative}
            if tool in (READ, LIST, STAT) else
            {"project": project, "query": query, "mode": mode,
             "relative_root": relative_root})
    return json.dumps({"type": "call", "id": uid, "tool": tool,
                       "args": args}, separators=(",", ":")).encode()


class RemoteCallParsingContracts(unittest.TestCase):
    def test_exact_read_and_search_schema(self):
        request, tool, args = parse_call(frame(READ))
        self.assertEqual((request, tool, args["project"]),
                         ("request-001", READ, "hermes"))
        request, tool, args = parse_call(frame(SEARCH))
        self.assertEqual(args["query"], "TODO")

    def test_no_unbounded_external_or_elevating_tool(self):
        for bad in (
            b"", b"[]", b"{}", b"x" * 4097,
            frame("start_process"), frame("write_file"),
            frame("native_file_delete"), frame("native_file_move"),
            frame("git_push"),
            frame(READ, relative="../secret"),
            frame(READ, relative="vault/password.md"),
            frame(READ, relative=".env"),
            frame(READ, relative="/etc/passwd"),
            frame(READ, relative=""),
            frame(READ, uid=""),
        ):
            with self.subTest(raw=bad[:42]), self.assertRaisesRegex(
                    NativeLinuxReadDenied, "^native_linux_read_denied$"):
                parse_call(bad)

    def test_duplicate_and_extra_request_fields_denied(self):
        valid = json.loads(frame(READ))
        for bad in (
            b'{"type":"call","type":"call","id":"x","tool":"native_file_read","args":{"project":"hermes","relative":"README.md"}}',
            b'{"type":"call","id":"x","tool":"native_file_read","args":{"project":"hermes","relative":"README.md","relative":"README.md"}}',
            json.dumps({**valid, "owner_approved": True}).encode(),
            json.dumps({**valid, "args": {**valid["args"],
                                        "device_id": DEVICE}}).encode(),
            json.dumps({**valid, "args": {**valid["args"],
                                        "approved": True}}).encode(),
            json.dumps({**valid, "id": True}).encode(),
        ):
            with self.subTest(raw=bad[:40]), self.assertRaises(NativeLinuxReadDenied):
                parse_call(bad)


@unittest.skipUnless(
    sys.platform == "linux" and platform.machine().lower() in ("x86_64", "aarch64"),
    "actual Linux openat2 fixtures only")
class OriginalLinuxReadDispatcherContracts(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="h454-native-read-dispatch-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name) / "original-fixture"
        self.root.mkdir()
        (self.root / "docs").mkdir()
        (self.root / "README.md").write_bytes(b"# Public\nTODO safe\n")
        (self.root / "docs" / "notes.md").write_text(
            "hello\nTODO second\n", encoding="utf-8")
        (self.root / ".env").write_text("DO_NOT_DISCLOSE", encoding="utf-8")
        (self.root / ".git").mkdir()
        (self.root / ".git" / "config").write_text("SECRET", encoding="utf-8")
        self.outside = Path(tmp.name) / "outside.txt"
        self.outside.write_text("SECRET", encoding="utf-8")
        (self.root / "redirect.md").symlink_to(self.outside)
        self.files = LinuxNativeFiles(root=self.root, project="hermes")
        self.addCleanup(self.files.close)
        self.dispatcher = LinuxOriginalReadDispatcher(
            device_id=DEVICE, local_roots={"hermes": self.files},
            is_device_revoked=lambda: False)

    def test_actual_kernel_stat_and_read_sha256(self):
        info = self.dispatcher.call(frame(STAT, uid="stat-1", relative="README.md"))
        self.assertEqual(info["result"]["kind"], "file")
        self.assertEqual(info["result"]["size_bytes"], len(b"# Public\nTODO safe\n"))
        read = self.dispatcher.call(frame(READ, uid="read-1"))
        data = base64.b64decode(read["result"]["data"])
        self.assertEqual(data, b"# Public\nTODO safe\n")
        self.assertEqual(read["result"]["sha256"],
                         hashlib.sha256(data).hexdigest())
        self.assertNotIn(str(self.root), str(read))

    def test_kernel_safe_root_and_nested_directory_listing(self):
        root = self.dispatcher.call(frame(LIST, uid="list-root", relative=""))
        names = {e["name"] for e in root["result"]["entries"]}
        self.assertIn("docs", names)
        self.assertIn("README.md", names)
        self.assertNotIn(".env", names)
        self.assertNotIn(".git", names)
        self.assertNotIn("redirect.md", names)
        nested = self.dispatcher.call(frame(LIST, uid="list-nested", relative="docs"))
        self.assertEqual(nested["result"]["entries"],
                         [{"name":"notes.md", "kind":"file"}])

    def test_name_and_content_search_not_snippets(self):
        names = self.dispatcher.call(frame(
            SEARCH, uid="search-name", query="README", mode="names"))
        self.assertEqual(names["result"]["matches"],
                         [{"path":"README.md", "kind":"file"}])
        content = self.dispatcher.call(frame(
            SEARCH, uid="search-text", query="todo", mode="content"))
        self.assertEqual(content["result"]["matches"],
                         [{"path":"README.md", "line":2},
                          {"path":"docs/notes.md", "line":2}])
        self.assertNotIn("TODO second", str(content))
        self.assertNotIn("SECRET", str(content))

    def test_symlink_secret_traversal_and_wrong_project_denied(self):
        bad = (
            frame(READ, uid="symlink", relative="redirect.md"),
            frame(READ, uid="secret", relative=".env"),
            frame(READ, uid="git", relative=".git/config"),
            frame(READ, uid="escape", relative="../outside.txt"),
            frame(READ, uid="foreign", project="financial-horizon"),
        )
        for raw in bad:
            with self.subTest(raw=raw[:35]), self.assertRaisesRegex(
                    NativeLinuxReadDenied, "^native_linux_read_denied$"):
                self.dispatcher.call(raw)
        self.assertEqual(self.outside.read_text(), "SECRET")

    def test_invalid_remote_approval_boolean_never_reaches_files(self):
        bad = json.loads(frame(READ))
        bad["owner_approved"] = True
        with patch.object(self.files, "read_file") as reader:
            with self.assertRaises(NativeLinuxReadDenied):
                self.dispatcher.call(json.dumps(bad).encode())
            reader.assert_not_called()

    def test_revocation_before_or_after_native_read(self):
        for state, label in (([True], "before"), ([False, True], "after")):
            with self.subTest(position=label):
                events = iter(state)
                broker = LinuxOriginalReadDispatcher(
                    device_id=DEVICE, local_roots={"hermes":self.files},
                    is_device_revoked=lambda: next(events))
                with self.assertRaises(NativeLinuxReadDenied):
                    broker.call(frame(READ, uid=label))
        self.assertEqual((self.root / "README.md").read_bytes(),
                         b"# Public\nTODO safe\n")

    def test_duplicate_id_fails_closed_even_after_previous_success(self):
        wire = frame(READ, uid="same-id")
        self.dispatcher.call(wire)
        with self.assertRaises(NativeLinuxReadDenied):
            self.dispatcher.call(wire)

    def test_concurrent_duplicate_id_only_one_read(self):
        wire = frame(READ, uid="same-concurrent-id")
        def attempt(_):
            try:
                self.dispatcher.call(wire)
                return "pass"
            except NativeLinuxReadDenied:
                return "denied"
        with ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(attempt, range(20)))
        self.assertEqual(outcomes.count("pass"), 1)
        self.assertEqual(outcomes.count("denied"), 19)

    def test_read_rate_and_search_budgets_enforced(self):
        for i in range(MAX_SESSION_READS):
            self.dispatcher.call(frame(READ, uid=f"read-{i}"))
        with self.assertRaises(NativeLinuxReadDenied):
            self.dispatcher.call(frame(READ, uid="read-overflow"))
        for i in range(MAX_SESSION_SEARCHES):
            self.dispatcher.call(frame(SEARCH, uid=f"search-{i}", query="TODO"))
        with self.assertRaises(NativeLinuxReadDenied):
            self.dispatcher.call(frame(SEARCH, uid="search-overflow", query="TODO"))

    def test_total_call_budget_enforced(self):
        for i in range(MAX_SESSION_CALLS):
            self.dispatcher.call(frame(STAT, uid=f"call-{i}"))
        with self.assertRaises(NativeLinuxReadDenied):
            self.dispatcher.call(frame(STAT, uid="call-overflow"))

    def test_malformed_native_result_cannot_leak_extra_fields(self):
        invalid = {
            "status": "ok", "project": "hermes",
            "relative": "README.md", "action": "read", "kind": "file",
            "size_bytes": 4, "encoding": "base64", "sha256": "0"*64,
            "data": base64.b64encode(b"evil").decode(),
            "absolute_host_path": "/root/super-secret",
        }
        with patch.object(self.files, "read_file", return_value=invalid):
            with self.assertRaises(NativeLinuxReadDenied) as caught:
                self.dispatcher.call(frame(READ, uid="bad-native-result"))
        self.assertNotIn("super-secret", str(caught.exception))

    def test_mismatched_native_data_integrity_denied(self):
        original = self.files.read_file("README.md")
        corrupt = dict(original, sha256="1" * 64)
        with patch.object(self.files, "read_file", return_value=corrupt):
            with self.assertRaises(NativeLinuxReadDenied):
                self.dispatcher.call(frame(READ, uid="bad-sha"))

    def test_corrupt_nested_search_result_denied(self):
        fake = {
            "status": "ok", "project": "hermes",
            "relative_root": "", "mode": "content", "truncated": False,
            "entries_scanned": 1, "bytes_scanned": 2,
            "matches":[{"path":"/etc/shadow","line":1}],
        }
        with patch("device_fabric.linux_native_read_dispatch.LinuxNativeSearch.search",
                   return_value=fake):
            with self.assertRaises(NativeLinuxReadDenied):
                self.dispatcher.call(frame(SEARCH, uid="search-malformed"))

    def test_wrong_locally_configured_project_or_closed_root_denied(self):
        with self.assertRaises(NativeLinuxReadDenied):
            LinuxOriginalReadDispatcher(
                device_id=DEVICE, local_roots={"financial-horizon":self.files},
                is_device_revoked=lambda:False)
        self.files.close()
        with self.assertRaises(NativeLinuxReadDenied):
            self.dispatcher.call(frame(STAT, uid="after-close"))

    def test_no_subprocess_invocations_from_adapter(self):
        with patch("subprocess.Popen", side_effect=AssertionError("not allowed")):
            response = self.dispatcher.call(frame(STAT, uid="no-shell"))
        self.assertEqual(response["result"]["kind"], "file")


if __name__ == "__main__":
    unittest.main()
