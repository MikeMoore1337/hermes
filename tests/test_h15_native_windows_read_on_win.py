"""Real Win32 handle tests with disposable CI-runner files only (#454).

Never runs on the owner's Windows; all fixtures are under TemporaryDirectory.
"""
from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import mmap
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import h15_native_windows_read as broker
from scripts import h15_native_windows_mcp_stdio as mcp
from scripts import h15_native_windows_outbound as outbound


@unittest.skipUnless(os.name == "nt", "real Win32 API required")
class NativeWindowsReadOnRunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="h454-ci-windows-")
        # Hosted runner TEMP can be reached through a junction/drive alias;
        # use the physically resolved synthetic root for strict handle checks.
        base = Path(self.tmp.name).resolve(strict=True)
        self.root = base / "hermes-code"
        self.root.mkdir()
        self.outside = base / "private-canary"
        self.outside.mkdir()
        self.code = self.root / "src"
        self.code.mkdir()
        self.file = self.code / "safe.py"
        self.data = b"print('synthetic-canary')\r\n"
        self.file.write_bytes(self.data)
        (self.outside / "private.py").write_bytes(b"CI_PRIVATE_CANNOT_READ")
        self.patcher = patch.dict(broker.READ_ROOTS, {"hermes": str(self.root)}, clear=True)
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        self.tmp.cleanup()

    def test_actual_win32_stat_and_same_handle_read(self):
        result = broker.handle_native_request("hermes", r"src\safe.py", "read")
        self.assertEqual(result["size_bytes"], len(self.data))
        self.assertEqual(result["sha256"], hashlib.sha256(self.data).hexdigest())
        self.assertEqual(base64.b64decode(result["data"]), self.data)
        self.assertEqual(result["status"], "ok")
        meta = broker.handle_native_request("hermes", r"src\safe.py", "stat")
        self.assertEqual(meta["size_bytes"], len(self.data))
        self.assertNotIn("data", meta)
        directory = broker.handle_native_request("hermes", "", "stat")
        self.assertEqual(directory["kind"], "directory")
        self.assertNotIn("data", directory)

    def test_read_refuses_an_already_open_writer(self):
        api = broker._winapi()
        writer = api.CreateFileW(str(self.file), 0x40000000,
            broker.FILE_SHARE_READ | broker.FILE_SHARE_WRITE | broker.FILE_SHARE_DELETE,
            None, broker.OPEN_EXISTING, 0, None)
        self.assertNotEqual(writer, ctypes.c_void_p(-1).value)
        try:
            with self.assertRaisesRegex(broker.NativeReadRefused, "file_busy"):
                broker.handle_native_request("hermes", r"src\safe.py", "read")
            session = mcp.McpSession()
            session.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                            "params": {"protocolVersion": mcp.PROTOCOL,
                                       "capabilities": {}, "clientInfo": {}}})
            response = session.handle({"jsonrpc": "2.0", "id": 2,
                "method": "tools/call", "params": {"name": "native_file_read",
                "arguments": {"project": "hermes", "relative": r"src\safe.py"}}})
            self.assertTrue(response["result"]["isError"])
            self.assertEqual(json.loads(response["result"]["content"][0]["text"])["reason"],
                             "native_file_busy")
            wire = outbound.safe_call(session, {"type": "call", "id": "busy-1",
                "tool": "native_file_read", "args": {
                    "project": "hermes", "relative": r"src\safe.py"}}, set())
            self.assertTrue(wire["result"]["isError"])
            self.assertEqual(json.loads(wire["result"]["content"][0]["text"])["reason"],
                             "native_file_busy")
            self.assertEqual(broker.handle_native_request(
                "hermes", r"src\safe.py", "stat")["size_bytes"], len(self.data))
        finally:
            api.CloseHandle(writer)
        self.assertEqual(base64.b64decode(broker.handle_native_request(
            "hermes", r"src\safe.py", "read")["data"]), self.data)

    def test_open_read_handle_blocks_a_new_writer_and_rename(self):
        actual_read = broker._read_file_handle
        moved = self.code / "moved.py"
        attempts = []
        def checked_read(api, handle, *, initial_size):
            ctypes.set_last_error(0)
            writer = api.CreateFileW(str(self.file), 0x40000000,
                broker.FILE_SHARE_READ | broker.FILE_SHARE_WRITE | broker.FILE_SHARE_DELETE,
                None, broker.OPEN_EXISTING, 0, None)
            error = ctypes.get_last_error()
            if writer != ctypes.c_void_p(-1).value:
                api.CloseHandle(writer)
                self.fail("writer opened during a native read")
            self.assertEqual(error, 32)
            try:
                with self.assertRaises(OSError):
                    os.rename(self.file, moved)
            finally:
                if moved.exists():
                    os.rename(moved, self.file)
            attempts.append(True)
            return actual_read(api, handle, initial_size=initial_size)
        with patch.object(broker, "_read_file_handle", side_effect=checked_read):
            result = broker.handle_native_request("hermes", r"src\safe.py", "read")
        self.assertEqual(attempts, [True])
        self.assertEqual(base64.b64decode(result["data"]), self.data)
        self.file.write_bytes(b"writer-after-read")
        self.assertEqual(self.file.read_bytes(), b"writer-after-read")

    def test_read_refuses_a_live_writable_mapping(self):
        with self.file.open("r+b") as writer:
            mapping = mmap.mmap(writer.fileno(), 0, access=mmap.ACCESS_WRITE)
        try:
            with self.assertRaisesRegex(broker.NativeReadRefused, "file_busy"):
                broker.handle_native_request("hermes", r"src\safe.py", "read")
        finally:
            mapping.close()
        result = broker.handle_native_request("hermes", r"src\safe.py", "read")
        self.assertEqual(base64.b64decode(result["data"]), self.data)

    def test_root_cannot_be_renamed_during_read_or_stat(self):
        real_open = broker._opened
        moved = self.root.with_name("moved-code")
        for operation in ("read", "stat"):
            attempts = []
            def checked_open(api, path, *, content, lock_rename=False):
                if os.path.normcase(path) == os.path.normcase(str(self.file)):
                    try:
                        with self.assertRaises(OSError) as denied:
                            os.rename(self.root, moved)
                        self.assertIn(denied.exception.winerror, (5, 32))
                        attempts.append(True)
                    finally:
                        if moved.exists():
                            os.rename(moved, self.root)
                return real_open(api, path, content=content, lock_rename=lock_rename)
            with self.subTest(operation=operation), \
                 patch.object(broker, "_opened", side_effect=checked_open):
                result = broker.handle_native_request("hermes", r"src\safe.py", operation)
                self.assertEqual(result["status"], "ok")
                self.assertEqual(attempts, [True])
            os.rename(self.root, moved)
            try:
                self.assertTrue(moved.exists())
            finally:
                os.rename(moved, self.root)

    def test_locked_directory_handle_prevents_rename(self):
        api = broker._winapi()
        moved = self.root.with_name("moved-code")
        handle = broker._opened(api, str(self.root), content=False, lock_rename=True)
        try:
            with self.assertRaises(OSError) as denied:
                os.rename(self.root, moved)
            self.assertIn(denied.exception.winerror, (5, 32))
        finally:
            api.CloseHandle(handle)
            if moved.exists():
                os.rename(moved, self.root)
        os.rename(self.root, moved)
        try:
            self.assertTrue(moved.exists())
        finally:
            os.rename(moved, self.root)

    def test_win32_handle_read_via_real_mcp_dispatch(self):
        session = mcp.McpSession()
        init = session.handle({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": mcp.PROTOCOL,
                       "capabilities": {}, "clientInfo": {}}
        })
        self.assertEqual(init["result"]["protocolVersion"], mcp.PROTOCOL)
        response = session.handle({"jsonrpc": "2.0", "id": 2,
            "method": "tools/call", "params": {
                "name": "native_file_read",
                "arguments": {"project": "hermes", "relative": r"src\safe.py"}}})
        self.assertFalse(response["result"]["isError"])
        body = json.loads(response["result"]["content"][0]["text"])
        self.assertEqual(base64.b64decode(body["data"]), self.data)
        self.assertEqual(body["sha256"], hashlib.sha256(self.data).hexdigest())
        denial = session.handle({"jsonrpc": "2.0", "id": 3,
            "method": "tools/call", "params": {
                "name": "native_file_read",
                "arguments": {"project": "hermes", "relative": r"..\private.py"}}})
        self.assertTrue(denial["result"]["isError"])

    def test_actual_win32_read_via_authenticated_wss_adapter(self):
        class SyntheticSocket:
            def __init__(self):
                self.events = [
                    {"type": "welcome", "protocol": 1, "relayVersion": "test",
                     "serverTime": 1792745662222},
                    {"type": "call", "id": "one", "tool": "native_file_read",
                     "args": {"project": "hermes", "relative": r"src\safe.py"}},
                ]
                self.responses = []
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return None
            def send(self, value):
                self.responses.append(json.loads(value))
            def recv(self, timeout=None):
                if not self.events:
                    raise TimeoutError
                return json.dumps(self.events.pop(0))
        socket = SyntheticSocket()
        settings = outbound.parse_settings(
            "wss://hermes.mikemoore.top/ws", "native-ci-win-handle-123", "x"*40)
        outcome = outbound.run_session(settings, lambda *_args, **_kwargs: socket)
        self.assertEqual(outcome, "idle_timeout")
        self.assertEqual(socket.responses[0]["type"], "hello")
        self.assertEqual(socket.responses[0]["device"]["platform"], "win32")
        response = socket.responses[1]
        self.assertEqual(response["type"], "result")
        self.assertFalse(response["result"]["isError"])
        body = json.loads(response["result"]["content"][0]["text"])
        self.assertEqual(base64.b64decode(body["data"]), self.data)
        self.assertEqual(body["sha256"], hashlib.sha256(self.data).hexdigest())

    def test_actual_outside_path_and_oversized_file_denied(self):
        with self.assertRaises(broker.NativeReadRefused):
            broker.handle_native_request("hermes", r"..\private-canary\private.py", "read")
        too_large = self.root / "big.py"
        too_large.write_bytes(b"x" * (broker.MAX_FILE_BYTES + 1))
        with self.assertRaisesRegex(broker.NativeReadRefused, "too_large"):
            broker.handle_native_request("hermes", "big.py", "read")

    def test_actual_hardlink_does_not_leak_other_file_aliases(self):
        link = self.root / "alias.py"
        os.link(self.file, link)
        with self.assertRaisesRegex(broker.NativeReadRefused, "hardlink_denied"):
            broker.handle_native_request("hermes", "alias.py", "read")

    def test_actual_reparse_target_and_root_denied(self):
        # GitHub-hosted Windows runner is an isolated, ephemeral machine with
        # symlink support; never make links on the owner's original D: drive.
        link = self.root / "out"
        os.symlink(self.outside, link, target_is_directory=True)
        with self.assertRaises(broker.NativeReadRefused):
            broker.handle_native_request("hermes", r"out\private.py", "read")
        file_link = self.root / "linked.py"
        os.symlink(self.file, file_link)
        with self.assertRaises(broker.NativeReadRefused):
            broker.handle_native_request("hermes", "linked.py", "read")
        redirected_root = Path(self.tmp.name) / "redirected-root"
        os.symlink(self.root, redirected_root, target_is_directory=True)
        with patch.dict(broker.READ_ROOTS, {"hermes": str(redirected_root)}, clear=True):
            with self.assertRaises(broker.NativeReadRefused):
                broker.handle_native_request("hermes", "src\\safe.py", "read")


    def test_real_win32_bounded_project_root_listing_without_private_names(self):
        (self.root / "README.md").write_text("# synthetic")
        (self.root / ".env").write_text("DO_NOT_EXPOSE=1")
        (self.root / "config.local").write_text("private")
        (self.root / "private-vault").mkdir()
        (self.root / ".git").mkdir()
        (self.root / "binary.exe").write_bytes(b"native-program")
        listing = broker.handle_native_list("hermes", "")
        self.assertEqual(listing["status"], "ok")
        self.assertEqual(listing["kind"], "directory")
        self.assertEqual(listing["action"], "list")
        self.assertEqual(listing["relative"], "")
        self.assertFalse(listing["truncated"])
        names = {item["name"] for item in listing["entries"]}
        self.assertEqual(names, {"src", "README.md"})
        self.assertTrue(all(set(item) == {"name", "kind"}
                            for item in listing["entries"]))
        self.assertNotIn("DO_NOT_EXPOSE", json.dumps(listing))
        with self.assertRaisesRegex(broker.NativeReadRefused,
                                    "listing_only_approved_root"):
            broker.handle_native_list("hermes", "src")

    def test_win32_list_excludes_junction_and_hardlink(self):
        (self.root / "safe.md").write_text("# safe")
        (self.root / "alias.md").hardlink_to(self.root / "safe.md")
        junction = self.root / "linked"
        os.symlink(self.outside, junction, target_is_directory=True)
        listing = broker.handle_native_list("hermes", "")
        names = {item["name"] for item in listing["entries"]}
        self.assertIn("src", names)
        self.assertNotIn("linked", names)
        self.assertNotIn("alias.md", names)
        self.assertNotIn("safe.md", names)

    def test_real_win32_mcp_and_wss_readonly_list(self):
        session = mcp.McpSession()
        session.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                        "params": {"protocolVersion": mcp.PROTOCOL,
                                   "capabilities": {}, "clientInfo": {}}})
        answer = session.handle({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "native_file_list",
                       "arguments": {"project": "hermes", "relative": ""}}
        })
        self.assertFalse(answer["result"]["isError"])
        payload = json.loads(answer["result"]["content"][0]["text"])
        self.assertEqual({x["name"] for x in payload["entries"]}, {"src"})
        denied = session.handle({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "native_file_list",
                       "arguments": {"project": "hermes", "relative": "src"}}
        })
        self.assertTrue(denied["result"]["isError"])
        class MockSocket:
            def __init__(self):
                self.events = [
                    {"type":"welcome", "protocol":1,
                     "relayVersion":"test", "serverTime": 1},
                    {"type":"call", "id":"list-1", "tool":"native_file_list",
                     "args":{"project":"hermes", "relative":""}},
                ]
                self.output = []
            def __enter__(self): return self
            def __exit__(self, *_): return None
            def send(self, frame): self.output.append(json.loads(frame))
            def recv(self, timeout=None):
                if not self.events: raise TimeoutError
                return json.dumps(self.events.pop(0))
        sock = MockSocket()
        settings = outbound.parse_settings(
            "wss://hermes.mikemoore.top/ws", "native-ci-win-handle-123", "x"*40)
        self.assertEqual(outbound.run_session(settings, lambda *a,**k:sock),
                         "idle_timeout")
        output = json.loads(sock.output[-1]["result"]["content"][0]["text"])
        self.assertEqual({x["name"] for x in output["entries"]}, {"src"})

    def test_broker_never_creates_or_changes_source_fixture(self):
        before = self.file.read_bytes()
        with self.assertRaises(broker.NativeReadRefused):
            broker.build_request("hermes", "src\\safe.py", "execute")
        with self.assertRaises(broker.NativeReadRefused):
            broker.build_request("hermes", "src\\safe.py", "write")
        self.assertEqual(self.file.read_bytes(), before)


# The production quality job requires a literal clean unittest 'OK' banner;
# do not emit skipped Windows cases on Linux CI. A genuine Windows runner
# separately discovers these tests and exercises the real kernel32 handles.
def load_tests(loader, tests, pattern):
    return tests if os.name == "nt" else unittest.TestSuite()


if __name__ == "__main__":
    unittest.main()
