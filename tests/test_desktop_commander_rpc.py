"""MCP probe contract: no onboarding, bounded stage diagnostics, no raw stderr leaks."""
from contextlib import redirect_stderr
from io import StringIO
import json
from queue import Queue
import unittest
from unittest.mock import patch

from control_center import desktop_commander as dc


class FakeOutput:
    def __init__(self, responses, stderr_text=""):
        self._responses = responses
        self.events = Queue()
        self.stderr = stderr_text

    def __iter__(self):
        while True:
            data = self.events.get()
            if data is None:
                return
            yield data


class FakeInput:
    def __init__(self, child):
        self.child = child
        self.buffer = ""

    def write(self, data):
        self.buffer += data

    def flush(self):
        for line in self.buffer.splitlines():
            item = json.loads(line)
            if "id" in item and self.child.respond:
                key = item["id"]
                value = {"id": key, "jsonrpc": "2.0", "result": (
                    {"tools": [{"name": "read_file"}, {"name": "list_directory"}]}
                    if key == 2 else {"protocolVersion": "2025-03-26", "capabilities": {}})}
                self.child.stdout.events.put(json.dumps(value) + "\n")
        self.buffer = ""

    def close(self):
        pass


class FakeProcess:
    def __init__(self, respond=True, diagnostics=""):
        self.respond = respond
        self.stdout = FakeOutput(None)
        self.stderr = iter([diagnostics]) if diagnostics else iter(())
        self.stdin = FakeInput(self)
        self.stopped = False

    def poll(self):
        return 0 if self.stopped else None

    def terminate(self):
        self.stopped = True
        self.stdout.events.put(None)

    def kill(self):
        self.terminate()

    def wait(self, timeout=None):
        return 0


class LocalRPCContracts(unittest.TestCase):
    def test_local_only_no_onboarding_and_tool_list(self):
        proc = FakeProcess()
        with patch("control_center.desktop_commander.subprocess.Popen", return_value=proc) as popen:
            result = dc.query_mcp(dc.LOCAL_COMMAND, timeout=5)
        self.assertEqual(result["available_tools"], ["read_file", "list_directory"])
        self.assertEqual(popen.call_args.args[0][-1], "--no-onboarding")
        self.assertEqual(popen.call_args.kwargs["stderr"], dc.subprocess.PIPE)
        self.assertEqual(popen.call_args.kwargs["stdin"], dc.subprocess.PIPE)

    def test_timeout_classification_hides_stderr_payload(self):
        secret = "SECRET_PASSWORD_DO_NOT_ECHO"
        proc = FakeProcess(respond=False, diagnostics="EACCES: permission denied " + secret)
        with patch("control_center.desktop_commander.subprocess.Popen", return_value=proc):
            with self.assertRaises(dc.CommanderError) as err:
                dc.query_mcp(dc.LOCAL_COMMAND, timeout=1)
        self.assertIn("local_initialize_timeout:permissions", str(err.exception))
        self.assertNotIn(secret, str(err.exception))

    def test_cli_probe_error_no_traceback(self):
        out = StringIO()
        with patch("sys.argv", ["desktop_commander", "--probe-local"]):
            with patch("control_center.desktop_commander.query_mcp",
                       side_effect=dc.CommanderError("local_initialize_timeout:no_classified_stderr")):
                with redirect_stderr(out), self.assertRaises(SystemExit) as ctx:
                    dc.main()
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("LOCAL_MCP_PROBE=FAILED", out.getvalue())
        self.assertNotIn("Traceback", out.getvalue())


if __name__ == "__main__":
    unittest.main()
