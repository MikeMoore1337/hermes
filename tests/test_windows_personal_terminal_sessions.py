"""Terminal session behavior with disposable, deterministic process doubles."""
import unittest
import time

from device_fabric import windows_personal_terminal_sessions as sessions


class Terminal:
    next_pid = 100

    def __init__(self, _sid, _root, *, command):
        self.pid = Terminal.next_pid
        Terminal.next_pid += 1
        self.chunks = []
        self.status = None
        self.closed = False
        self.writes = []
        if command == "failed":
            self.chunks = [b"failure\n"]
            self.status = 7
        elif command == "lines":
            self.chunks = [b"first\nsecond\nthird\n"]

    def read(self):
        return self.chunks.pop(0) if self.chunks else b""

    def poll(self):
        return self.status

    def write(self, data):
        self.writes.append(data)
        self.chunks.append(b"response\n")

    def close(self):
        self.closed = True


class TerminalSessionsTests(unittest.TestCase):
    def setUp(self):
        self.created = []
        def factory(*args, **kwargs):
            terminal = Terminal(*args, **kwargs)
            self.created.append(terminal)
            return terminal
        self.broker = sessions.PersonalTerminalSessions(1, "synthetic", factory=factory, encoding="utf-8")

    def tearDown(self):
        self.broker.close()

    def start(self, command="interactive"):
        result = self.broker.dispatch("start_process", {"command": command, "timeout_ms": 0})
        self.assertFalse(result["isError"], result)
        return self.created[-1]

    def test_interaction_tracks_only_its_own_session_and_terminates_it(self):
        terminal = self.start()
        result = self.broker.dispatch("interact_with_process", {
            "pid": terminal.pid, "input": "synthetic input", "timeout_ms": 0})
        self.assertEqual(terminal.writes, [b"synthetic input\n"])
        self.assertEqual(result["content"][0]["text"], "response\n")
        self.assertTrue(self.broker.dispatch("force_terminate", {"pid": terminal.pid + 999})["isError"])
        self.assertFalse(terminal.closed)
        self.assertFalse(self.broker.dispatch("force_terminate", {"pid": terminal.pid})["isError"])
        self.assertTrue(terminal.closed)
        self.assertTrue(self.broker.dispatch("read_process_output", {"pid": terminal.pid})["isError"])

    def test_nonzero_exit_is_error_and_output_is_not_duplicated(self):
        result = self.broker.dispatch("start_process", {"command": "failed", "timeout_ms": 0})
        self.assertTrue(result["isError"])
        self.assertIn("code 7", result["content"][0]["text"])
        self.assertIn("failure", result["content"][0]["text"])
        result = self.broker.dispatch("read_process_output", {"pid": self.created[-1].pid, "timeout_ms": 0})
        self.assertTrue(result["isError"])
        self.assertNotIn("failure", result["content"][0]["text"])

    def test_pagination_and_split_utf8_do_not_lose_bytes(self):
        terminal = self.start("lines")
        page = self.broker.dispatch("read_process_output", {"pid": terminal.pid, "offset": 1, "length": 1})
        self.assertEqual(page["content"][0]["text"], "second\n")
        terminal.chunks = [b"\xd0"]
        self.broker.dispatch("read_process_output", {"pid": terminal.pid, "timeout_ms": 0})
        terminal.chunks = [b"\xb0\n"]
        result = self.broker.dispatch("read_process_output", {"pid": terminal.pid, "timeout_ms": 0})
        self.assertEqual(result["content"][0]["text"], "а\n")

    def test_session_limit_and_bad_arguments_do_not_start_extra_processes(self):
        for _ in range(sessions.MAX_SESSIONS):
            self.start()
        before = len(self.created)
        self.assertTrue(self.broker.dispatch("start_process", {"command": "x", "timeout_ms": 0})["isError"])
        self.assertTrue(self.broker.dispatch("start_process", {"command": "x", "timeout_ms": True})["isError"])
        self.assertEqual(len(self.created), before)

    def test_output_overflow_stops_session_and_can_be_cleared(self):
        terminal = self.start()
        terminal.chunks = [b"x" * 65536 for _ in range(9)]
        result = self.broker.dispatch("read_process_output", {"pid": terminal.pid, "timeout_ms": 0})
        if not result["isError"]:
            result = self.broker.dispatch("read_process_output", {"pid": terminal.pid, "timeout_ms": 0})
        self.assertTrue(result["isError"])
        self.assertTrue(terminal.closed)
        self.assertFalse(self.broker.dispatch("force_terminate", {"pid": terminal.pid})["isError"])

    def test_background_drains_output_without_a_client_read(self):
        terminal = self.start()
        terminal.chunks = [b"x" * 65536]
        session = self.broker._sessions[terminal.pid]
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            with session.lock:
                if session.bytes_seen == 65536:
                    break
            time.sleep(0.01)
        self.assertEqual(session.bytes_seen, 65536)

    def test_finished_processes_do_not_exhaust_active_session_limit(self):
        for _ in range(sessions.MAX_RETAINED + 1):
            result = self.broker.dispatch("start_process", {"command": "failed", "timeout_ms": 0})
            self.assertTrue(result["isError"])
            self.assertIn("code 7", result["content"][0]["text"])
        self.assertEqual(len(self.created), sessions.MAX_RETAINED + 1)
        self.assertTrue(self.created[0].closed)
        self.assertFalse(self.created[-1].closed)

    def test_large_line_is_returned_in_bounded_chunks_without_loss(self):
        terminal = self.start()
        terminal.chunks = [b"x" * 65536, b"y" * 34464]
        first = self.broker.dispatch("read_process_output", {"pid": terminal.pid, "timeout_ms": 0})
        second = self.broker.dispatch("read_process_output", {"pid": terminal.pid, "timeout_ms": 0})
        one = first["content"][0]["text"]
        two = second["content"][0]["text"]
        self.assertEqual(len(one), sessions.MAX_RESPONSE_CHARS)
        self.assertEqual(one + two, "x" * 65536 + "y" * 34464)

    def test_configured_windows_encoding_applies_to_input_and_output(self):
        terminal = Terminal(1, "synthetic", command="interactive")
        broker = sessions.PersonalTerminalSessions(1, "synthetic", factory=lambda *_a, **_k: terminal,
                                                   encoding="cp866")
        try:
            result = broker.dispatch("start_process", {"command": "interactive", "timeout_ms": 0})
            self.assertFalse(result["isError"])
            terminal.chunks = ["Привет\n".encode("cp866")]
            result = broker.dispatch("read_process_output", {"pid": terminal.pid, "timeout_ms": 0})
            self.assertEqual(result["content"][0]["text"], "Привет\n")
            broker.dispatch("interact_with_process", {"pid": terminal.pid, "input": "Привет", "timeout_ms": 0})
            self.assertEqual(terminal.writes[-1], "Привет\n".encode("cp866"))
        finally:
            broker.close()


if __name__ == "__main__":
    unittest.main()
