"""Framing and failure behavior for the isolated local adapter channel."""
import json
import unittest
from unittest.mock import patch

from device_fabric import windows_personal_appcontainer_pipe as channel
from device_fabric.windows_personal_commander_pipe import PersonalPipeDenied
from device_fabric.windows_personal_commander_transport import ADAPTER_TOOLS as TOOLS


class Terminal:
    def __init__(self):
        self.incoming = bytearray()
        self.outgoing = bytearray()
        self.sizes = []
        self.closed = False
        self.bad_reply = False
        self.frames = []

    def write(self, data, *, timeout):
        self.sizes.append(len(data))
        self.incoming.extend(data)
        while b"\n" in self.incoming:
            line, _, rest = self.incoming.partition(b"\n")
            self.incoming[:] = rest
            frame = json.loads(line)
            self.frames.append(frame)
            if frame["type"] == "initialize":
                response = {"type": "ready", "tools": [{"name": name} for name in sorted(TOOLS)]}
            else:
                response = {"type": "result", "id": "wrong" if self.bad_reply else frame["id"],
                            "result": {"content": [{"type": "text", "text": "synthetic"}]}}
            self.outgoing.extend(json.dumps(response).encode("ascii") + b"\n")

    def read(self):
        data = bytes(self.outgoing[:17])
        del self.outgoing[:17]
        return data

    def poll(self):
        return 0 if self.closed else None

    def close(self):
        self.closed = True


class PersonalAppContainerPipeTests(unittest.TestCase):
    def setUp(self):
        self.terminal = Terminal()
        self.patch = patch.object(channel, "AppContainerTerminal", Terminal)
        self.patch.start()
        self.pipe = channel.PersonalAppContainerPipe(self.terminal, ["synthetic"], timeout=1)

    def tearDown(self):
        self.pipe.close()
        self.patch.stop()

    def test_large_frame_is_chunked_and_matching_reply_is_returned(self):
        result = self.pipe.dispatch("write_file", {"path": "synthetic", "content": "x" * 9000})
        self.assertEqual(result["content"][0]["text"], "synthetic")
        self.assertGreater(len(self.terminal.sizes), 2)
        self.assertLessEqual(max(self.terminal.sizes), channel.MAX_WRITE)
        self.assertEqual(self.terminal.frames[-1]["args"]["content"], "x" * 9000)

    def test_multiple_roots_are_forwarded_with_the_same_bound(self):
        terminal = Terminal()
        roots = [f'root-{i}' for i in range(16)]
        pipe = channel.PersonalAppContainerPipe(terminal, roots, timeout=1)
        self.assertEqual(terminal.frames[0]['roots'], roots)
        pipe.close()
        with self.assertRaises(PersonalPipeDenied):
            channel.PersonalAppContainerPipe(Terminal(), roots + ['extra'], timeout=1)

    def test_mismatched_reply_closes_channel_and_never_retries(self):
        self.terminal.bad_reply = True
        with self.assertRaises(PersonalPipeDenied):
            self.pipe.dispatch("write_file", {"path": "synthetic", "content": "x"})
        self.assertTrue(self.terminal.closed)
        self.assertEqual(len(self.terminal.frames), 2)
        with self.assertRaises(PersonalPipeDenied):
            self.pipe.dispatch("write_file", {"path": "synthetic", "content": "x"})

    def test_oversized_frame_is_rejected_before_dispatch(self):
        with self.assertRaises(PersonalPipeDenied):
            self.pipe.dispatch("write_file", {"content": "x" * channel.MAX_FRAME})
        self.assertEqual(len(self.terminal.frames), 1)
        self.assertTrue(self.terminal.closed)


if __name__ == "__main__":
    unittest.main()
