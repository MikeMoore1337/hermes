"""Offline personal Commander session and durable call-claim contracts."""
import json
import unittest

from device_fabric import windows_personal_commander_transport as transport

DEVICE = "h454-win-personal-" + "a" * 32
TOKEN = "brc_dev_" + "b" * 64
TOOLS = [{"name": name, "description": "synthetic", "inputSchema": {"type": "object"}}
         for name in sorted(transport.TOOLS)]
WELCOME = {"type": "welcome", "protocol": 1, "relayVersion": "test", "serverTime": 1}


class Socket:
    def __init__(self, frames):
        self.frames = list(frames)
        self.sent = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def send(self, data):
        self.sent.append(json.loads(data))

    def recv(self, *, timeout):
        if not self.frames:
            raise TimeoutError()
        return json.dumps(self.frames.pop(0), separators=(",", ":"))


class PersonalTransportTests(unittest.TestCase):
    def run_session(self, frames, *, active=lambda: True, claim=lambda _id: True,
                    dispatch=lambda name, args: {"content": [{"type": "text", "text": name}], "isError": False},
                    device=DEVICE):
        socket = Socket(frames)
        def connector(url, **options):
            self.assertEqual(url, transport.ENDPOINT)
            self.assertEqual(options["additional_headers"]["Authorization"], "Bearer " + TOKEN)
            return socket
        outcome = transport.run_session(device_id=device, bearer=TOKEN, tools=TOOLS,
            connector=connector, dispatch=dispatch, is_active=active, claim_call=claim)
        return outcome, socket

    def test_claim_precedes_write_and_reply_is_sent_over_the_same_session(self):
        calls = []
        def claim(ident):
            calls.append(("claim", ident))
            return True
        def dispatch(name, args):
            calls.append(("dispatch", name))
            return {"content": [{"type": "text", "text": "done"}], "isError": False}
        outcome, socket = self.run_session([WELCOME, {"type": "ping", "ts": 3},
            {"type": "call", "id": "call-1", "tool": "write_file", "args": {"path": "synthetic"}}],
            claim=claim, dispatch=dispatch)
        self.assertEqual(outcome, "idle_timeout")
        self.assertEqual(calls, [("claim", "call-1"), ("dispatch", "write_file")])
        self.assertEqual(socket.sent[0]["device"]["deviceId"], DEVICE)
        self.assertEqual(socket.sent[1], {"type": "pong", "ts": 3})
        self.assertEqual(socket.sent[2]["result"]["content"][0]["text"], "done")

    def test_read_only_identity_replay_or_revocation_cannot_dispatch(self):
        frame = {"type": "call", "id": "call-1", "tool": "start_process", "args": {"command": "synthetic"}}
        called = []
        def dispatch(*_args):
            called.append(True)
            return {"content": []}
        for kwargs in ({"device": "h454-win-native-" + "a" * 32},
                       {"claim": lambda _id: False}, {"active": lambda: False}):
            with self.subTest(kwargs=tuple(kwargs)), self.assertRaises(transport.PersonalTransportDenied):
                self.run_session([WELCOME, frame], dispatch=dispatch, **kwargs)
        self.assertEqual(called, [])

    def test_repeated_id_and_unknown_tool_are_not_executed(self):
        frame = {"type": "call", "id": "call-1", "tool": "write_file", "args": {}}
        called = []
        def dispatch(*_args):
            called.append(True)
            return {"content": []}
        with self.assertRaises(transport.PersonalTransportDenied):
            self.run_session([WELCOME, frame, frame], dispatch=dispatch)
        self.assertEqual(len(called), 1)
        with self.assertRaises(transport.PersonalTransportDenied):
            self.run_session([WELCOME, {**frame, "tool": "set_config_value"}], dispatch=dispatch)
        self.assertEqual(len(called), 1)

    def test_import_tool_is_refused_when_worker_does_not_advertise_it(self):
        socket = Socket([WELCOME, {'type': 'call', 'id': 'call-import',
                                   'tool': 'import_public_project', 'args': {'action': 'start'}}])
        base = [tool for tool in TOOLS if tool['name'] != 'import_public_project']
        calls = []
        with self.assertRaises(transport.PersonalTransportDenied):
            transport.run_session(device_id=DEVICE, bearer=TOKEN, tools=base,
                connector=lambda *_a, **_k: socket, dispatch=lambda *_a: calls.append(True),
                is_active=lambda: True, claim_call=lambda _id: True)
        self.assertEqual(calls, [])

    def test_bearer_never_returns_in_an_agent_result(self):
        frame = {"type": "call", "id": "call-1", "tool": "read_file", "args": {}}
        with self.assertRaises(transport.PersonalTransportDenied) as error:
            self.run_session([WELCOME, frame], dispatch=lambda *_: {
                "content": [{"type": "text", "text": TOKEN}]})
        self.assertNotIn(TOKEN, str(error.exception))


if __name__ == "__main__":
    unittest.main()
