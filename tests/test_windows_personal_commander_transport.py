"""Offline personal Commander session and durable call-claim contracts."""
import json
import unittest
from unittest.mock import patch

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
                    device=DEVICE, target='windows'):
        socket = Socket(frames)
        def connector(url, **options):
            self.assertEqual(url, transport.ENDPOINT)
            self.assertEqual(options["additional_headers"]["Authorization"], "Bearer " + TOKEN)
            return socket
        outcome = transport.run_session(device_id=device, bearer=TOKEN, tools=TOOLS,
            connector=connector, dispatch=dispatch, is_active=active, claim_call=claim, target=target)
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

    def test_local_reload_occurs_only_after_result_is_sent(self):
        frame = {'type': 'call', 'id': 'call-1', 'tool': 'write_file', 'args': {}}
        socket, called = Socket([WELCOME, frame]), []
        def pending():
            called.append(len(socket.sent))
            return True
        outcome = transport.run_session(device_id=DEVICE, bearer=TOKEN, tools=TOOLS,
            connector=lambda *_a, **_k: socket, dispatch=lambda *_a: {'content': []},
            is_active=lambda: True, claim_call=lambda _id: True, reload_pending=pending)
        self.assertEqual(outcome, 'reload_requested')
        self.assertEqual(called, [2])
        self.assertEqual(socket.sent[-1]['id'], 'call-1')

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

    def test_vps_registration_can_only_be_advertised_by_windows_personal_device(self):
        from device_fabric.windows_personal_vps_registration import SCHEMA
        tools = TOOLS + [SCHEMA]
        frame = {'type': 'call', 'id': 'project-1', 'tool': SCHEMA['name'], 'args': {}}
        for target, device in (('windows', DEVICE),
                               ('yfc-vps', 'h454-linux-personal-yfc-' + 'a' * 32)):
            calls, socket = [], Socket([WELCOME, frame])
            def run():
                return transport.run_session(target=target, device_id=device, bearer=TOKEN, tools=tools,
                    connector=lambda *_a, **_k: socket,
                    dispatch=lambda name, args: calls.append(name) or {'content': []},
                    is_active=lambda: True, claim_call=lambda _id: True)
            if target == 'windows':
                self.assertEqual(run(), 'idle_timeout')
                self.assertEqual(calls, [SCHEMA['name']])
            else:
                with self.assertRaises(transport.PersonalTransportDenied): run()
                self.assertEqual(calls, [])

    def test_windows_registration_is_only_advertised_by_windows_personal_device(self):
        from device_fabric.windows_personal_project_hot_registration import SCHEMA
        from device_fabric.windows_personal_vps_registration import SCHEMA as VPS_SCHEMA
        tools = TOOLS + [SCHEMA, VPS_SCHEMA]
        frame = {'type': 'call', 'id': 'project-1', 'tool': SCHEMA['name'], 'args': {}}
        for target, device in (('windows', DEVICE),
                               ('yfc-vps', 'h454-linux-personal-yfc-' + 'a' * 32)):
            calls, socket = [], Socket([WELCOME, frame])
            def run():
                return transport.run_session(target=target, device_id=device, bearer=TOKEN, tools=tools,
                    connector=lambda *_a, **_k: socket,
                    dispatch=lambda name, args: calls.append(name) or {'content': []},
                    is_active=lambda: True, claim_call=lambda _id: True)
            if target == 'windows':
                self.assertEqual(run(), 'idle_timeout')
                self.assertEqual(calls, [SCHEMA['name']])
            else:
                with self.assertRaises(transport.PersonalTransportDenied): run()
                self.assertEqual(calls, [])

    def test_bearer_never_returns_in_an_agent_result(self):
        frame = {"type": "call", "id": "call-1", "tool": "read_file", "args": {}}
        with self.assertRaises(transport.PersonalTransportDenied) as error:
            self.run_session([WELCOME, frame], dispatch=lambda *_: {
                "content": [{"type": "text", "text": TOKEN}]})
        self.assertNotIn(TOKEN, str(error.exception))

    def test_alias_is_accepted_only_when_advertised_and_claimed_before_dispatch(self):
        from device_fabric.personal_session_alias import advertised_tools
        frame = {'type': 'call', 'id': 'terminate-1', 'tool': 'kill_process', 'args': {'pid': 123}}
        for advertised in (False, True):
            with self.subTest(advertised=advertised):
                socket, calls = Socket([WELCOME, frame]), []
                tools = advertised_tools(TOOLS) if advertised else TOOLS
                def run():
                    return transport.run_session(device_id=DEVICE, bearer=TOKEN, tools=tools,
                        connector=lambda *_a, **_k: socket,
                        dispatch=lambda name, args: calls.append(('dispatch', name, args)) or {'content': []},
                        is_active=lambda: True,
                        claim_call=lambda ident: calls.append(('claim', ident)) or True)
                if advertised:
                    self.assertEqual(run(), 'idle_timeout')
                    self.assertEqual(calls, [('claim', 'terminate-1'), ('dispatch', 'kill_process', {'pid': 123})])
                else:
                    with self.assertRaises(transport.PersonalTransportDenied):
                        run()
                    self.assertEqual(calls, [])

    def test_separately_bound_linux_personal_sessions_claim_before_dispatch(self):
        frame = {"type": "call", "id": "linux-call-1", "tool": "start_process",
                 "args": {"command": "synthetic"}}
        for target, host, name in (
            ('hermes-vps', 'hermes', 'H454 Hermes VPS personal Commander'),
            ('yfc-vps', 'yfc', 'H454 YFC VPS personal Commander'),
        ):
            with self.subTest(target=target):
                device = 'h454-linux-personal-' + host + '-' + 'a' * 32
                seen = []
                outcome, socket = self.run_session([WELCOME, frame], target=target, device=device,
                    claim=lambda ident: seen.append(('claim', ident)) or True,
                    dispatch=lambda tool, args: seen.append(('dispatch', tool)) or {'content': []})
                self.assertEqual(outcome, 'idle_timeout')
                self.assertEqual(seen, [('claim', 'linux-call-1'), ('dispatch', 'start_process')])
                self.assertEqual(socket.sent[0]['device']['deviceId'], device)
                self.assertEqual(socket.sent[0]['device']['name'], name)
                self.assertEqual(socket.sent[0]['device']['platform'], 'linux')
                self.assertIn(socket.sent[0]['device']['arch'], ('x64', 'arm64'))

    def test_linux_read_only_and_cross_host_identities_are_not_promoted(self):
        for target, device in (
            ('hermes-vps', 'h454-linux-hermes-' + 'a' * 32),
            ('yfc-vps', 'h454-linux-personal-hermes-' + 'a' * 32),
            ('hermes-vps', DEVICE),
            ('windows', 'h454-linux-personal-yfc-' + 'a' * 32),
        ):
            with self.subTest(target=target, device=device), self.assertRaises(transport.PersonalTransportDenied):
                self.run_session([WELCOME], target=target, device=device)

    def test_linux_replay_revocation_and_unknown_architecture_are_refused(self):
        device = 'h454-linux-personal-hermes-' + 'a' * 32
        frame = {'type': 'call', 'id': 'linux-replay', 'tool': 'write_file', 'args': {}}
        calls = []
        def dispatch(*_args):
            calls.append(True)
            return {'content': []}
        with self.assertRaises(transport.PersonalTransportDenied):
            self.run_session([WELCOME, frame, frame], target='hermes-vps', device=device, dispatch=dispatch)
        self.assertEqual(len(calls), 1)
        with self.assertRaises(transport.PersonalTransportDenied):
            self.run_session([WELCOME, frame], target='hermes-vps', device=device,
                             active=lambda: False, dispatch=dispatch)
        with patch.object(transport.platform, 'machine', return_value='unknown-cpu'):
            with self.assertRaises(transport.PersonalTransportDenied):
                self.run_session([WELCOME, frame], target='hermes-vps', device=device, dispatch=dispatch)
        self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
