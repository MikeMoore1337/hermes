"""#276: bounded reconnect for existing native Win32 *read-only* BRC adapter.

Offline synthetic only. Does not start a Windows service, open a socket, or
use any real paired device token, original file, CLI client or paid provider.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from scripts import h15_native_windows_outbound as native


def conf():
    return native.parse_settings(
        "wss://hermes.mikemoore.top/ws", "h454-win-owner-test", "x" * 48
    )


class ReconnectTests(unittest.TestCase):
    def test_fails_twice_then_reconnects_and_returns_budget(self):
        sleeps, attempts = [], []
        sequence = [
            native.NativeTransportDenied("transport_failed"),
            native.NativeTransportDenied("transport_failed"),
            "read_budget_exhausted",
        ]

        def fake_session(config, connector, *, seen_ids=None):
            self.assertIsInstance(seen_ids, set)
            attempts.append(config.device_id)
            item = sequence.pop(0)
            if isinstance(item, Exception):
                raise item
            return item

        with patch.object(native, "run_session", side_effect=fake_session):
            answer = native.run_bounded_reconnect(
                conf(), lambda *_args: None, pause=sleeps.append
            )
        self.assertEqual(answer, "read_budget_exhausted")
        self.assertEqual(sleeps, [1, 2])
        self.assertEqual(len(attempts), 3)
        self.assertEqual(len(sequence), 0)

    def test_retries_idle_disconnect_with_backoff_not_infinite(self):
        sleeps = []
        with patch.object(native, "run_session", return_value="idle_timeout") as run:
            answer = native.run_bounded_reconnect(
                conf(), lambda *_args: None, pause=sleeps.append
            )
        self.assertEqual(answer, "reconnect_budget_exhausted")
        self.assertEqual(run.call_count, native.MAX_RECONNECT_ATTEMPTS)
        self.assertEqual(sleeps, [1, 2, 4, 8])
        self.assertEqual(sum(sleeps), 15)

    def test_transport_failure_exhausts_retry_and_never_returns_success(self):
        sleeps = []
        with patch.object(native, "run_session",
                          side_effect=native.NativeTransportDenied("transport_failed")) as run:
            answer = native.run_bounded_reconnect(
                conf(), lambda *_args: None, pause=sleeps.append
            )
        self.assertEqual(answer, "reconnect_budget_exhausted")
        self.assertEqual(run.call_count, 5)
        self.assertEqual(sleeps, [1, 2, 4, 8])

    def test_fatal_relay_refusal_must_not_retry(self):
        reasons = ("relay_rejected", "invalid_welcome", "welcome_required",
                   "frame_json_invalid", "reconnect_requires_readonly_catalog")
        for reason in reasons:
            with self.subTest(reason=reason):
                sleeps = []
                with patch.object(native, "run_session",
                                  side_effect=native.NativeTransportDenied(reason)) as run:
                    with self.assertRaisesRegex(native.NativeTransportDenied, reason):
                        native.run_bounded_reconnect(
                            conf(), lambda *_args: None, pause=sleeps.append
                        )
                run.assert_called_once()
                self.assertEqual(sleeps, [])

    def test_never_reconnects_after_successful_session_with_call_budget_exceeded(self):
        for reason in ("session_budget_exhausted", "read_budget_exhausted"):
            with self.subTest(reason=reason):
                with patch.object(native, "run_session", return_value=reason) as run:
                    self.assertEqual(
                        native.run_bounded_reconnect(conf(), lambda *_args: None,
                                                     pause=lambda _: self.fail("slept")),
                        reason,
                    )
                    run.assert_called_once()

    def test_only_readonly_catalog_allowed(self):
        for tools in [
            ({"name": "native_file_read"}, {"name": "start_process"}),
            ({"name": "native_file_read"}, {"name": "native_file_stat"},
             {"name": "native_file_write"}),
            (),
        ]:
            with self.subTest(tools=tools):
                with patch.object(native, "TOOLS", tools), \
                        patch.object(native, "run_session") as runner:
                    with self.assertRaisesRegex(native.NativeTransportDenied,
                                                "reconnect_requires_readonly_catalog"):
                        native.run_bounded_reconnect(
                            conf(), lambda *_args: None, pause=lambda _: None
                        )
                    runner.assert_not_called()

    def test_readonly_reconnect_does_not_repeat_or_queue_prior_calls(self):
        # Fake two sessions, the first disconnects and the second reads once.
        # This is explicitly NOT evidence of durable replay protection for
        # future write/execute tools; those are not in the advertised catalog.
        invokes = []
        class FakeWS:
            def __init__(self, payload):
                self.incoming = iter(payload)
                self.sent = []
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                return False
            def send(self, raw):
                self.sent.append(raw)
            def recv(self, timeout=None):
                item = next(self.incoming, None)
                if item is None:
                    raise TimeoutError
                return item
        import json
        sockets = []
        def connector(*_args, **_kwargs):
            index = len(sockets)
            welcome = json.dumps({"type": "welcome", "protocol": 1,
                                  "relayVersion": "test", "serverTime": 1})
            if index == 0:
                ws = FakeWS([welcome])
            else:
                ws = FakeWS([welcome, json.dumps({
                    "type": "call", "id": "new-session",
                    "tool": "native_file_stat",
                    "args": {"project": "hermes", "relative": "README.md"}
                })])
            sockets.append(ws)
            return ws
        from scripts import h15_native_windows_mcp_stdio as mcp
        with patch.object(mcp.native, "handle_native_request") as reader:
            reader.return_value = {"status": "ok", "project": "hermes",
                                   "relative": "README.md", "action": "stat",
                                   "kind": "file", "size_bytes": 3}
            # Five idle sessions due to bounded policy, no queued calls.
            result = native.run_bounded_reconnect(
                conf(), connector, pause=lambda _: None
            )
        self.assertEqual(result, "reconnect_budget_exhausted")
        self.assertEqual(reader.call_count, 1)
        self.assertEqual(len(sockets), 5)
        self.assertEqual(len([x for s in sockets for x in s.sent if
                              json.loads(x).get("type") == "result"]), 1)

    def test_non_windows_cli_never_executes_reconnect(self):
        if native.os.name != "nt":
            with patch.object(native, "run_bounded_reconnect") as runner:
                self.assertEqual(native.main(["--bounded-reconnect"]), 2)
                runner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
