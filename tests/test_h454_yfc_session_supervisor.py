"""Bounded YFC session rotation; no host, credentials, or network access."""
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from scripts import h454_native_linux_runtime as runtime


class YfcSessionSupervisorTests(unittest.TestCase):
    def setUp(self):
        self.prepared = SimpleNamespace(device=SimpleNamespace(device_id='synthetic'))
        self.gate = lambda: True
        self.revoked = lambda: False
        self.connector = lambda *args, **kwargs: None

    def run_with(self, session, *, clock=lambda: 0.0, gate=None, revoked=None):
        with patch.object(runtime, 'LinuxOriginalReadDispatcher', side_effect=lambda **_: object()):
            with patch.object(runtime, 'run_session', side_effect=session):
                return runtime._run_yfc_sessions(self.prepared, {}, self.connector,
                    revoked or self.revoked, gate or self.gate, monotonic=clock)

    def test_only_call_budget_rotates_and_total_sessions_remain_bounded(self):
        calls=[]
        def session(_device, dispatcher, _connector, **options):
            calls.append((dispatcher, options['seen_ids'], options['max_seconds']))
            options['seen_ids'].add('request-'+str(len(calls)))
            return 'session_call_budget'
        self.assertEqual(self.run_with(session), 'session_call_budget')
        self.assertEqual(len(calls), 3)
        self.assertEqual(len({id(c[0]) for c in calls}), 3)
        self.assertTrue(all(c[1] is calls[0][1] for c in calls))
        self.assertEqual(calls[0][1], {'request-1','request-2','request-3'})
        self.assertTrue(all(c[2] <= runtime.MAX_SESSION_SECONDS for c in calls))

    def test_transport_failure_is_not_retried(self):
        calls=[]
        def session(*_args, **_kwargs):
            calls.append(1)
            return 'transport_timeout'
        self.assertEqual(self.run_with(session), 'transport_timeout')
        self.assertEqual(len(calls), 1)

    def test_revocation_and_os_gate_checked_before_next_session(self):
        for gate, revoked in ((lambda: False, lambda: False), (lambda: True, lambda: True),
                              (lambda: True, lambda: None)):
            with self.subTest(gate=gate, revoked=revoked):
                calls=[]
                with self.assertRaises(runtime.RuntimeDenied):
                    self.run_with(lambda *_a,**_k: calls.append(1), gate=gate, revoked=revoked)
                self.assertEqual(calls, [])
        states=iter([False, True])
        calls=[]
        def session(*_args, **_kwargs):
            calls.append(1)
            return 'session_call_budget'
        with self.assertRaises(runtime.RuntimeDenied):
            self.run_with(session, revoked=lambda: next(states))
        self.assertEqual(calls, [1])

    def test_deadline_prevents_another_session(self):
        times=iter([0.0, 1.0, runtime.MAX_SESSION_SECONDS+1.0])
        calls=[]
        def session(*_args, **_kwargs):
            calls.append(1)
            return 'session_call_budget'
        self.assertEqual(self.run_with(session, clock=lambda: next(times)), 'session_deadline')
        self.assertEqual(calls, [1])

    def test_rotation_requires_yfc_and_landlock(self):
        for target, landlock in (('hermes-vps', True), ('yfc-vps', False)):
            prepared=runtime.PreparedRuntime(SimpleNamespace(target=target), (), None)
            with self.subTest(target=target, landlock=landlock), self.assertRaises(runtime.RuntimeDenied):
                runtime.run_once(prepared, connector=self.connector, is_device_revoked=self.revoked,
                    is_os_isolation_verified=self.gate, landlock_read=landlock, allow_session_rotation=True)


if __name__ == '__main__':
    unittest.main()
