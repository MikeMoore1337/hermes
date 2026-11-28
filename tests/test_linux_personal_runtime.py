"""Personal runtime composes current-grant status and durable call claims."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from device_fabric import linux_personal_runtime as runtime


class PersonalLinuxRuntimeTests(unittest.TestCase):
    def setUp(self):
        base = Path(tempfile.gettempdir()).resolve() / 'h454-runtime-fixture'
        self.options = dict(target='yfc-vps', device_id='device-fixture', bearer='bearer-fixture',
            project=str(base / 'project'), bundle=str(base / 'bundle'),
            expected_manifest=b'fixture', bundle_sha256='a' * 64, trust_release_sha='b' * 40,
            journal=base / 'state' / 'journal', websocket_connect=lambda *_a, **_k: None)

    def test_current_grant_verified_bundle_and_durable_claim_are_connected(self):
        trust, connector, replay = object(), object(), MagicMock()
        replay.claim.return_value = True
        def serve(**kwargs):
            self.assertIs(kwargs['connector'], connector)
            self.assertIs(kwargs['is_active'](), True)
            self.assertIs(kwargs['verify_bundle'](), True)
            self.assertIs(kwargs['claim_call']('fixture-call'), True)
            return 'idle_timeout'
        with patch.object(runtime.private, 'load_private_relay', return_value=trust), \
             patch.object(runtime.private, 'private_websocket_connector', return_value=connector), \
             patch.object(runtime, 'LinuxReadReplay', return_value=replay), \
             patch.object(runtime.linux_personal_status, 'bearer_state', return_value=True), \
             patch.object(runtime.bundle_check, 'verify', return_value='a' * 64), \
             patch.object(runtime.linux_personal_worker, 'serve_once', side_effect=serve):
            self.assertEqual(runtime.run_once(**self.options), 'idle_timeout')
        replay.claim.assert_called_once_with('fixture-call')
        replay.close.assert_called_once_with()

    def test_project_cannot_contain_replay_journal(self):
        self.options['journal'] = Path(self.options['project']) / 'journal'
        with patch.object(runtime.private, 'load_private_relay') as load:
            with self.assertRaises(runtime.PersonalLinuxRuntimeDenied):
                runtime.run_once(**self.options)
        load.assert_not_called()

    def test_runtime_failure_closes_journal_and_hides_error(self):
        replay = MagicMock()
        with patch.object(runtime.private, 'load_private_relay'), \
             patch.object(runtime.private, 'private_websocket_connector'), \
             patch.object(runtime, 'LinuxReadReplay', return_value=replay), \
             patch.object(runtime.linux_personal_worker, 'serve_once', side_effect=ValueError('secret fixture')):
            with self.assertRaises(runtime.PersonalLinuxRuntimeDenied) as error:
                runtime.run_once(**self.options)
        replay.close.assert_called_once_with()
        self.assertEqual(str(error.exception), 'personal_linux_runtime_denied')

    def test_failed_worker_with_active_grant_exits_for_supervisor_restart(self):
        replay = MagicMock()
        self.options.update(keep_available=True, sleep=lambda _delay: None)
        with patch.object(runtime.private, 'load_private_relay'), \
             patch.object(runtime.private, 'private_websocket_connector'), \
             patch.object(runtime, 'LinuxReadReplay', return_value=replay), \
             patch.object(runtime.linux_personal_status, 'bearer_state', return_value=True), \
             patch.object(runtime.linux_personal_worker, 'serve_once',
                          side_effect=runtime.linux_personal_worker.LinuxPersonalWorkerDenied('failure')) as serve:
            with self.assertRaises(runtime.PersonalLinuxRuntimeDenied):
                runtime.run_once(**self.options)
        serve.assert_called_once()
        replay.close.assert_called_once()

    def test_grant_loss_closes_session_and_waits_for_fresh_active_status(self):
        replay = MagicMock()
        delays, events = [], []
        states = iter([True, False, None, None, None, True])
        def serve(**kwargs):
            events.append(('session', kwargs['claim_call']))
            return 'grant_inactive' if len(events) == 1 else 'idle_timeout'
        self.options.update(keep_available=True, sleep=delays.append)
        with patch.object(runtime.private, 'load_private_relay'), \
             patch.object(runtime.private, 'private_websocket_connector'), \
             patch.object(runtime, 'LinuxReadReplay', return_value=replay), \
             patch.object(runtime.linux_personal_status, 'bearer_state', side_effect=lambda *_a, **_k: next(states)), \
             patch.object(runtime.linux_personal_worker, 'serve_once', side_effect=serve):
            self.assertEqual(runtime.run_once(**self.options), 'idle_timeout')
        self.assertEqual(len(events), 2)
        self.assertTrue(all(event[1] is replay.claim for event in events))
        self.assertEqual(delays, [5, 5, 0.2, 0.2, 5])
        replay.close.assert_called_once()

    def test_transient_status_retries_are_bounded_and_never_retry_denial(self):
        for statuses, expected, count, delays in (([None, True], True, 2, [0.2]),
                                                   ([False, True], False, 1, []),
                                                   ([None, None, None], None, 3, [0.2, 0.2])):
            with self.subTest(statuses=statuses):
                check = MagicMock(side_effect=statuses)
                pauses = []
                self.assertIs(runtime._grant_state_with_retry(check, pauses.append), expected)
                self.assertEqual(check.call_count, count)
                self.assertEqual(pauses, delays)

    def test_revoked_grant_does_not_launch_sandbox(self):
        replay = MagicMock()
        self.options.update(keep_available=True, sleep=lambda _delay: (_ for _ in ()).throw(StopIteration()))
        with patch.object(runtime.private, 'load_private_relay'), \
             patch.object(runtime.private, 'private_websocket_connector'), \
             patch.object(runtime, 'LinuxReadReplay', return_value=replay), \
             patch.object(runtime.linux_personal_status, 'bearer_state', return_value=False), \
             patch.object(runtime.linux_personal_worker, 'serve_once') as serve:
            with self.assertRaises(runtime.PersonalLinuxRuntimeDenied):
                runtime.run_once(**self.options)
        serve.assert_not_called()
        replay.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()
