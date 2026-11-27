"""The worker must bind the sandbox to one verified session and close it."""
import unittest
from unittest.mock import MagicMock, patch

from device_fabric import linux_personal_worker as worker


class LinuxPersonalWorkerTests(unittest.TestCase):
    def setUp(self):
        self.options = dict(target='yfc-vps', device_id='device', bearer='bearer',
                            project='/tmp/project', bundle='/tmp/bundle',
                            connector=lambda *_args, **_kwargs: None,
                            is_active=lambda: True, claim_call=lambda _id: True,
                            verify_bundle=lambda: True)

    def test_inactive_grant_never_starts_project_process(self):
        self.options['is_active'] = lambda: False
        with patch.object(worker, 'start') as start:
            with self.assertRaises(worker.LinuxPersonalWorkerDenied):
                worker.serve_once(**self.options)
        start.assert_not_called()

    def test_session_receives_sandbox_bridge_and_close_always_runs(self):
        events = []
        class Bridge:
            tools = [{'name': 'fixture'}, {'name': 'force_terminate', 'inputSchema': {'type': 'object'}}]
            def __init__(self, process, roots):
                self.process = process
                events.append(('bridge', roots))
            def dispatch(self, name, args):
                return {'content': []}
            def close(self):
                events.append(('close',))
        process = object()
        def session(**kwargs):
            events.append(('session', kwargs['target'], kwargs['tools'], kwargs['dispatch']))
            self.assertEqual(kwargs['dispatch']('kill_process', {'pid': 123}), {'content': []})
            return 'idle_timeout'
        with patch.object(worker, 'start', return_value=process) as launch, \
             patch.object(worker, 'PersonalCommanderPipe', Bridge), \
             patch.object(worker, 'run_session', side_effect=session):
            self.assertEqual(worker.serve_once(**self.options), 'idle_timeout')
        launch.assert_called_once_with('/tmp/project', '/tmp/bundle', ['/opt/commander/run'])
        self.assertEqual(events[0], ('bridge', ['/workspace']))
        self.assertEqual(events[1][1], 'yfc-vps')
        self.assertEqual({tool['name'] for tool in events[1][2]}, {'fixture', 'force_terminate', 'kill_process'})
        self.assertEqual(events[2], ('close',))

    def test_unverified_bundle_never_starts_project_process(self):
        self.options['verify_bundle'] = lambda: False
        with patch.object(worker, 'start') as start:
            with self.assertRaises(worker.LinuxPersonalWorkerDenied):
                worker.serve_once(**self.options)
        start.assert_not_called()

    def test_additional_project_is_mounted_and_advertised_to_the_same_bridge(self):
        self.options['additional_projects'] = (('alpha', '/tmp/alpha'),)
        bridge = MagicMock()
        bridge.tools = [{'name': 'force_terminate', 'inputSchema': {'type': 'object'}}]
        with patch.object(worker, 'start', return_value=object()) as launch, \
             patch.object(worker, 'PersonalCommanderPipe', return_value=bridge) as create, \
             patch.object(worker, 'run_session', return_value='idle_timeout'):
            self.assertEqual(worker.serve_once(**self.options), 'idle_timeout')
        launch.assert_called_once_with('/tmp/project', '/tmp/bundle', ['/opt/commander/run'],
                                       additional_projects=(('alpha', '/tmp/alpha'),))
        self.assertEqual(create.call_args.args[1], ['/workspace', '/projects/alpha'])
        bridge.close.assert_called_once()

    def test_transport_failure_is_sanitized_and_closes_sandbox(self):
        closed = []
        class Bridge:
            tools = []
            def __init__(self, *_args): pass
            def dispatch(self, *_args): pass
            def close(self): closed.append(True)
        with patch.object(worker, 'start', return_value=object()), \
             patch.object(worker, 'PersonalCommanderPipe', Bridge), \
             patch.object(worker, 'run_session', side_effect=ValueError('secret fixture')):
            with self.assertRaises(worker.LinuxPersonalWorkerDenied) as error:
                worker.serve_once(**self.options)
        self.assertEqual(str(error.exception), 'linux_personal_worker_denied')
        self.assertEqual(closed, [True])

    def test_transient_disconnect_reuses_sandbox_and_stops_after_revocation(self):
        process = MagicMock()
        process.poll.return_value = None
        bridge = MagicMock()
        bridge.tools = [{'name': 'force_terminate', 'inputSchema': {'type': 'object'}}]
        states = iter([None, True, False])
        delays = []
        self.options.update(grant_state=lambda: next(states), sleep=delays.append)
        with patch.object(worker, 'start', return_value=process) as launch, \
             patch.object(worker, 'PersonalCommanderPipe', return_value=bridge) as create_bridge, \
             patch.object(worker, 'run_session', side_effect=[
                 worker.PersonalTransportDenied('fixture'), 'idle_timeout']) as session:
            self.assertEqual(worker.serve_once(**self.options), 'grant_inactive')
        launch.assert_called_once()
        create_bridge.assert_called_once()
        self.assertEqual(session.call_count, 2)
        self.assertEqual(delays, [5, 5])
        bridge.close.assert_called_once()

    def test_dead_sandbox_is_not_reconnected(self):
        process = MagicMock()
        process.poll.return_value = 1
        bridge = MagicMock()
        bridge.tools = [{'name': 'force_terminate', 'inputSchema': {'type': 'object'}}]
        self.options.update(grant_state=lambda: True, sleep=lambda _delay: None)
        with patch.object(worker, 'start', return_value=process), \
             patch.object(worker, 'PersonalCommanderPipe', return_value=bridge), \
             patch.object(worker, 'run_session', side_effect=worker.PersonalTransportDenied('fixture')) as session:
            with self.assertRaises(worker.LinuxPersonalWorkerDenied):
                worker.serve_once(**self.options)
        session.assert_called_once()
        bridge.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()
