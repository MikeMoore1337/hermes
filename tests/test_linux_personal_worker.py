"""The worker must bind the sandbox to one verified session and close it."""
import unittest
from unittest.mock import patch

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
            tools = [{'name': 'fixture'}]
            def __init__(self, process, roots):
                self.process = process
                events.append(('bridge', roots))
            def dispatch(self, name, args):
                return {'content': []}
            def close(self):
                events.append(('close',))
        process = object()
        def session(**kwargs):
            events.append(('session', kwargs['target'], kwargs['tools'], kwargs['dispatch'].__self__))
            return 'idle_timeout'
        with patch.object(worker, 'start', return_value=process) as launch, \
             patch.object(worker, 'PersonalCommanderPipe', Bridge), \
             patch.object(worker, 'run_session', side_effect=session):
            self.assertEqual(worker.serve_once(**self.options), 'idle_timeout')
        launch.assert_called_once_with('/tmp/project', '/tmp/bundle', ['/opt/commander/run'])
        self.assertEqual(events[0], ('bridge', ['/workspace']))
        self.assertEqual(events[1][:3], ('session', 'yfc-vps', [{'name': 'fixture'}]))
        self.assertIsInstance(events[1][3], Bridge)
        self.assertEqual(events[2], ('close',))

    def test_unverified_bundle_never_starts_project_process(self):
        self.options['verify_bundle'] = lambda: False
        with patch.object(worker, 'start') as start:
            with self.assertRaises(worker.LinuxPersonalWorkerDenied):
                worker.serve_once(**self.options)
        start.assert_not_called()

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


if __name__ == '__main__':
    unittest.main()
