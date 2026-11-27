"""Public imports run asynchronously through one fixed, bounded host helper."""
import json
from pathlib import Path
import unittest

from device_fabric.windows_personal_project_import import PublicProjectImport


def data(result):
    return json.loads(result['content'][0]['text'])


class Process:
    def __init__(self):
        self.returncode = None
        self.terminated = False
        self.output = json.dumps({'status': 'INSTALLED', 'name': 'local-project',
                                  'head': 'a' * 40, 'branch': 'main', 'clean': True}).encode()

    def poll(self):
        return self.returncode

    def communicate(self, timeout):
        return self.output, None

    def terminate(self):
        self.terminated = True
        self.returncode = 1


class PublicProjectBrokerTests(unittest.TestCase):
    def setUp(self):
        self.process = Process()
        self.calls = []
        def launch(command, **kwargs):
            self.calls.append((command, kwargs))
            return self.process
        helper = Path(__file__).resolve().parents[1] / 'scripts' / 'h15_offline_project_import.py'
        self.broker = PublicProjectImport(helper, launch=launch, terminate=lambda p: p.terminate())

    def test_start_status_and_result(self):
        response = data(self.broker.dispatch({'action': 'start', 'repository': 'Owner/Repo_Name',
                                             'workspace': 'local-project'}))
        self.assertEqual(response['status'], 'started')
        command = self.calls[0][0]
        self.assertEqual(command[-3:], ['Owner/Repo_Name', '--workspace', 'local-project'])
        self.assertEqual(data(self.broker.dispatch({'action': 'status', 'job_id': response['job_id']}) )['status'], 'running')
        self.process.returncode = 0
        result = data(self.broker.dispatch({'action': 'status', 'job_id': response['job_id']}))
        self.assertEqual((result['status'], result['workspace'], result['head']), ('installed', 'local-project', 'a' * 40))

    def test_refuses_untrusted_arguments_and_multiple_running_jobs(self):
        for args in ({'action': 'start', 'repository': 'owner/repo;whoami'},
                     {'action': 'start', 'repository': 'owner/repo', 'workspace': '../secret'},
                     {'action': 'start', 'repository': 'owner/repo', 'command': 'whoami'}):
            self.assertEqual(data(self.broker.dispatch(args))['status'], 'refused')
        self.assertFalse(self.calls)
        self.broker.dispatch({'action': 'start', 'repository': 'owner/repo'})
        self.assertEqual(data(self.broker.dispatch({'action': 'start', 'repository': 'owner/other'}))['status'], 'busy')
        self.assertEqual(len(self.calls), 1)
        self.broker.close()
        self.assertTrue(self.process.terminated)

    def test_status_does_not_return_raw_child_errors(self):
        response = data(self.broker.dispatch({'action': 'start', 'repository': 'owner/repo'}))
        self.process.returncode = 2
        self.process.output = b'secret diagnostic'
        result = self.broker.dispatch({'action': 'status', 'job_id': response['job_id']})
        self.assertEqual(data(result)['status'], 'failed')
        self.assertNotIn('secret diagnostic', str(result))

    def test_timeout_stops_running_import_and_reports_failure(self):
        response = data(self.broker.dispatch({'action': 'start', 'repository': 'owner/repo'}))
        self.broker._expire(response['job_id'])
        self.assertTrue(self.process.terminated)
        self.assertEqual(data(self.broker.dispatch({'action': 'status', 'job_id': response['job_id']}))['status'], 'failed')


if __name__ == '__main__':
    unittest.main()
