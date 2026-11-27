"""Project selection and real namespace checks for the personal executor."""
import unittest

from device_fabric.linux_personal_sandbox import SandboxDenied, _project_path, start


class ProjectSelectionTests(unittest.TestCase):
    def test_project_root_must_be_a_specific_normalized_nonprivate_path(self):
        for value in ('/', '/srv', '/opt', '/root/project', '/etc/project',
                      '/srv/second-brain', '/srv/second-brain/second-brain-vault',
                      '/srv/second-brain/second-brain-vault/project',
                      '/tmp/../etc', '/tmp//project', 'relative', '/tmp/project\n'):
            with self.subTest(value=value), self.assertRaises(SandboxDenied):
                _project_path(value)
        self.assertEqual(_project_path('/srv/yfc/project'), '/srv/yfc/project')
        self.assertEqual(_project_path('/srv/second-brain/second-brain'),
                         '/srv/second-brain/second-brain')

    def test_bad_child_command_cannot_start(self):
        with self.assertRaises(SandboxDenied):
            start('/tmp/project', '/tmp/bundle', ['/bin/sh', '-c', 'true'])


if __name__ == '__main__':
    unittest.main()
