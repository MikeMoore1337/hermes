"""Project selection and real namespace checks for the personal executor."""
import unittest

from device_fabric.linux_personal_sandbox import SandboxDenied, _project_path, start, validate_projects


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

    def test_additional_roots_must_be_distinct_bounded_and_non_nested(self):
        self.assertEqual(validate_projects('/srv/a/code', (('one', '/srv/b/code'),)),
                         (('one', '/srv/b/code'),))
        for extra in ((('one', '/srv/a/code'),), (('one', '/srv/a/code/nested'),),
                      (('one', '/srv/a'),), (('../escape', '/srv/b/code'),),
                      (('one', '/srv/second-brain/second-brain-vault'),),
                      tuple(('p' + str(i), '/srv/p' + str(i)) for i in range(5))):
            with self.subTest(extra=extra), self.assertRaises(SandboxDenied):
                validate_projects('/srv/a/code', extra)


if __name__ == '__main__':
    unittest.main()
