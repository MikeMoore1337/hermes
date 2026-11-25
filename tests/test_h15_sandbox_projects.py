"""Sandbox onboarding preserves existing projects and reports verified Git facts."""
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.h15_sandbox_projects import ProjectError, inspect


class SandboxProjectTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def repository(self, name):
        project = self.root / name
        project.mkdir()
        def git(*args):
            subprocess.run(['git', '-C', str(project), *args], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        git('init', '-b', 'main')
        git('config', 'user.email', 'fixture@example.invalid')
        git('config', 'user.name', 'Fixture')
        (project / 'README').write_text('fixture', encoding='utf-8')
        git('add', 'README')
        git('commit', '-m', 'fixture')
        git('remote', 'add', 'origin', 'https://github.com/MikeMoore1337/' + name + '.git')
        return project

    def test_inspects_real_existing_repository(self):
        project = self.repository('new-project')
        value = inspect('new-project', self.root)
        self.assertEqual((value['workspace'], value['root'], value['branch']),
                         ('new-project', str(project), 'main'))
        self.assertEqual(len(value['head']), 40)
        self.assertTrue(value['verification_required_before_write'])

    def test_existing_project_is_never_modified(self):
        project = self.repository('new-project')
        before = (project / 'README').read_bytes()
        inspect('new-project', self.root)
        self.assertEqual((project / 'README').read_bytes(), before)

    def test_invalid_name_and_non_repository_are_refused(self):
        for value in ('../other', 'a', '-bad', 'repo/name', 'NAME'):
            with self.subTest(value=value), self.assertRaises(ProjectError):
                inspect(value, self.root)
        (self.root / 'not-a-repo').mkdir()
        with self.assertRaisesRegex(ProjectError, 'invalid_project'):
            inspect('not-a-repo', self.root)

    def test_unexpected_origin_is_refused(self):
        project = self.repository('new-project')
        subprocess.run(['git', '-C', str(project), 'remote', 'set-url', 'origin',
                        'https://example.invalid/new-project.git'], check=True)
        with self.assertRaisesRegex(ProjectError, 'origin_mismatch'):
            inspect('new-project', self.root)


if __name__ == '__main__':
    unittest.main()
