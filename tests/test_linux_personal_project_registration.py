"""Project registration planning on synthetic config and systemd text."""
import json
import unittest

from device_fabric import linux_personal_config as config
from device_fabric import linux_personal_project_registration as registration
from scripts.h454_linux_personal_unit import render


class ProjectRegistrationTests(unittest.TestCase):
    def setUp(self):
        self.target = 'hermes-vps'
        data = {'schema': config.SCHEMA, 'target': self.target,
            'device_id': 'h454-linux-personal-hermes-' + 'a' * 32,
            'project': '/opt/reminder-bot', 'release_sha': 'b' * 40,
            'trust_release_sha': 'c' * 40, 'bundle_sha256': 'd' * 64}
        self.raw = json.dumps(data, sort_keys=True, separators=(',', ':')).encode('ascii')
        self.unit = render(target=self.target, release_sha='b' * 40, dependency_sha='c' * 40,
            project=data['project'], project_group='reminder-deploy', relay_ip='172.20.0.7').encode()

    def test_adds_one_named_root_without_changing_other_unit_settings(self):
        raw, unit = registration.prepare(self.raw, self.unit, target=self.target,
            name='example', project='/opt/example')
        result = config.parse(raw, target=self.target)
        self.assertEqual(result.additional_projects, (('example', '/opt/example'),))
        self.assertEqual(result.device_id, 'h454-linux-personal-hermes-' + 'a' * 32)
        expected = self.unit.replace(b'ReadWritePaths="/opt/reminder-bot" ',
            b'ReadWritePaths="/opt/reminder-bot" "/opt/example" ')
        self.assertEqual(unit, expected)

    def test_idempotent_and_rejects_duplicate_name_or_path(self):
        raw, unit = registration.prepare(self.raw, self.unit, target=self.target,
            name='example', project='/opt/example')
        self.assertEqual(registration.prepare(raw, unit, target=self.target,
            name='example', project='/opt/example'), (raw, unit))
        for name, path in [('example', '/opt/other'), ('other', '/opt/example')]:
            with self.subTest(name=name), self.assertRaises(registration.ProjectRegistrationDenied):
                registration.prepare(raw, unit, target=self.target, name=name, project=path)

    def test_registers_past_four_until_shared_dispatcher_limit(self):
        from device_fabric.linux_personal_sandbox import MAX_ADDITIONAL_PROJECTS
        raw, unit = self.raw, self.unit
        for index in range(MAX_ADDITIONAL_PROJECTS):
            name, path = f'p{index:02}', f'/opt/project{index:02}'
            raw, unit = registration.prepare(raw, unit, target=self.target, name=name, project=path)
            self.assertEqual(len(config.parse(raw, target=self.target).additional_projects), index + 1)
            self.assertIn(('"' + path + '"').encode(), unit)
        with self.assertRaises(registration.ProjectRegistrationDenied):
            registration.prepare(raw, unit, target=self.target, name='pz', project='/opt/extra')

    def test_rejects_unsafe_paths_and_modified_unit(self):
        for name, path in [('private', '/srv/second-brain'), ('bad/name', '/opt/example'),
                           ('nested', '/opt/reminder-bot/subdir'), ('root', '/opt')]:
            with self.subTest(path=path), self.assertRaises(registration.ProjectRegistrationDenied):
                registration.prepare(self.raw, self.unit, target=self.target, name=name, project=path)
        for changed in (self.unit.replace(b'NoNewPrivileges=yes', b'NoNewPrivileges=no'),
                        self.unit.replace(b'ReadWritePaths=', b'ReadWritePaths=/extra '),
                        self.unit + b'ReadWritePaths=/tmp\n'):
            with self.subTest(unit=changed[:20]), self.assertRaises(registration.ProjectRegistrationDenied):
                registration.prepare(self.raw, changed, target=self.target, name='example', project='/opt/example')

    def test_transaction_restores_on_each_interrupted_step(self):
        new_config, new_unit = registration.prepare(self.raw, self.unit, target=self.target,
            name='example', project='/opt/example')
        for failure in (None, 'stop', 'unit', 'config', 'reload', 'start', 'health'):
            with self.subTest(failure=failure):
                state = {'config': self.raw, 'unit': self.unit, 'failed': False, 'running': True, 'backup': None}
                def checkpoint(name):
                    if name == failure and not state['failed']:
                        state['failed'] = True
                        raise ValueError('synthetic failure')
                def replace(key, old, new):
                    checkpoint(key)
                    if state[key] != old:
                        raise ValueError('drift')
                    state[key] = new
                def stop():
                    checkpoint('stop')
                    state['running'] = False
                def start():
                    checkpoint('start')
                    state['running'] = True
                def reload(): checkpoint('reload')
                def health(): checkpoint('health'); return state['running']
                options = dict(backup=lambda *items: state.update(backup=items),
                    read=lambda: (state['config'], state['unit']),
                    replace_config=lambda old,new: replace('config', old, new),
                    replace_unit=lambda old,new: replace('unit', old, new),
                    stop=stop, reload=reload, start=start, healthy=health)
                if failure is None:
                    registration.apply(self.raw, self.unit, new_config, new_unit, **options)
                    self.assertEqual((state['config'], state['unit']), (new_config, new_unit))
                else:
                    with self.assertRaisesRegex(registration.ProjectRegistrationDenied, 'rolled_back'):
                        registration.apply(self.raw, self.unit, new_config, new_unit, **options)
                    self.assertEqual((state['config'], state['unit']), (self.raw, self.unit))
                self.assertTrue(state['running'])
                self.assertEqual(state['backup'], (self.raw, self.unit, new_config, new_unit))

    def test_transaction_detects_unrecoverable_failure(self):
        with self.assertRaises(registration.ProjectRollbackFailed):
            registration.apply(b'old', b'old-unit', b'new', b'new-unit',
                backup=lambda *_: None, read=lambda: (b'old', b'old-unit'),
                replace_config=lambda *_: None, replace_unit=lambda *_: None,
                stop=lambda: (_ for _ in ()).throw(ValueError()),
                reload=lambda: None, start=lambda: None, healthy=lambda: True)


if __name__ == '__main__':
    unittest.main()
