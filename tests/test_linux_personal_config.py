"""Personal Linux config selects one explicit project and one host identity."""
import json
import unittest

from device_fabric import linux_personal_config as config


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


class PersonalLinuxConfigTests(unittest.TestCase):
    def setUp(self):
        self.data = {'schema': config.SCHEMA, 'target': 'yfc-vps',
                     'device_id': 'h454-linux-personal-yfc-' + 'a' * 32,
                     'project': '/srv/yfc/project', 'release_sha': 'b' * 40,
                     'trust_release_sha': 'c' * 40, 'bundle_sha256': 'd' * 64}

    def test_valid_config_pins_bundle_and_redacts_repr(self):
        result = config.parse(encode(self.data), target='yfc-vps')
        self.assertEqual(result.bundle, '/opt/hermes-commander-personal/releases/main-' + 'b' * 40)
        self.assertNotIn(self.data['project'], repr(result))

    def test_unsafe_or_wrong_identity_cannot_select_a_project(self):
        for changes in ({'project': '/srv/second-brain'}, {'project': '/srv/second-brain/second-brain-vault'},
                        {'project': '/tmp/../etc'}, {'device_id': 'h454-linux-personal-hermes-' + 'a' * 32},
                        {'target': 'hermes-vps'}, {'release_sha': 'x' * 40}, {'bundle_sha256': 'e' * 63},
                        {'unexpected': True}):
            with self.subTest(changes=changes), self.assertRaises(config.PersonalLinuxConfigDenied):
                config.parse(encode({**self.data, **changes}), target='yfc-vps')

    def test_duplicate_or_noncanonical_json_is_denied(self):
        raw = encode(self.data)
        for value in (raw + b'\n', raw.replace(b'"schema":', b'"schema":"duplicate","schema":', 1)):
            with self.subTest(length=len(value)), self.assertRaises(config.PersonalLinuxConfigDenied):
                config.parse(value, target='yfc-vps')

    def test_multiple_projects_are_explicit_nonoverlapping_and_ordered(self):
        data = {**self.data, 'schema': config.MULTI_SCHEMA,
                'projects': [{'name': 'alpha', 'path': '/srv/alpha/code'},
                             {'name': 'beta', 'path': '/opt/beta/code'}]}
        result = config.parse(encode(data), target='yfc-vps')
        self.assertEqual(result.additional_projects, (('alpha', '/srv/alpha/code'), ('beta', '/opt/beta/code')))
        for projects in ([], list(reversed(data['projects'])),
                         [{'name': 'alpha', 'path': '/srv/yfc/project/subdir'}],
                         [{'name': 'alpha', 'path': '/srv/second-brain'}],
                         [{'name': '../x', 'path': '/srv/alpha/code'}],
                         [{'name': 'alpha', 'path': '/srv/alpha/code'},
                          {'name': 'alpha', 'path': '/srv/beta/code'}]):
            with self.subTest(projects=projects), self.assertRaises(config.PersonalLinuxConfigDenied):
                config.parse(encode({**data, 'projects': projects}), target='yfc-vps')

    def test_more_than_four_roots_survive_config_parsing_and_dispatch_limit(self):
        from device_fabric.linux_personal_sandbox import MAX_ADDITIONAL_PROJECTS
        projects = [{'name': f'p{i:02}', 'path': f'/opt/project{i:02}'}
                    for i in range(MAX_ADDITIONAL_PROJECTS)]
        data = {**self.data, 'schema': config.MULTI_SCHEMA, 'projects': projects}
        result = config.parse(encode(data), target='yfc-vps')
        self.assertEqual(len(result.additional_projects), MAX_ADDITIONAL_PROJECTS)
        data['projects'] = projects + [{'name': 'pz', 'path': '/opt/extra'}]
        with self.assertRaises(config.PersonalLinuxConfigDenied):
            config.parse(encode(data), target='yfc-vps')


if __name__ == '__main__':
    unittest.main()
