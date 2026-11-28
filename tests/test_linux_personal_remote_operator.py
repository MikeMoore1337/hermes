"""The SSH entry accepts only the pinned operator and a bounded request."""
import hashlib
import io
import json
from pathlib import Path
import stat
import unittest
from unittest.mock import patch

from device_fabric import linux_personal_remote_operator as operator


class RemoteOperatorTests(unittest.TestCase):
    def test_verified_manifest_cannot_be_replaced_or_change_a_file(self):
        root = Path('/fixture/operator')
        body = b'fixed trusted operator'
        records = {'scripts/h454_linux_personal_add_project.py': hashlib.sha256(body).hexdigest()}
        manifest = json.dumps({'release': operator.RELEASE, 'files': records}).encode('ascii')
        digest = hashlib.sha256(manifest).hexdigest()
        directory = type('Directory', (), {'st_mode': stat.S_IFDIR | 0o755, 'st_uid': 0})()
        def read(path, _maximum):
            return manifest if path.name == 'manifest.json' else body
        with patch.object(operator, 'ROOT', root), patch.object(operator, 'MANIFEST_SHA256', digest), \
             patch.object(Path, 'lstat', return_value=directory), patch.object(operator, '_read', side_effect=read):
            operator._verify_operator()
            with patch.object(operator, 'MANIFEST_SHA256', '0' * 64), self.assertRaises(ValueError):
                operator._verify_operator()
            with patch.object(operator, '_read', side_effect=lambda path, _m: manifest if path.name == 'manifest.json' else b'changed'), \
                 self.assertRaises(ValueError):
                operator._verify_operator()

    def test_invalid_request_never_loads_or_runs_the_operator(self):
        for request in ({'target': 'other', 'name': 'demo', 'path': '/opt/demo', 'mode': 'plan'},
                        {'target': 'yfc-vps', 'name': '../bad', 'path': '/opt/demo', 'mode': 'execute'},
                        {'target': 'yfc-vps', 'name': 'demo', 'path': '/opt/demo', 'mode': 'execute', 'command': 'bad'}):
            with self.subTest(request=request):
                stdin = io.TextIOWrapper(io.BytesIO(json.dumps(request).encode()), encoding='ascii')
                with patch.object(operator.os, 'geteuid', return_value=0, create=True), \
                     patch.object(operator.sys, 'stdin', stdin), patch.object(operator, '_verify_operator') as verify, \
                     patch.object(operator.runpy, 'run_module') as run, \
                     patch.object(operator.sys, 'stderr', io.StringIO()):
                    with self.assertRaises(SystemExit): operator.main()
                verify.assert_not_called()
                run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
