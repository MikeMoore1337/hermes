"""Linux operator plan in a synthetic filesystem; never touches systemd."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


class LinuxOperatorPlanTests(unittest.TestCase):
    def _plan_checks_access_without_writing(self):
        from scripts import h454_linux_personal_add_project as operator
        from device_fabric import linux_personal_config as config
        from scripts.h454_linux_personal_unit import render
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            etc, units, state = root/'etc', root/'units', root/'state'
            for directory in (etc, units, state): directory.mkdir()
            data = {'schema':config.SCHEMA, 'target':'hermes-vps',
                'device_id':'h454-linux-personal-hermes-'+'a'*32, 'project':'/opt/example',
                'release_sha':'b'*40, 'trust_release_sha':'c'*40, 'bundle_sha256':'d'*64}
            raw = json.dumps(data,sort_keys=True,separators=(',',':')).encode()
            unit = render(target='hermes-vps',release_sha='b'*40,dependency_sha='c'*40,
                project='/opt/example',project_group='example',relay_ip='172.20.0.7').encode()
            config_path=etc/'hermes-vps.json'
            unit_path=units/'hermes-commander-personal-hermes.service'
            config_path.write_bytes(raw); unit_path.write_bytes(unit)
            calls=[]
            with patch.object(operator,'CONFIG_ROOT',etc), patch.object(operator,'UNIT_ROOT',units), \
                 patch.object(operator,'STATE_ROOT',state), patch.object(operator,'_root_chain'), \
                 patch.object(operator,'_read',side_effect=lambda path, **_kw:path.read_bytes()), \
                 patch.object(operator,'_check_unit',side_effect=lambda *_:calls.append('unit')), \
                 patch.object(operator,'_check_access',side_effect=lambda path:calls.append(('access',path))), \
                 patch.object(operator.os,'geteuid',return_value=0), contextlib.redirect_stdout(io.StringIO()) as output:
                result=operator.main(['--target','hermes-vps','--name','next','--project','/opt/next'])
            self.assertEqual(result,0)
            self.assertIn('PLAN_PASS',output.getvalue())
            self.assertEqual(calls,['unit',('access','/opt/next')])
            self.assertEqual(config_path.read_bytes(),raw)
            self.assertEqual(unit_path.read_bytes(),unit)
            self.assertEqual(list(state.iterdir()),[])

    def _rollback_plan_refuses_wrong_backup(self):
        from scripts import h454_linux_personal_add_project as operator
        from device_fabric import linux_personal_config as config
        from device_fabric import linux_personal_project_registration as registration
        from scripts.h454_linux_personal_unit import render
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); etc=root/'etc'; units=root/'units'; state=root/'state'
            for directory in (etc,units,state): directory.mkdir()
            data={'schema':config.SCHEMA,'target':'hermes-vps',
                'device_id':'h454-linux-personal-hermes-'+'a'*32,'project':'/opt/example',
                'release_sha':'b'*40,'trust_release_sha':'c'*40,'bundle_sha256':'d'*64}
            original=json.dumps(data,sort_keys=True,separators=(',',':')).encode()
            original_unit=render(target='hermes-vps',release_sha='b'*40,dependency_sha='c'*40,
                project='/opt/example',project_group='example',relay_ip='172.20.0.7').encode()
            new,new_unit=registration.prepare(original,original_unit,target='hermes-vps',name='next',project='/opt/next')
            config_path=etc/'hermes-vps.json'; unit_path=units/'hermes-commander-personal-hermes.service'
            config_path.write_bytes(new); unit_path.write_bytes(new_unit)
            backup=state/('project-registration-'+'a'*32); backup.mkdir(mode=0o700)
            for name,raw in [('old-config',original),('old-unit',original_unit),('new-config',new),('new-unit',new_unit)]:
                (backup/name).write_bytes(raw)
            with patch.object(operator,'CONFIG_ROOT',etc), patch.object(operator,'UNIT_ROOT',units), \
                 patch.object(operator,'STATE_ROOT',state), patch.object(operator,'_root_chain'), \
                 patch.object(operator,'_read',side_effect=lambda path, **_kw:path.read_bytes()), \
                 patch.object(operator,'_check_unit'), patch.object(operator,'_check_access') as access, \
                 patch.object(operator.os,'geteuid',return_value=0), contextlib.redirect_stdout(io.StringIO()) as output:
                result=operator.main(['--target','hermes-vps','--rollback',backup.name])
            self.assertEqual(result,0); self.assertIn('PLAN_PASS',output.getvalue())
            access.assert_not_called()
            (backup/'new-unit').write_bytes(b'unrelated')
            with patch.object(operator,'CONFIG_ROOT',etc), patch.object(operator,'UNIT_ROOT',units), \
                 patch.object(operator,'STATE_ROOT',state), patch.object(operator,'_root_chain'), \
                 patch.object(operator,'_read',side_effect=lambda path, **_kw:path.read_bytes()), \
                 patch.object(operator.os,'geteuid',return_value=0), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(operator.main(['--target','hermes-vps','--rollback',backup.name]),2)
            self.assertEqual(config_path.read_bytes(),new); self.assertEqual(unit_path.read_bytes(),new_unit)


if sys.platform == 'linux':
    LinuxOperatorPlanTests.test_plan_checks_access_without_writing = LinuxOperatorPlanTests._plan_checks_access_without_writing
    LinuxOperatorPlanTests.test_rollback_plan_refuses_wrong_backup = LinuxOperatorPlanTests._rollback_plan_refuses_wrong_backup


if __name__ == '__main__':
    unittest.main()
