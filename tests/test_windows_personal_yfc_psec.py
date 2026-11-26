import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from device_fabric import windows_personal_yfc_psec as yfc


if os.name == "nt":
    class YfcScopeTests(unittest.TestCase):
        def setUp(self):
            self.temp = tempfile.TemporaryDirectory(prefix="h454-yfc-scope-")
            self.addCleanup(self.temp.cleanup)
            self.base = Path(self.temp.name).resolve()
            self.project = self.base / "project"
            self.git = self.base / "git"
            app = self.base / yfc.APP_NAME
            self.state, self.release = app / "adapter-state", app / "release"
            for path in (self.project, self.git, self.state, self.release):
                path.mkdir(parents=True)
            (self.project / "code.txt").write_text("synthetic", encoding="ascii")
            self.patches = [patch.object(yfc, "YFC_DEV", self.project), patch.object(yfc, "GIT_ROOT", self.git),
                            patch.dict(os.environ, {"LOCALAPPDATA": str(self.base)})]
            for item in self.patches:
                item.start()
                self.addCleanup(item.stop)
            self.terminal = object.__new__(yfc.YfcDevPsecTerminal)

        def validate(self, root=None, writable=None, readonly=None):
            self.terminal._validate_paths(root or str(self.project), writable or (str(self.state),),
                readonly or (str(self.release), str(self.git)))

        def test_exact_scope_produces_a_metadata_snapshot(self):
            self.validate()
            self.assertEqual(self.terminal.project_snapshot.files, 1)

        def test_other_project_state_or_readonly_path_is_denied(self):
            for args in ({"root": str(self.base)}, {"writable": (str(self.base),)},
                         {"readonly": (str(self.release), str(self.base))}):
                with self.subTest(args=args), self.assertRaises(ValueError):
                    self.validate(**args)

        def test_existing_hardlink_refuses_launch_scope(self):
            os.link(self.project / "code.txt", self.project / "alias.txt")
            with self.assertRaises(ValueError):
                self.validate()
