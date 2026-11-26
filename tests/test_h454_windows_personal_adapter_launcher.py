"""Windows launcher contracts using only disposable local stubs."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "scripts/h454_windows_personal_adapter_launcher.mjs"


if os.name == "nt":
    class PersonalAdapterLauncherTests(unittest.TestCase):
        def setUp(self):
            self.node = shutil.which("node")
            self.assertIsNotNone(self.node, "Node is required for the Windows launcher test")

        def run_fixture(self, *, flags=True, invalid_state=False):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                launcher = root / LAUNCHER.name
                launcher.write_bytes(LAUNCHER.read_bytes())
                adapter = root / "h454_windows_personal_dispatcher.mjs"
                adapter.write_text(
                    "import {execSync} from 'node:child_process';\n"
                    "let blocked=false; try { execSync('cmd /d /c exit 0',"
                    "{windowsHide:true,timeout:1000,stdio:'pipe'}); } "
                    "catch(e) {blocked=e.message==='H454_ADAPTER_SYNC_PROCESS_UNAVAILABLE';}\n"
                    "process.stdout.write(JSON.stringify({blocked,argc:process.argv.length,"
                    "dispatcher:process.argv[2],home:process.env.BRC_HOME}));\n", encoding="utf-8")
                dispatcher = root / "bundle" / "dispatcher.js"
                dispatcher.parent.mkdir()
                dispatcher.write_text("// synthetic", encoding="utf-8")
                state = root / "state"
                argv = [self.node]
                if flags:
                    argv += ["--preserve-symlinks-main", "--preserve-symlinks"]
                argv += [str(launcher), str(dispatcher), "relative" if invalid_state else str(state)]
                result = subprocess.run(argv, capture_output=True, text=True, timeout=10,
                                        creationflags=subprocess.CREATE_NO_WINDOW)
                return result, str(dispatcher), str(state)

        def test_launcher_sets_state_and_disables_synchronous_child_processes(self):
            result, dispatcher, state = self.run_fixture()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), {
                "blocked": True, "argc": 3, "dispatcher": dispatcher, "home": state,
            })

        def test_missing_node_flags_or_nonabsolute_state_fails_before_adapter(self):
            for options in ({"flags": False}, {"invalid_state": True}):
                with self.subTest(options=options):
                    result, _, _ = self.run_fixture(**options)
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
