"""Check the narrowly scoped YFC tunnel recovery drop-in."""
import configparser
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
DROP_IN = ROOT / "deploy/h454-yfc-tunnel-recovery.conf"


class YfcTunnelRecoveryTests(unittest.TestCase):
    def test_drop_in_only_upholds_the_existing_native_read_service(self):
        parser = configparser.ConfigParser(interpolation=None, strict=True)
        parser.optionxform = str
        parser.read_string(DROP_IN.read_text(encoding="utf-8"))
        self.assertEqual(parser.sections(), ["Unit"])
        self.assertEqual(dict(parser["Unit"]), {
            "Upholds": "hermes-commander-native.service",
        })

    if sys.platform == "linux":
        def test_systemd_accepts_the_drop_in_with_the_existing_dependency_shape(self):
            executable = shutil.which("systemd-analyze")
            self.assertIsNotNone(executable, "systemd-analyze is required on Linux")
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                tunnel = root / "hermes-commander-tunnel.service"
                tunnel.write_text("[Service]\nExecStart=/bin/true\n", encoding="utf-8")
                native = root / "hermes-commander-native.service"
                native.write_text(
                    "[Unit]\nRequires=hermes-commander-tunnel.service\n"
                    "After=hermes-commander-tunnel.service\n"
                    "[Service]\nExecStart=/bin/true\n", encoding="utf-8")
                directory = root / "hermes-commander-tunnel.service.d"
                directory.mkdir()
                (directory / "recovery.conf").write_bytes(DROP_IN.read_bytes())
                env = dict(os.environ, SYSTEMD_UNIT_PATH=str(root) + ":")
                result = subprocess.run([executable, "verify", str(tunnel), str(native)],
                    env=env, capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
