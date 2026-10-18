"""Regression contracts for owner-gated Windows presence bootstrap."""
from pathlib import Path
import unittest

SCRIPT = (Path(__file__).resolve().parents[1] /
          "deploy/h15-device-fabric-windows-autostart.ps1")


class WindowsBootstrapSafetyTests(unittest.TestCase):
    def test_native_windows_argument_uses_numeric_string_conversion(self):
        code = SCRIPT.read_text()
        self.assertIn("assert websockets.__version__ == str(16.0)", code)

    def test_repair_requires_protected_unchanged_credentials(self):
        code = SCRIPT.read_text()
        for needle in ("REPAIR_SOURCE_MISMATCH", "PRIVATE_ACL_FAILED",
                       "MACHINE_WIDE_PYTHON_REQUIRED", "Get-FileHash",
                       "REPAIR_UNTRUSTED_STATE"):
            self.assertIn(needle, code)
        self.assertLess(code.index("icacls.exe $state"),
                        code.index("Copy-Item -LiteralPath"))

    def test_background_principal_and_boot_trigger_unchanged(self):
        code = SCRIPT.read_text()
        self.assertIn("-AtStartup", code)
        self.assertIn("-LogonType ServiceAccount", code)
        self.assertIn("NT AUTHORITY\\LOCAL SERVICE", code)
        self.assertIn("-RunLevel Limited", code)
        self.assertIn("AUTOSTART=NOT_ENABLED", code)


if __name__ == "__main__":
    unittest.main()
