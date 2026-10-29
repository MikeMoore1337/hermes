"""Real PS5.1 subprocess oracles; never access Docker or owner credentials."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/h454_windows_native_preflight.ps1"
POWERSHELL = shutil.which("powershell.exe")


if os.name == "nt":
    class WindowsNativePreflightTests(unittest.TestCase):
        def invoke(self, source):
            self.assertIsNotNone(POWERSHELL, "Windows tests require PowerShell 5.1")
            result = subprocess.run(
                [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", source],
                env={**os.environ, "H454_PREFLIGHT_SCRIPT": str(SCRIPT),
                     "H454_TEST_PYTHON": sys.executable},
                text=True, capture_output=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, "")
            return result.stdout.strip()

        def test_resolves_interpreter_instead_of_launcher(self):
            actual = self.invoke("""
                . $env:H454_PREFLIGHT_SCRIPT
                function py.exe { $global:LASTEXITCODE=0; $env:H454_TEST_PYTHON }
                Get-H454Python
            """)
            self.assertEqual(actual.casefold(), sys.executable.casefold())

        def test_duplicate_command_matches_are_not_concatenated(self):
            actual = self.invoke("""
                . $env:H454_PREFLIGHT_SCRIPT
                function Get-Command {
                    [pscustomobject]@{Path=$env:H454_TEST_PYTHON;Source='wrong-source'}
                    [pscustomobject]@{Path='Z:\\private-marker\\other.exe';Source='wrong-source'}
                }
                Get-H454Application 'python.exe'
            """)
            self.assertEqual(actual.casefold(), sys.executable.casefold())

        def test_invalid_command_path_is_refused_without_leaking_it(self):
            output = self.invoke(r"""
                . $env:H454_PREFLIGHT_SCRIPT
                function Get-Command { [pscustomobject]@{Path='Z:\private-marker\missing.exe'} }
                try { Get-H454Application 'git.exe'; exit 9 }
                catch { Write-H454NativeFailure $_ }
            """)
            self.assertIn("H454_REASON=EXECUTABLE_RESOLUTION_FAILED", output)
            self.assertNotIn("private-marker", output)

        def test_missing_interpreter_diagnostic_does_not_expose_path(self):
            output = self.invoke(r"""
                . $env:H454_PREFLIGHT_SCRIPT
                try { Invoke-H454StdinProbe 'Z:\private-marker\missing python.exe'; exit 9 }
                catch { Write-H454NativeFailure $_ }
            """)
            self.assertIn("H454_NATIVE_PREFLIGHT=HOLD", output)
            self.assertIn("H454_WIN32_CODE=2", output)
            self.assertIn("H454_CHANGES_APPLIED=FALSE", output)
            self.assertNotIn("private-marker", output)

        def test_multiple_launcher_results_are_refused(self):
            output = self.invoke("""
                . $env:H454_PREFLIGHT_SCRIPT
                function py.exe { $global:LASTEXITCODE=0; 'first'; 'second' }
                try { Get-H454Python; exit 9 } catch { Write-H454NativeFailure $_ }
            """)
            self.assertIn("H454_REASON=PYTHON_RESOLUTION_FAILED", output)

        def test_launcher_path_is_not_accepted_as_python(self):
            output = self.invoke(r"""
                . $env:H454_PREFLIGHT_SCRIPT
                function py.exe { $global:LASTEXITCODE=0; 'C:\private-marker\py.exe' }
                try { Get-H454Python; exit 9 } catch { Write-H454NativeFailure $_ }
            """)
            self.assertIn("H454_REASON=PYTHON_PATH_INVALID", output)
            self.assertNotIn("private-marker", output)

        if sys.version_info[:2] == (3, 14):
            def test_real_ps51_utf8_stdin_reaches_direct_python(self):
                output = self.invoke("""
                    . $env:H454_PREFLIGHT_SCRIPT
                    if ($PSVersionTable.PSVersion.Major -ne 5) { exit 9 }
                    Invoke-H454StdinProbe $env:H454_TEST_PYTHON
                    'DIRECT_UTF8_PASS'
                """)
                self.assertEqual(output, "DIRECT_UTF8_PASS")


class PreflightSourceTests(unittest.TestCase):
    def test_has_no_runtime_mutations_or_credentials(self):
        source = SCRIPT.read_text(encoding="utf-8")
        for forbidden in ("docker.exe", "ConvertTo-SecureString", "Get-ScheduledTask",
                          "Set-Content", "Start-Process", "StandardInputEncoding"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
