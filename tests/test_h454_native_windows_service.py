"""H454 Windows SCM source contract. No owner host or privileges used."""
from __future__ import annotations

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "deploy/h454/native-windows-service/Program.cs"
PROJECT = ROOT / "deploy/h454/native-windows-service/HermesCommanderNativeService.csproj"
CI = ROOT / ".github/workflows/h454-native-windows-service.yml"


class WindowsScmSourceContracts(unittest.TestCase):
    def test_native_scm_lifecycle_is_deliberately_not_provisioned(self):
        code = SOURCE.read_text(encoding="utf-8")
        for marker in (
            "StartServiceCtrlDispatcherW", "RegisterServiceCtrlHandlerExW",
            "SetServiceStatus", 'ServiceName = "HermesCommanderNative"',
            r'ServiceAccount = @"NT SERVICE\HermesCommanderNative"',
            'StartMode = "DISABLED"', 'AccessMode = "READ_ONLY"',
            "CanActivate = false", "CanInstall = false",
            "NATIVE_NOT_PROVISIONED = 454",
            "Report(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR",
            'args[0] == "--self-test"', 'args[0] != "--service"',
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, code)
        self.assertNotIn("private const uint SERVICE_RUNNING", code)
        self.assertNotIn("Report(SERVICE_RUNNING,", code)
        self.assertNotIn("StartServiceW", code)
        self.assertNotIn("CreateServiceW", code)
        self.assertNotIn("ChangeServiceConfigW", code)

    def test_binary_has_no_unapproved_host_side_effects(self):
        code = SOURCE.read_text(encoding="utf-8")
        for forbidden in (
            "Process.Start", "ProcessStartInfo", "File.Read", "File.Write",
            "Directory.", "Registry.", "HttpClient", "TcpClient",
            "Socket(", "websockets", "ReadFile", "WriteFile",
            "CryptUnprotectData", "LoadLibrary", "DllImport(\"kernel32",
            "OpenProcessToken", "SetNamedSecurityInfo", "WinForms",
            "PowerShell", "CreateProcessW", "ShellExecute",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, code)
        project = PROJECT.read_text(encoding="utf-8")
        for required in (
            "<OutputType>Exe</OutputType>",
            "<TargetFramework>net10.0-windows</TargetFramework>",
            "<SelfContained>true</SelfContained>",
            "<PublishSingleFile>true</PublishSingleFile>",
        ):
            self.assertIn(required, project)
        self.assertNotIn("PackageReference", project)
        self.assertNotIn("PostBuildEvent", project)

    def test_ci_is_disposable_and_never_publishes_unsigned_service(self):
        yml = CI.read_text(encoding="utf-8")
        for required in (
            "runs-on: windows-2025", "permissions:", "contents: read",
            "persist-credentials: false", "--self-test",
            "StartMode", "Disabled", "sc.exe create",
            "sc.exe delete", "finally", "H454_WIN32_SCM_DISABLED=PASS",
            "H454_WIN32_SCM_NOT_PROVISIONED=PASS",
            "H454_OWNER_WINDOWS_HOST=NOT_RUN",
        ):
            with self.subTest(required=required):
                self.assertIn(required, yml)
        self.assertIn("runs-on: windows-2025", yml)
        self.assertIn("$actual.ServiceSpecificExitCode -ne 454", yml)
        self.assertIn("sc.exe config $name start= disabled", yml)
        for forbidden in (
            "workflow_dispatch", "upload-artifact", "HERMES_DEPLOY_KEY",
            "secrets.", "ssh ", "scp ", "docker ",
            "Start-Service", "Set-Service",
            "service start", "sudo ", "pwsh -EncodedCommand",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, yml)


if __name__ == "__main__":
    unittest.main()
