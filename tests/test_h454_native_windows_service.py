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
            "CanActivate = true", "CanInstall = false",
            "NATIVE_NOT_PROVISIONED = 454",
            "NATIVE_OS_IDENTITY_DENIED = 455",
            "NativeHostAdmission.MatchesServiceUser()",
            "NativeHostAdmission.PrivateStateIsConfined()",
            "NativeHostAdmission.OriginalRootsAreKernelReadOnly()",
            "Report(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR",
            'args[0] == "--self-test"', 'args[0] != "--service"',
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, code)
        self.assertIn("private const uint SERVICE_RUNNING", code)
        self.assertIn("Report(SERVICE_RUNNING, NO_ERROR, 0, 0)", code)
        self.assertIn("WaitForAuthenticatedWelcome(", code)
        self.assertIn("NativeWorkerSupervisor.TryLaunch(Revision())", code)
        self.assertLess(code.index("WaitForAuthenticatedWelcome("),
                        code.index("Report(SERVICE_RUNNING, NO_ERROR, 0, 0)"))
        self.assertIn("StopRequested.Set();", code)
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
        supervisor = (ROOT / "deploy/h454/native-windows-service/NativeWorkerSupervisor.cs").read_text()
        for marker in (
            "signed-release.json", "ReceiptMatches(", "HashPinnedFile(",
            "NativeHostAdmission.InstallBinaryIsReadOnly(",
            "ProcessStartInfo settings = new(workerPath)",
            "UseShellExecute = false", "CreateNoWindow = true",
            'settings.ArgumentList.Add("--run-once")',
            'settings.ArgumentList.Add("--service-supervised")',
            "settings.Environment.Clear()", "RedirectStandardOutput = true",
            'internal const string Ready = "H454_NATIVE_BRC_SESSION_READY=YES"',
            "WaitForAuthenticatedWelcome(", "StopWorker(",
        ):
            self.assertIn(marker, supervisor)
        self.assertNotIn("cmd.exe", supervisor)
        self.assertNotIn("powershell.exe", supervisor)
        self.assertNotIn("ShellExecute(", supervisor)
        self.assertNotIn("http://", supervisor)

    def test_real_os_security_code_does_not_grant_privileges(self):
        gate = (ROOT / "deploy/h454/native-windows-service/NativeHostAdmission.cs").read_text(encoding="utf-8")
        for required in (
            "WindowsIdentity.GetCurrent()", "NT SERVICE",
            "SecurityIdentifier", "AreAccessRulesProtected",
            "FileSystemAclExtensions.GetAccessControl",
            "CreateFileW", "FILE_FLAG_OPEN_REPARSE_POINT",
            "FILE_ADD_FILE", "forbiddenWrite.IsInvalid",
            "manifest.json", "device.json",
            "OriginalRootsAreKernelReadOnly",
            "RestrictedDaclForIdentity", "unsafeRights",
            "FILE_ADD_SUBDIRECTORY", "FILE_WRITE_ATTRIBUTES",
            "DELETE_RIGHT", "WRITE_DAC", "WRITE_OWNER",
        ):
            with self.subTest(marker=required):
                self.assertIn(required, gate)
        for forbidden in (
            "Process.Start", "File.WriteAll", "File.Create",
            "Directory.CreateDirectory", "Registry.",
            "Socket(", "HttpClient", "Net.WebSockets",
            "sc.exe", "icacls", "SetAccessControl",
            "SetNamedSecurityInfo", "CryptUnprotectData",
        ):
            self.assertNotIn(forbidden, gate)
        self.assertIn(r'@"D:\Pet-projects\hermes"', gate)
        self.assertIn("signed-release.json", gate)
        self.assertIn("ProtectedStateFile(", gate)
        self.assertIn("InstallBinaryIsReadOnly(", gate)

    def test_ci_is_disposable_and_never_publishes_unsigned_service(self):
        yml = CI.read_text(encoding="utf-8")
        for required in (
            "runs-on: windows-2025", "permissions:", "contents: read",
            "persist-credentials: false", "--self-test",
            "StartMode", "Disabled", "sc.exe create",
            "sc.exe delete", "finally", "H454_WIN32_SCM_DISABLED=PASS",
            "H454_WIN32_SCM_WRONG_SID=DENIED",
            "H454_WIN32_PRIVATE_ACL_FIXTURE=PASS",
            "H454_WIN32_SIGNED_RELEASE_RECEIPT=PASS",
            "H454_OWNER_WINDOWS_HOST=NOT_RUN",
        ):
            with self.subTest(required=required):
                self.assertIn(required, yml)
        self.assertIn("runs-on: windows-2025", yml)
        self.assertIn("$actual.ServiceSpecificExitCode -ne 455", yml)
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
