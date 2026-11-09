"""Hermes #454: source-only Windows GUI preview contract.

Never starts the Windows application, reads owner device paths, installs a
service, invokes UAC or contacts any host. These tests inspect checked-in
source and the existing authoritative original-Windows root policy.
"""
from __future__ import annotations

from pathlib import Path
import re
import unittest

from device_fabric.native_install_preview import WINDOWS_ROOTS

BASE = Path(__file__).resolve().parents[1]
CS = BASE / "deploy/h454/native-windows-preview/Program.cs"
PROJECT = BASE / "deploy/h454/native-windows-preview/HermesCommanderNativePreview.csproj"
WORKFLOW = BASE / ".github/workflows/h454-native-windows-preview.yml"


class WindowsNativePreviewPolicy(unittest.TestCase):
    def test_original_root_selection_exactly_matches_existing_owner_policy(self):
        source = CS.read_text(encoding="utf-8")
        self.assertIn("ApprovedReadRoots =", source)
        section = source.split("ApprovedReadRoots =", 1)[1].split("];", 1)[0]
        entries = re.findall(r'\("([^"]+)", @"([^"]+)"\)', section)
        self.assertEqual(len(entries), 5)
        self.assertEqual({root for _, root in entries}, set(WINDOWS_ROOTS.values()))
        self.assertEqual(len(set(label for label, _ in entries)), 5)
        self.assertNotIn(r"D:\Pet-projects", {root for _, root in entries})

    def test_preview_cannot_start_installer_or_access_host(self):
        source = CS.read_text(encoding="utf-8")
        for expected in (
            'CanInstall = false', 'InitialState = "DISABLED"',
            'AccessMode = "READ_ONLY"', 'SignatureStatus = "NOT_SIGNED"',
            "Application.Run(new ScopePreviewForm(Revision()))",
            'args[0] == "--self-test"', "return SelfTest(args[1]);",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, source)
        for forbidden in (
            "Process.Start", "ServiceController", "DllImport", "HttpClient",
            "TcpClient", "Registry.", "File.Write", "Directory.Create",
            "ProcessStartInfo", "sc.exe", "PowerShell",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)

    def test_no_unapproved_new_install_or_persistent_service_dependency(self):
        project = PROJECT.read_text(encoding="utf-8")
        self.assertIn("<OutputType>WinExe</OutputType>", project)
        self.assertIn("<TargetFramework>net10.0-windows</TargetFramework>", project)
        self.assertIn("<UseWindowsForms>true</UseWindowsForms>", project)
        self.assertIn("<SelfContained>true</SelfContained>", project)
        self.assertIn("<PublishSingleFile>true</PublishSingleFile>", project)
        self.assertNotIn("PackageReference", project)
        self.assertNotIn("PostBuildEvent", project)
        self.assertNotIn("Exec Command=", project)

    def test_github_run_is_separate_manual_source_bundle_not_host_install(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        for required in (
            "workflow_dispatch:", "pull_request:", "contents: read",
            "actions: read", "persist-credentials: false", "refs/heads/main",
            "Get-AuthenticodeSignature", "NotSigned", "--self-test",
            "H454_WIN32_NATIVE_HOST_PASS=NOT_RUN",
            "H454_WIN32_INSTALL_AVAILABLE=NO",
            "github.event_name == 'workflow_dispatch'",
        ):
            with self.subTest(required=required):
                self.assertIn(required, workflow)
        for forbidden in (
            "HERMES_DEPLOY_KEY", "HERMES_DEPLOY_TARGET", "secrets.",
            "ssh -", "scp ", "sudo ", "systemctl", "docker ",
            "sc create", "sc start", "Start-Service", "New-Service",
            "pwsh -EncodedCommand",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, workflow)


if __name__ == "__main__":
    unittest.main()
