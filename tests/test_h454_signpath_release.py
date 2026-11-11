"""Hermes #454 SignPath signed release - source-only fail-closed gates."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/h454-native-win32-signpath-release.yml"
VERIFY = ROOT / "scripts/h454_verify_signed_windows_msi.ps1"


class SignPathReleaseSourceTests(unittest.TestCase):
    def test_manual_main_sha_osi_license_owner_gate_is_not_optional(self):
        content = WORKFLOW.read_text(encoding="utf-8")
        for marker in (
            "workflow_dispatch:", "source_sha:", "refs/heads/main",
            "H454_SIGNPATH=HOLD_SOURCE_SHA", "H454_SIGNPATH=HOLD_MAIN_MOVED",
            "H454_SIGNPATH=HOLD_CI_NOT_GREEN", "H454_SIGNPATH=HOLD_ELIGIBILITY_OR_KEYS",
            "H454_SIGNPATH=HOLD_OSI_LICENSE_UNDECLARED",
            "H454_SIGNPATH_OSS_APPROVED", "LICENSE",
            "environment:", "h454-signpath-release",
            "H454_SIGNPATH_API_TOKEN", "contents: read", "actions: read",
            "persist-credentials: false",
            "Hermes repository checks", "Hermes Control Center UI",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, content)
        self.assertNotIn("push:\n", content)
        self.assertNotIn("pull_request:\n", content)

    def test_signature_verification_before_signed_delivery(self):
        content = WORKFLOW.read_text(encoding="utf-8")
        verify = VERIFY.read_text(encoding="utf-8")
        for required in (
            "signpath/github-action-submit-signing-request@f6d04783b4569d051e0c80105fe66e82819d0092",
            "github-artifact-id:", "artifact-configuration-slug:",
            "wait-for-completion: true",
            "H454_SIGNPATH_UNSIGNED_CANDIDATE_READY=YES",
            "h454-signpath-request-UNSIGNED-never-install",
            "h454-signpath-VERIFIED-signed-msi",
            "h454_verify_signed_windows_msi.ps1",
            "H454_OWNER_WINDOWS_HOST_INSTALL=NOT_RUN",
        ):
            self.assertIn(required, content)
        self.assertLess(
            content.index("Validate trusted signatures on BOTH"),
            content.index("Upload VERIFIED signed MSI"),
        )
        for required in (
            "Get-AuthenticodeSignature", "Status -ne 'Valid'",
            "SignPath Foundation", "TimeStamperCertificate",
            "signer_thumbprint", "PUBLISHER_MISMATCH", "SOURCE_SHA_MISMATCH",
            "msiexec.exe", "/a", "VerifyAuthenticode $exe",
            "H454_SIGNPATH_MSI_AND_EXE_VALID=PASS",
            "H454_SIGNPATH_MSI_SERVICE_WORKER_VALID=PASS",
            "WORKER_PUBLISHER_MISMATCH",
            "worker_sha256",
            "H454_SIGNPATH_OWNER_HOST_NOT_INSTALLED=YES",
        ):
            self.assertIn(required, verify)
        self.assertNotIn("sc.exe start", verify)
        self.assertNotIn("Start-Service", verify)
        self.assertNotIn("New-Service", verify)
        self.assertNotIn("http://", verify)

    def test_worker_is_built_only_in_windows_ci_and_refuses_foreign_sid(self):
        script = (ROOT / "scripts/h454_package_win32_worker.ps1").read_text(
            encoding="utf-8")
        for marker in (
            "RUNNER_OS", "GITHUB_WORKSPACE", "git rev-parse HEAD",
            "pyinstaller==6.22.3", "websockets==17.2",
            "H454_WIN32_WORKER_PACKAGED_SYNTHETIC=PASS",
            "H454_OWNER_WINDOWS_ORIGINAL_HOST=NOT_RUN",
            "--hidden-import websockets.sync.client",
            "H454_WIN32_WORKER_BUILD_HOLD_WRONG_SID_NOT_DENIED",
        ):
            self.assertIn(marker, script)
        for forbidden in (
            "HERMES_DEPLOY_KEY", "ssh ", "scp ", "New-Service",
            "Start-Service", "Set-Service", "Invoke-Expression",
            "powershell -EncodedCommand",
        ):
            self.assertNotIn(forbidden, script)

    def test_release_artifact_and_signing_secrets_never_in_repository(self):
        content = WORKFLOW.read_text(encoding="utf-8")
        assert re.search(r"signpath/github-action-submit-signing-request@[0-9a-f]{40}", content)
        self.assertNotIn("SIGNPATH_API_TOKEN=", content)
        self.assertNotIn("OPENAI_API_KEY", content)
        self.assertNotIn("HERMES_DEPLOY_KEY", content)
        self.assertNotIn("production-deploy", content)
        self.assertNotIn("msiexec.exe /i", content)
        self.assertNotIn("uses: actions/upload-artifact@v", content)
        self.assertIn("retention-days: 1", content)
        self.assertIn("retention-days: 7", content)


if __name__ == "__main__":
    unittest.main()
