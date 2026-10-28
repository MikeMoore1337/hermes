"""H445 read-only task launcher source and secret-exposure contracts."""
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/h445_windows_task_launcher_preflight.ps1"

class TaskLauncherSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.src = SCRIPT.read_text(encoding="utf-8")

    def test_exact_task_and_immutable_container_pin(self):
        for required in (
            "HermesH15BRCWindows",
            "571a1e2bede31a07638b896e3ef2de677dafa1c000e4a7975e7996257f8ea162",
            "sha256:8d28b0e1158b01c179ae1e6e1e399acaf3f502675522136d931ce08f2851a5a3",
            "'Get-ScheduledTask'".replace("'",""), "Get-ScheduledTaskInfo",
            "'container', 'inspect'", "'image', 'inspect'",
            "'96|536870912|65534:65534|true|no|'".replace("'",""),
        ):
            with self.subTest(required=required):
                self.assertIn(required,self.src)

    def test_source_is_not_executed_or_exposed(self):
        for required in (
            "Get-FileArgument", "Get-FileHash", "[IO.File]::ReadAllText",
            "script_sha256", "script_uses_docker_text",
            "script_mentions_init_text", "original_image_available",
            "rollback_verified = $false", "restart_authorized = $false",
            "changes_applied = $false",
        ):
            with self.subTest(required=required):
                self.assertIn(required,self.src)
        for forbidden in (
            "Invoke-Expression", "iex ", "Start-Process", "Stop-Process",
            "Register-ScheduledTask", "Set-ScheduledTask", "Unregister-ScheduledTask",
            "Write-Output $body", "Write-Output $source",
            "docker run", "docker stop", "docker restart", "docker exec",
            ".Config.Env", "HostConfig.Binds", "{{json .}}",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden,self.src)

    def test_fail_closed_no_raw_errors(self):
        for required in (
            "UNEXPECTED_TASK_EXECUTABLE", "TASK_SOURCE_NOT_VERIFIED",
            "CONTAINER_IDENTITY_NOT_VERIFIED", "READONLY_PREFLIGHT_INCOMPLETE",
            "return $null", "Get-Item -LiteralPath $source",
            "[IO.FileAttributes]::ReparsePoint",
        ):
            self.assertIn(required,self.src)
        self.assertNotIn("Write-Output $_",self.src)
        self.assertNotIn("Write-Error $_",self.src)

if __name__ == "__main__":
    unittest.main()
