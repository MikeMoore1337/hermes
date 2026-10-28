"""Source-only fail-closed contracts for Windows Docker capacity check."""
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"scripts"/"h445_windows_docker_capacity.ps1"

class H445CapacitySourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.src=SCRIPT.read_text(encoding="utf-8")

    def test_read_only_pinned_target(self):
        for required in (
            "ValidatePattern('^[a-f0-9]{64}$')",
            "/hermes-h15-windows-permanent",
            "sha256:8d28b0e1158b01c179ae1e6e1e399acaf3f502675522136d931ce08f2851a5a3",
            "'96'", "'536870912'", "'65534:65534'",
            "'container', 'inspect'", "'stats', '--no-stream'",
            "'top', $ContainerId, '-eo', 'pid,ppid,stat'",
        ):
            with self.subTest(required=required):
                self.assertIn(required,self.src)
        for forbidden in (
            "'exec'","'run'","'restart'","'stop'","'kill'","'rm'","'cp'",
            "Stop-Process","Start-Process","Invoke-Expression","docker.exe -H",
            ".Config.Env","HostConfig.Binds","{{json .}}"
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden,self.src)
        self.assertNotIn("'top', $ContainerId, '-eo', 'stat'", self.src)

    def test_optional_top_failure_keeps_saturated_pid_evidence(self):
        src=self.src
        for marker in (
            "function Top-Summary", "process_state_status = 'NOT_VERIFIED'",
            "visible_zombies = $null", "$top = Top-Summary -Lines $rows",
            "catch {", "[Math]::Max(0, 96 - $pids)",
            "if ($headroom -lt 24) { 'HOLD' }",
            "pid1_reaper_verified = $false",
            "host_change_authorized = $false",
            "changes_applied = $false",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker,src)

if __name__ == "__main__":
    unittest.main()
