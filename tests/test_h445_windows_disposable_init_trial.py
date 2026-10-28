"""Source-only contracts for owner-gated ephemeral H445 init test."""
from pathlib import Path
import unittest
SRC=(Path(__file__).resolve().parents[1]/"scripts/h445_windows_disposable_init_trial.ps1").read_text(encoding="utf-8")

class TrialContracts(unittest.TestCase):
    def test_owner_gate_and_read_only_default(self):
        for word in ("'Preflight','Test'","$Mode='Preflight'",
                     "[switch]$OwnerApproved",
                     "if (-not $OwnerApproved) { Deny 'EXPLICIT_TEST_APPROVAL_REQUIRED' }",
                     "'H445_TEST_CONTAINER_CREATED=FALSE'","'H445_ROLLBACK_VERIFIED=FALSE'"):
            self.assertIn(word,SRC)
        self.assertLess(SRC.index("EXPLICIT_TEST_APPROVAL_REQUIRED"),SRC.index("$docker run"))
    def test_one_unconnected_ephemeral_container_only(self):
        for word in ("--rm","--pull=never","--init","--network none","--read-only",
                     "--user 65534:65534","--pids-limit 96","--memory 512m",
                     "--cap-drop ALL","--security-opt no-new-privileges",
                     "--entrypoint node","--tmpfs /tmp:rw,nosuid,nodev,size=16m"):
            self.assertIn(word,SRC)
        for bad in ("--mount","--volume","--env","--publish","--privileged",
                    "docker stop","docker restart","docker exec","docker rm",
                    "docker create","--pid host","--network host",
                    "Stop-Process","Start-Process","Invoke-Expression",
                    ".Config.Env","HostConfig.Binds"):
            with self.subTest(bad=bad):
                self.assertNotIn(bad,SRC)
    def test_pinned_image_and_no_e2e_claim(self):
        self.assertIn("571a1e2bede31a07638b896e3ef2de677dafa1c000e4a7975e7996257f8ea162",SRC)
        self.assertIn("sha256:8d28b0e1158b01c179ae1e6e1e399acaf3f502675522136d931ce08f2851a5a3",SRC)
        self.assertIn("/hermes-h15-windows-permanent",SRC)
        self.assertIn("H445_PRODUCTION_CUTOVER=NOT_AUTHORIZED",SRC)
        self.assertIn("H445_PROCESS_TREE_TERMINATION=NOT_TESTED",SRC)
    def test_synthetic_node_reaper_contract(self):
        self.assertIn("setTimeout(()=>process.exit(2),5000)",SRC)
        self.assertIn("max-pids<24",SRC)
        self.assertIn("zombies!==0",SRC)
        self.assertIn("H445_REAPER_PROBE=PASS",SRC)

if __name__ == "__main__":
    unittest.main()
