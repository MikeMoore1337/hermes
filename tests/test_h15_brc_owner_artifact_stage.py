"""Offline unit tests for exact-main OCI stage without any owner-host operations."""
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from scripts import h15_brc_owner_artifact_stage as m

SHA="a"*40
IMAGE="sha256:"+"b"*64
HASH="c"*64
GOOD={"sha":SHA,"run_id":123,"artifact_id":456,"image":IMAGE,"archive":HASH}
RUN={"id":123,"head_sha":SHA,"head_branch":"main","event":"push",
     "conclusion":"success","status":"completed",
     "name":"H-15 pinned Remote Commander candidate (isolated CI only)"}
ART={"name":m.ARTIFACT,"id":456,"expired":False,"size_in_bytes":110000000}

class StagingTests(unittest.TestCase):
    def test_exact_main_ci_log_pins(self):
        with patch.object(m,"api",side_effect=[
                {"commit":{"sha":SHA}},
                {"workflow_runs":[RUN,dict(RUN,head_sha="0"*40,id=999)]},
                {"artifacts":[ART]}]),patch.object(m,"run",return_value=(
                    f"H15_OFFLINE_BUNDLE_IMAGE_ID={IMAGE}\n"
                    f"H15_OFFLINE_BUNDLE_ARCHIVE_SHA256={HASH}\n")):
            self.assertEqual(m.discover(),GOOD)
    def test_no_latest_ci_refuse(self):
        with patch.object(m,"api",side_effect=[
                {"commit":{"sha":SHA}},
                {"workflow_runs":[dict(RUN,head_sha="0"*40)]}]):
            with self.assertRaisesRegex(m.StagingDenied,"exact_main"):
                m.discover()
    def test_expired_artifact_rejected(self):
        with patch.object(m,"api",side_effect=[
                {"commit":{"sha":SHA}},
                {"workflow_runs":[RUN]},
                {"artifacts":[dict(ART,expired=True)]}]):
            with self.assertRaisesRegex(m.StagingDenied,"expired"):
                m.discover()
    def test_conflicting_ci_image_pins_rejected(self):
        with patch.object(m,"api",side_effect=[
                {"commit":{"sha":SHA}},
                {"workflow_runs":[RUN]},
                {"artifacts":[ART]}]),patch.object(m,"run",return_value=(
                    f"H15_OFFLINE_BUNDLE_IMAGE_ID={IMAGE}\n"
                    f"H15_OFFLINE_BUNDLE_IMAGE_ID=sha256:{'e'*64}\n"
                    f"H15_OFFLINE_BUNDLE_ARCHIVE_SHA256={HASH}\n")):
            with self.assertRaisesRegex(m.StagingDenied,"ambiguous"):
                m.discover()
    def test_download_then_verify_never_docker(self):
        with TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700)
            with patch.object(m,"run",return_value="") as client,\
                 patch.object(m,"verify",return_value={}) as check,\
                 patch.object(m.subprocess,"run") as native:
                out=m.stage(root,GOOD)
                self.assertEqual(out["status"],"VERIFIED_OFFLINE_ONLY")
                client.assert_called_once()
                check.assert_called_once()
                native.assert_not_called()
    def test_existing_invalid_not_overwritten(self):
        with TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700)
            (root/("main-"+SHA)).mkdir(mode=0o700)
            with patch.object(m,"verify",side_effect=m.BundleDenied("bad")),\
                 patch.object(m,"run") as client:
                with self.assertRaisesRegex(m.StagingDenied,"not_overwritten"):
                    m.stage(root,GOOD)
                client.assert_not_called()
    def test_symlinked_candidate_rejected(self):
        with TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700)
            (root/("main-"+SHA)).symlink_to("/tmp")
            with patch.object(m,"run") as client:
                with self.assertRaisesRegex(m.StagingDenied,"unsafe_existing"):
                    m.stage(root,GOOD)
                client.assert_not_called()
    def test_unpinned_candidate_refused_before_download(self):
        with TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700)
            with patch.object(m,"run") as client:
                with self.assertRaisesRegex(m.StagingDenied,"invalid_pinned"):
                    m.stage(root,dict(GOOD,image="latest"))
                client.assert_not_called()
    def test_load_not_allowed_as_unprivileged(self):
        with TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700)
            with patch.object(m,"run",return_value=""),\
                 patch.object(m,"verify",return_value={}),\
                 patch.object(m.os,"geteuid",return_value=1234),\
                 patch.object(m.subprocess,"run") as native:
                # Root directory owner must match the fake user for this test.
                with patch.object(m,"private",return_value=None):
                    with self.assertRaisesRegex(m.StagingDenied,"root_required"):
                        m.stage(root,GOOD,load=True)
                native.assert_not_called()

if __name__=="__main__":
    unittest.main()
