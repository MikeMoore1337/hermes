"""Offline unit tests for exact-main OCI stage without any owner-host operations."""
from pathlib import Path
from types import SimpleNamespace
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
    def test_missing_gh_auth_refuses_before_any_api_request(self):
        with patch.object(m.shutil, "which", return_value="/usr/bin/gh"), \
             patch.object(m.subprocess, "run",
                          return_value=SimpleNamespace(returncode=1)) as cli:
            with self.assertRaisesRegex(m.StagingDenied, "^github_cli_auth_required$"):
                m.run("api", f"repos/{m.REPO}/branches/main")
            cli.assert_called_once()
            self.assertEqual(cli.call_args.args[0],
                             ["gh", "auth", "status", "--hostname", "github.com"])

    def test_authenticated_gh_cli_can_read_api(self):
        result = SimpleNamespace(returncode=0, stdout='{"test":true}')
        with patch.object(m.shutil, "which", return_value="/usr/bin/gh"), \
             patch.object(m.subprocess, "run", return_value=result) as cli:
            self.assertEqual(m.api(f"repos/{m.REPO}/branches/main"), {"test": True})
            self.assertEqual(cli.call_count, 2)
            self.assertEqual(cli.call_args_list[0].args[0][:3], ["gh", "auth", "status"])
            self.assertEqual(cli.call_args_list[1].args[0][:2], ["gh", "api"])

    def test_exact_main_ci_log_pins(self):
        with patch.object(m,"api",side_effect=[
                {"commit":{"sha":SHA}},
                {"workflow_runs":[RUN,dict(RUN,head_sha="0"*40,id=999)]},
                {"artifacts":[ART]}]),patch.object(m,"run",return_value=(
                    f"H15_OFFLINE_BUNDLE_IMAGE_ID={IMAGE}\n"
                    f"H15_OFFLINE_BUNDLE_ARCHIVE_SHA256={HASH}\n")):
            self.assertEqual(m.discover(),dict(GOOD,current_main_sha=SHA,
                                                      ancestor_candidate_reused=False))
    def test_no_main_candidate_refuse(self):
        with patch.object(m,"api",side_effect=[
                {"commit":{"sha":SHA}}, {"workflow_runs":[]}]):
            with self.assertRaisesRegex(m.StagingDenied,"successful_main"):
                m.discover()
    def test_old_candidate_allowed_only_if_ancestor_and_brc_unchanged(self):
        current="d"*40
        source_sha=SHA
        unrelated={"status":"ahead","merge_base_commit":{"sha":source_sha},
                   "ahead_by":9,"behind_by":0,
                   "files":[{"filename":".github/workflows/quality.yml"},
                            {"filename":"hermes_toolperf/core.py"}]}
        with patch.object(m,"api",side_effect=[
                {"commit":{"sha":current}},
                {"workflow_runs":[RUN]},unrelated, {"artifacts":[ART]}]), \
             patch.object(m,"run",return_value=(
                    f"H15_OFFLINE_BUNDLE_IMAGE_ID={IMAGE}\n"
                    f"H15_OFFLINE_BUNDLE_ARCHIVE_SHA256={HASH}\n")):
            got=m.discover()
        self.assertEqual(got["sha"],source_sha)
        self.assertEqual(got["current_main_sha"],current)
        self.assertTrue(got["ancestor_candidate_reused"])

    def test_live_main_advanced_with_brc_edit_denied_before_download(self):
        for modified in ("scripts/h15_brc_harden_relay.py",
                         "deploy/h15/Dockerfile.brc-relay",
                         "tests/test_h15_brc_owner_artifact_stage.py",
                         ".github/workflows/h15-remote-commander-candidate.yml",
                         "pnpm-lock.yaml"):
            with self.subTest(modified=modified):
                with patch.object(m,"api",side_effect=[
                        {"commit":{"sha":"d"*40}},{"workflow_runs":[RUN]},
                        {"status":"ahead","merge_base_commit":{"sha":SHA},
                         "ahead_by":2,"behind_by":0,
                         "files":[{"filename":modified}]}]), \
                     patch.object(m,"run") as download:
                    with self.assertRaisesRegex(m.StagingDenied,
                                                "brc_input_modified"):
                        m.discover()
                    download.assert_not_called()

    def test_rename_from_sensitive_path_denied(self):
        with patch.object(m,"api",return_value={
                "status":"ahead","merge_base_commit":{"sha":SHA},
                "ahead_by":1,"behind_by":0,
                "files":[{"filename":"unrelated-renamed.py",
                          "previous_filename":"scripts/h15_brc_gateway.py"}]}):
            with self.assertRaisesRegex(m.StagingDenied,"brc_input_modified"):
                m.require_unchanged_brc_inputs(SHA,"d"*40)

    def test_not_ancestor_or_diff_truncated_denied(self):
        valid={"status":"ahead","merge_base_commit":{"sha":SHA},
               "ahead_by":1,"behind_by":0,"files":[]}
        cases=[dict(valid,status="diverged"),
               dict(valid,merge_base_commit={"sha":"f"*40}),
               dict(valid,behind_by=1),
               dict(valid,ahead_by=81),
               dict(valid,files=[{"filename":"harmless.txt"}]*300),
               dict(valid,files=None)]
        for condition in cases:
            with self.subTest(condition=condition), \
                 patch.object(m,"api",return_value=condition):
                with self.assertRaisesRegex(m.StagingDenied,"ancestry"):
                    m.require_unchanged_brc_inputs(SHA,"d"*40)

    def test_exact_current_main_skips_compare(self):
        with patch.object(m,"api") as api:
            self.assertFalse(m.require_unchanged_brc_inputs(SHA,SHA))
            api.assert_not_called()

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
    def test_explicit_root_load_requires_real_host_preflight(self):
        with TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700)
            command=type("P",(),{"returncode":0,
                   "stdout":"H15_BRC_IMAGE_OFFLINE_LOAD=PASS","stderr":""})()
            with patch.object(m,"run",return_value=""),                 patch.object(m,"verify",return_value={}),                 patch.object(m.os,"geteuid",return_value=0),                 patch.object(m,"private",return_value=None),                 patch.object(m,"admit",return_value={"status":"PREFLIGHT_PASS"}) as checked,                 patch.object(m.subprocess,"run",return_value=command):
                # No Docker host in this test: only explicit loader call mocked.
                with patch.object(m.Path,"is_file",return_value=True):
                    result=m.stage(root,GOOD,load=True)
                self.assertEqual(result["status"],"IMAGE_LOADED_PREFLIGHT_PASS_NO_CUTOVER")
                checked.assert_called_once()

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
