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
JOB={"id":789,"run_id":123,"name":"candidate","status":"completed","conclusion":"success"}
JOBS={"total_count":1,"jobs":[JOB]}
LIST={"total_count":1,"workflow_runs":[RUN]}

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

    def test_job_log_uses_actions_read_endpoint_not_run_view(self):
        with patch.object(m,"api",return_value=JOBS) as endpoint, \
             patch.object(m,"run",return_value=(
                 f"H15_OFFLINE_BUNDLE_IMAGE_ID={IMAGE}\n"
                 f"H15_OFFLINE_BUNDLE_ARCHIVE_SHA256={HASH}\n")) as cli:
            log=m.candidate_job_log(123)
        self.assertIn("H15_OFFLINE_BUNDLE_IMAGE_ID=", log)
        endpoint.assert_called_once_with(
            f"repos/{m.REPO}/actions/runs/123/jobs?filter=latest&per_page=100")
        cli.assert_called_once_with(
            "api",f"repos/{m.REPO}/actions/jobs/789/logs",cap=16000000)

    def test_job_log_refuses_ambiguous_or_foreign_job(self):
        cases=(
            {"total_count":2,"jobs":[JOB, dict(JOB,id=999)]},
            {"total_count":1,"jobs":[]},
            {"total_count":1,"jobs":[dict(JOB,run_id=999)]},
            {"total_count":1,"jobs":[dict(JOB,conclusion="failure")]},
            {"total_count":1,"jobs":[dict(JOB,name="foreign")]},
            {"total_count":1,"jobs":[dict(JOB,id="789")]},
            {"total_count":True,"jobs":[JOB]},
        )
        for data in cases:
            with self.subTest(data=data), \
                 patch.object(m,"api",return_value=data), \
                 patch.object(m,"run") as cli:
                with self.assertRaisesRegex(m.StagingDenied,"ci_candidate_job"):
                    m.candidate_job_log(123)
                cli.assert_not_called()

    def test_transient_empty_workflow_listing_retries_and_pins_provenance(self):
        empty={"total_count":0,"workflow_runs":[]}
        with patch.object(m,"api",side_effect=[
                {"commit":{"sha":SHA}}, empty, empty, LIST,
                {"artifacts":[ART]}, JOBS]) as endpoint, \
             patch.object(m,"run",return_value=(
                 f"H15_OFFLINE_BUNDLE_IMAGE_ID={IMAGE}\n"
                 f"H15_OFFLINE_BUNDLE_ARCHIVE_SHA256={HASH}\n")):
            result=m.discover()
        self.assertEqual(result["run_id"],123)
        self.assertEqual(result["sha"],SHA)
        self.assertEqual(result["image"],IMAGE)
        self.assertEqual(result["archive"],HASH)
        self.assertEqual(endpoint.call_count,6)

    def test_permanent_empty_workflow_listing_fails_closed_bounded(self):
        empty={"total_count":0,"workflow_runs":[]}
        with patch.object(m,"api",side_effect=[
                {"commit":{"sha":SHA}},
                *[empty for _ in range(m.MAX_CANDIDATE_LIST_ATTEMPTS)]]) as endpoint, \
             patch.object(m,"run") as logs:
            with self.assertRaisesRegex(
                    m.StagingDenied,"^successful_main_candidate_missing$"):
                m.discover()
            self.assertEqual(endpoint.call_count,1+m.MAX_CANDIDATE_LIST_ATTEMPTS)
            logs.assert_not_called()

    def test_malformed_listing_fails_without_retries_or_download(self):
        cases=(
            {"workflow_runs":None,"total_count":0},
            {"workflow_runs":[]},
            {"workflow_runs":[],"total_count":True},
            {"workflow_runs":[RUN],"total_count":0},
        )
        for malformed in cases:
            with self.subTest(malformed=malformed), \
                 patch.object(m,"api",side_effect=[
                     {"commit":{"sha":SHA}}, malformed]) as endpoint, \
                 patch.object(m,"run") as logs:
                with self.assertRaisesRegex(
                        m.StagingDenied,"^candidate_listing_invalid$"):
                    m.discover()
                self.assertEqual(endpoint.call_count,2)
                logs.assert_not_called()

    def test_nonempty_untrusted_runs_never_trigger_retry(self):
        invalid=dict(RUN,conclusion="failure")
        with patch.object(m,"api",side_effect=[
                {"commit":{"sha":SHA}},
                {"total_count":1,"workflow_runs":[invalid]}]) as endpoint, \
             patch.object(m,"run") as logs:
            with self.assertRaisesRegex(
                    m.StagingDenied,"^successful_main_candidate_missing$"):
                m.discover()
            self.assertEqual(endpoint.call_count,2)
            logs.assert_not_called()

    def test_exact_main_ci_log_pins(self):
        with patch.object(m,"api",side_effect=[
                {"commit":{"sha":SHA}},
                {"total_count":2,"workflow_runs":[RUN,dict(RUN,head_sha="0"*40,id=999)]},
                {"artifacts":[ART]}, JOBS]),patch.object(m,"run",return_value=(
                    f"H15_OFFLINE_BUNDLE_IMAGE_ID={IMAGE}\n"
                    f"H15_OFFLINE_BUNDLE_ARCHIVE_SHA256={HASH}\n")):
            self.assertEqual(m.discover(),dict(GOOD,current_main_sha=SHA,
                                                      ancestor_candidate_reused=False))
    def test_current_main_dispatch_candidate_admitted(self):
        dispatched = dict(RUN, event="workflow_dispatch", id=123)
        with patch.object(m, "api", side_effect=[
                {"commit": {"sha": SHA}},
                {"total_count": 1, "workflow_runs": [dispatched]},
                {"artifacts": [ART]}, JOBS]), \
             patch.object(m, "run", return_value=(
                 f"H15_OFFLINE_BUNDLE_IMAGE_ID={IMAGE}\\n"
                 f"H15_OFFLINE_BUNDLE_ARCHIVE_SHA256={HASH}\\n")):
            result = m.discover()
        self.assertEqual(result["sha"], SHA)
        self.assertFalse(result["ancestor_candidate_reused"])
        self.assertEqual(result["run_id"], 123)

    def test_stale_dispatch_candidate_rejected_before_download(self):
        old_dispatch = dict(RUN, event="workflow_dispatch", id=123)
        with patch.object(m, "api", side_effect=[
                {"commit": {"sha": "d" * 40}},
                {"total_count": 1, "workflow_runs": [old_dispatch]}]) as api, \
             patch.object(m, "run") as downloaded:
            with self.assertRaisesRegex(
                    m.StagingDenied, "^successful_main_candidate_missing$"):
                m.discover()
            self.assertEqual(api.call_count, 2)
            downloaded.assert_not_called()

    def test_foreign_event_or_branch_not_eligible(self):
        for candidate in (dict(RUN, event="pull_request"),
                          dict(RUN, event="workflow_dispatch", head_branch="other")):
            with self.subTest(candidate=candidate), \
                 patch.object(m, "api", side_effect=[
                     {"commit": {"sha": SHA}},
                     {"total_count": 1, "workflow_runs": [candidate]}]), \
                 patch.object(m, "run") as downloaded:
                with self.assertRaisesRegex(
                        m.StagingDenied, "^successful_main_candidate_missing$"):
                    m.discover()
                downloaded.assert_not_called()

    def test_no_main_candidate_refuse(self):
        empty={"total_count":0,"workflow_runs":[]}
        with patch.object(m,"api",side_effect=[
                {"commit":{"sha":SHA}},
                *[empty for _ in range(m.MAX_CANDIDATE_LIST_ATTEMPTS)]]):
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
                LIST,unrelated, {"artifacts":[ART]}, JOBS]), \
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
                        {"commit":{"sha":"d"*40}},LIST,
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
                LIST,
                {"artifacts":[dict(ART,expired=True)]}]):
            with self.assertRaisesRegex(m.StagingDenied,"expired"):
                m.discover()
    def test_conflicting_ci_image_pins_rejected(self):
        with patch.object(m,"api",side_effect=[
                {"commit":{"sha":SHA}},
                LIST,
                {"artifacts":[ART]}, JOBS]),patch.object(m,"run",return_value=(
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
            with patch.object(m,"run",return_value=""),                 patch.object(m,"verify",return_value={}),                 patch.object(m.os,"geteuid",return_value=0),                 patch.object(m,"private",return_value=None),                 patch.object(m,"admit",return_value={"status":"PREFLIGHT_PASS","candidate_image":IMAGE}) as checked,                 patch.object(m.subprocess,"run",return_value=command):
                # No Docker host in this test: only explicit loader call mocked.
                with patch.object(m.Path,"is_file",return_value=True):
                    result=m.stage(root,GOOD,load=True)
                self.assertEqual(result["status"],"IMAGE_LOADED_PREFLIGHT_PASS_NO_CUTOVER")
                self.assertEqual(result["runtime_image_id"],IMAGE)
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
