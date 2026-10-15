"""Offline tests: green release != performed CI and docker integration tests."""
from __future__ import annotations

import io
import json
import unittest
from unittest.mock import Mock, patch

from scripts import verify_upstream_release_ci as verifier

VERSION = "v0.22.1"
RUN, SHA, CLAIM = verifier.RELEASES[VERSION]


def job(index, name, conclusion, *, steps=None):
    return {"id": index, "name": name, "conclusion": conclusion,
            "steps": steps if steps is not None else []}


def step(name, conclusion):
    return {"name": name, "conclusion": conclusion}


def api_fixture(*, skipped=True, make_175=True):
    all_jobs = [
        job(1, "Full CI pipeline", "skipped" if skipped else "success"),
        job(2, "All release acceptance checks pass", "success"),
        job(3,
            "Publish tested Docker image / Assemble versioned manifest and digest receipt",
            "success"),
    ]
    for i, variant in enumerate(verifier.VARIANTS, 4):
        all_jobs.append(job(i,
            f"Docker build and tests / Build and test image ({variant})",
            "success",
            steps=[
                step("Run docker integration tests",
                     "skipped" if skipped else "success"),
                step("Verify release image identity", "success"),
            ]))
    if make_175:
        all_jobs.extend(job(100+i, f"Unrelated {i}", "skipped") for i in range(168))
    run = {
        "id": RUN, "head_sha": SHA, "name": f"Stable release {CLAIM}",
        "event": "workflow_dispatch", "conclusion": "success",
        "status": "completed",
    }
    def api(path):
        if path == verifier.ROOT + str(RUN):
            return dict(run)
        if path.startswith(verifier.ROOT + str(RUN) + "/jobs?per_page=100&page="):
            n = int(path.rsplit("=", 1)[-1])
            return {"total_count": len(all_jobs), "jobs": all_jobs[(n-1)*100:n*100]}
        raise AssertionError("unexpected public fetch path: " + path)
    return api, run, all_jobs


class OfficialReleaseCIContracts(unittest.TestCase):
    def test_actual_green_run_skipped_required_docker_integration(self):
        api, _, _ = api_fixture()
        result = verifier.review(VERSION, fetcher=api)
        self.assertEqual(result["status"],"UPSTREAM_REQUIRED_TESTS_SKIPPED")
        self.assertEqual(result["full_ci_job_conclusion"],"skipped")
        self.assertEqual(result["release_jobs_observed"],175)
        self.assertEqual(set(result["docker_integrations"]),set(verifier.VARIANTS))
        self.assertTrue(all(x == "skipped" for x in result["docker_integrations"].values()))
        self.assertFalse(result["tests_fully_executed_for_release"])
        self.assertTrue(result["any_required_tests_skipped"])
        self.assertFalse(result["resident_agent_allowed"])

    def test_even_every_reported_step_pass_is_not_signed_attestation(self):
        api, _, _ = api_fixture(skipped=False,make_175=False)
        result=verifier.review(VERSION,fetcher=api)
        self.assertEqual(result["status"],"UPSTREAM_TESTS_REPORTED_PASS_UNATTESTED")
        self.assertTrue(result["tests_fully_executed_for_release"])
        self.assertFalse(result["signed_build_attestation_verified"])
        self.assertFalse(result["complete_sbom_verified"])
        self.assertFalse(result["resident_agent_allowed"])

    def test_release_head_commit_must_match_exact_selected_run(self):
        api, head, jobs=api_fixture()
        head["head_sha"]="a"*40
        def swapped(path):
            return head if path == verifier.ROOT+str(RUN) else api(path)
        with self.assertRaisesRegex(verifier.ReleaseCIDenied,
                                     "release_run_identity_invalid"):
            verifier.review(VERSION,fetcher=swapped)

    def test_ambiguous_job_and_missing_docker_step_cannot_claim_green(self):
        for modify in ("duplicate_ci", "missing_step", "missing_job"):
            api, _, jobs = api_fixture(make_175=False)
            if modify == "duplicate_ci":
                jobs.append(job(99,"Full CI pipeline","success"))
            if modify == "missing_step":
                jobs[3]["steps"] = [step("Verify release image identity","success")]
            if modify == "missing_job":
                jobs.pop(3)
            with self.subTest(modify=modify):
                with self.assertRaises(verifier.ReleaseCIDenied):
                    verifier.review(VERSION,fetcher=api)

    def test_paging_denies_short_or_changed_total_or_duplicate_ids(self):
        for mode in ("count_drift", "short", "duplicate"):
            api, _, jobs = api_fixture()
            def broken(path):
                response=api(path)
                if "/jobs?" in path and "page=2" in path:
                    if mode=="count_drift":
                        response["total_count"]+=1
                    elif mode=="short":
                        response["jobs"]=[]
                    elif mode=="duplicate":
                        response["jobs"][0]["id"]=jobs[0]["id"]
                return response
            with self.subTest(mode=mode):
                with self.assertRaises(verifier.ReleaseCIDenied):
                    verifier.review(VERSION,fetcher=broken)

    def test_unknown_release_fails_before_network(self):
        fetcher=Mock()
        for release in ("latest",":stable","v0.23.0","../../123",None,5,[]):
            with self.subTest(release=str(release)):
                with self.assertRaisesRegex(verifier.ReleaseCIDenied,
                                            "release_not_allowlisted"):
                    verifier.review(release,fetcher=fetcher)
        fetcher.assert_not_called()

    def test_json_duplicate_payload_oversize_and_paths_rejected(self):
        for raw in (b"", b"not json", b"[]", b'{"x":1,"x":2}', b"a"*(verifier.MAX_BODY+1)):
            with self.subTest(bytes=len(raw)):
                with self.assertRaises(verifier.ReleaseCIDenied):
                    verifier.decode(raw)
        for path in ("/", "https://evil/", verifier.ROOT+str(RUN)+"/logs",
                     verifier.ROOT+str(RUN)+"/jobs?per_page=100&page=5"):
            with self.assertRaisesRegex(verifier.ReleaseCIDenied,
                                        "public_api_route_denied"):
                verifier.get_public(path)

    def test_dry_cli_does_not_use_network(self):
        with patch.object(verifier,"review") as review:
            with patch("sys.stdout",new_callable=io.StringIO) as stdout:
                self.assertEqual(verifier.main(["--release",VERSION]),0)
            review.assert_not_called()
            self.assertEqual(json.loads(stdout.getvalue())["status"],"NOT_EXECUTED")

    def test_live_cli_never_returns_zero_or_enables_agent(self):
        api,_,_=api_fixture()
        with patch.object(verifier,"review",
                          return_value=verifier.review(VERSION,fetcher=api)):
            with patch("sys.stdout",new_callable=io.StringIO) as stdout:
                self.assertEqual(verifier.main(["--execute","--release",VERSION]),2)
        parsed=json.loads(stdout.getvalue())
        self.assertFalse(parsed["resident_agent_allowed"])
        self.assertEqual(parsed["status"],"UPSTREAM_REQUIRED_TESTS_SKIPPED")

    def test_errors_never_echo_untrusted_raw_data(self):
        with patch.object(verifier,"review",
                          side_effect=verifier.ReleaseCIDenied("SECRET=my-secret")):
            with patch("sys.stdout",new_callable=io.StringIO) as output:
                self.assertEqual(verifier.main(["--execute"]),2)
        self.assertNotIn("SECRET",output.getvalue())
        self.assertEqual(json.loads(output.getvalue())["status"],"UNKNOWN")


if __name__ == "__main__":
    unittest.main()
