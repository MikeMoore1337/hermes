"""Offline tests for #271 read-only, no-inference production acceptance."""
import hashlib
from pathlib import Path
import tempfile
import unittest

from scripts import h271_post_canary_readonly as check


class H271PostCanaryReadOnlyTests(unittest.TestCase):
    def rows(self):
        job = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        digest = "a" * 64
        return [
            {
                "job_id": check.OLD_JOB_ID,
                "approval_id": "old-grant",
                "status": "blocked", "attempt_count": 1,
                "invocation_state": "reviewed", "result_ref": None,
                "last_error_code": "manual_review_completed",
                "delivered": None, "lease_owner": None,
                "cancellation_requested": 0,
            },
            {
                "job_id": job,
                "approval_id": "new-grant",
                "status": "succeeded", "attempt_count": 1,
                "invocation_state": "finished",
                "result_ref": f"artifact:{job}:{digest}",
                "last_error_code": None,
                "delivered": 1.0, "lease_owner": None,
                "cancellation_requested": 0,
            },
        ]

    def test_valid_historical_and_delivered_receipt(self):
        rows = self.rows()
        self.assertEqual(check.verify_jobs(rows), (
            rows[1]["job_id"], rows[1]["result_ref"]
        ))

    def test_never_accept_additional_or_uncertain_jobs(self):
        rows = self.rows()
        with self.assertRaises(ValueError):
            check.verify_jobs(rows + [rows[1]])
        rows[0]["invocation_state"] = "uncertain"
        with self.assertRaises(ValueError):
            check.verify_jobs(rows)

    def test_reject_missing_delivery_or_extra_attempt(self):
        rows = self.rows()
        rows[1]["delivered"] = None
        with self.assertRaises(ValueError):
            check.verify_jobs(rows)
        rows = self.rows()
        rows[1]["attempt_count"] = 2
        with self.assertRaises(ValueError):
            check.verify_jobs(rows)

    def test_artifact_digest_and_permissions(self):
        rows = self.rows()
        job = rows[1]["job_id"]
        payload = b'{"type":"sample"}\n'
        digest = hashlib.sha256(payload).hexdigest()
        ref = f"artifact:{job}:{digest}"
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / "artifacts"
            base.mkdir(mode=0o700)
            path = base / f"{job}-{digest}.jsonl"
            path.write_bytes(payload)
            path.chmod(0o600)
            check.verify_artifact(job, ref, base)
            path.write_bytes(b"tampered")
            with self.assertRaises(ValueError):
                check.verify_artifact(job, ref, base)
            path.write_bytes(payload)
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                check.verify_artifact(job, ref, base)

    def test_empty_sha_matching_artifact_is_not_positive_canary_evidence(self):
        job = self.rows()[1]["job_id"]
        empty_digest = hashlib.sha256(b"").hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / "artifacts"
            base.mkdir(mode=0o700)
            target = base / f"{job}-{empty_digest}.jsonl"
            target.write_bytes(b"")
            target.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "artifact_file_mode_or_size"):
                check.verify_artifact(job, f"artifact:{job}:{empty_digest}", base)

    def test_no_external_actions_under_pure_contract(self):
        # These pure validators do not import a CLI, mutate SQLite or emit
        # task prompt contents; the production main is never invoked here.
        with self.assertRaises(ValueError):
            check.verify_artifact("bad", "artifact:incorrect:bad", Path("/no"))


if __name__ == "__main__":
    unittest.main()
