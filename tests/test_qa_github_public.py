"""Mocked public GitHub Actions retrieval; never contacts GitHub in CI."""

from __future__ import annotations

import json
import unittest
from unittest.mock import Mock

from qa_advisor.github_public import (
    GithubPublicError, public_runs, run_public_report, get_json,
)


class Response:
    def __init__(self, body, status=200):
        self.status = status
        self.body = json.dumps(body).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, length):
        assert length <= 700_001
        return self.body[:length]


def row(rid=101, conclusion="failure", workflow=23):
    return {"id": rid, "workflow_id": workflow, "head_sha": "a" * 40,
            "status": "completed", "conclusion": conclusion,
            "authorization": "SHOULD_NEVER_BE_EMITTED", "name": "Unsafe <>!"}


class ReadonlyGithubAPITests(unittest.TestCase):
    def test_public_data_is_reduced_to_strict_metadata(self):
        client = Mock()
        client.open.return_value = Response({"workflow_runs": [row()]})
        result = public_runs("MikeMoore1337/hermes", opener=client)
        self.assertEqual(result[0]["workflow"], "workflow-23")
        self.assertEqual(result[0]["jobs"], [])
        self.assertNotIn("authorization", str(result))
        request = client.open.call_args.args[0]
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(
            request.full_url,
            "https://api.github.com/repos/MikeMoore1337/hermes/actions/runs?per_page=3",
        )
        self.assertIsNone(request.headers.get("Authorization"))
        self.assertEqual(client.open.call_count, 1)

    def test_run_failure_stays_hypothesis(self):
        client = Mock()
        client.open.return_value = Response({"workflow_runs": [row()]})
        report = run_public_report("MikeMoore1337/hermes", opener=client)
        self.assertEqual(report["findings"][0]["classification"], "failure_unknown_root_cause")

    def test_fully_successful_public_run_is_no_incident(self):
        client = Mock()
        client.open.return_value = Response({"workflow_runs": [row(conclusion="success")]})
        self.assertEqual(run_public_report("MikeMoore1337/hermes", opener=client)["status"],
                         "NO_INCIDENT_EVIDENCE")

    def test_empty_collection_reports_no_data(self):
        client = Mock()
        client.open.return_value = Response({"workflow_runs": []})
        self.assertEqual(run_public_report("MikeMoore1337/hermes", opener=client)["status"],
                         "NO_DATA")

    def test_unapproved_repositories_cannot_trigger_http_request(self):
        client = Mock()
        for name in ("other/private", "MikeMoore1337/second-brain",
                     "MikeMoore1337/hermes/../../secret"):
            with self.subTest(name=name), self.assertRaises(GithubPublicError):
                public_runs(name, opener=client)
        client.open.assert_not_called()

    def test_arbitrary_api_endpoint_is_rejected(self):
        client = Mock()
        for path in ("/user", "/repos/MikeMoore1337/hermes/issues",
                     "/repos/MikeMoore1337/hermes/actions/runs?per_page=100"):
            with self.subTest(path=path), self.assertRaises(GithubPublicError):
                get_json(path, opener=client)
        client.open.assert_not_called()

    def test_missing_workflow_id_refuses_forged_metadata(self):
        client = Mock()
        r = row()
        r["workflow_id"] = None
        client.open.return_value = Response({"workflow_runs": [r]})
        with self.assertRaisesRegex(GithubPublicError, "workflow_id_missing"):
            public_runs("MikeMoore1337/hermes", opener=client)

    def test_malformed_status_does_not_become_healthy(self):
        client = Mock()
        r = row()
        r["status"] = ["completed"]
        client.open.return_value = Response({"workflow_runs": [r]})
        with self.assertRaisesRegex(GithubPublicError, "unexpected_run_metadata"):
            public_runs("MikeMoore1337/hermes", opener=client)

    def test_unbounded_collection_is_rejected(self):
        client = Mock()
        client.open.return_value = Response({"workflow_runs": [row(i) for i in range(4)]})
        with self.assertRaisesRegex(GithubPublicError, "unexpected_run_collection"):
            public_runs("MikeMoore1337/hermes", opener=client)

    def test_no_raw_response_errors_or_token_echo(self):
        import urllib.error

        client = Mock()
        url = "https://api.github.com/repos/MikeMoore1337/hermes/actions/runs"
        client.open.side_effect = urllib.error.HTTPError(
            url, 403, "SECRET_TOKEN_INSIDE_ERROR", {}, None
        )
        with self.assertRaises(GithubPublicError) as error:
            public_runs("MikeMoore1337/hermes", opener=client)
        self.assertEqual(str(error.exception), "public_rate_limited_or_denied")
        self.assertNotIn("SECRET_TOKEN", str(error.exception))

    def test_inconsistent_http_200_schema_is_refused(self):
        client = Mock()
        client.open.return_value = Response({"message": "Not Found"})
        with self.assertRaises(GithubPublicError):
            public_runs("MikeMoore1337/hermes", opener=client)


if __name__ == "__main__":
    unittest.main()
