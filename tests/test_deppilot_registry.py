"""H774: official-registry candidate transport without install/registry writes."""
from __future__ import annotations

from datetime import UTC, datetime
import io
import json
import urllib.error
from contextlib import redirect_stdout
from unittest.mock import MagicMock, Mock, patch
import unittest

from qa_advisor import deppilot_registry as reg

NOW = datetime(2026, 11, 5, 11, 30, tzinfo=UTC)
REPO = "MikeMoore1337/hermes"
UV = b'''version = 1
[[package]]
name = "pytest"
version = "8.4.0"
[[package]]
name = "fastapi"
version = "0.115.2"
'''
NPM = json.dumps({
    "lockfileVersion": 3,
    "packages": {
        "node_modules/@scope/demo": {"version": "1.0.0"},
        "node_modules/vite": {"version": "6.0.0"},
    },
}).encode()


class Fake:
    def __init__(self, data):
        self.data = data
        self.calls = []

    def get(self, ecosystem, name):
        self.calls.append((ecosystem, name))
        return self.data[(ecosystem, name)]


def pypi(name="pytest", version="8.4.2", requires=">=3.11,<3.15"):
    return {"info": {
        "name": name, "version": version,
        "requires_python": requires, "yanked": False,
    }}


class DepRegistryTests(unittest.TestCase):
    def test_pypi_patch_candidate_remains_unapproved(self):
        client = Fake({("pypi", "pytest"): pypi()})
        result = reg.candidates_for(
            "uv.lock", UV, repo=REPO, runtime="3.14.0",
            packages=["pytest"], source=client, now=NOW,
        )
        self.assertEqual(result["status"], "REVIEW_REQUIRED")
        self.assertEqual(result["findings"][0]["change"], "PATCH")
        self.assertEqual(result["findings"][0]["runtime_support"], "SUPPORTED_BY_SUPPLIED_RANGE")
        self.assertEqual(result["inventory_coverage"], "SELECTED_PACKAGES_ONLY")
        self.assertFalse(result["changes_written"])
        self.assertFalse(result["tests_executed"])
        self.assertFalse(result["production_authorized"])
        self.assertFalse(result["latest_versions_verified"])
        self.assertEqual(result["vulnerability_scan"], "NOT_RUN")
        self.assertEqual(client.calls, [("pypi", "pytest")])

    def test_npm_scoped_package_candidate(self):
        client = Fake({("npm", "@scope/demo"): {
            "name": "@scope/demo", "version": "1.1.0",
            "engines": {"node": ">=18.0.0,<25.0.0"},
        }})
        report = reg.candidates_for(
            "package-lock.json", NPM, repo=REPO, runtime="22.0.0",
            packages=["@scope/demo"], source=client, now=NOW,
        )
        self.assertEqual(report["ecosystem"], "npm")
        self.assertEqual(report["findings"][0]["change"], "MINOR")
        self.assertEqual(report["findings"][0]["runtime_support"], "SUPPORTED_BY_SUPPLIED_RANGE")

    def test_unsupported_ranges_remain_unknown(self):
        for spec in ("~=3.10", "^20 || ^22", ">=3.10,!=3.13.*", "garbage", "", 123):
            with self.subTest(spec=spec):
                self.assertEqual(reg._runtime_bounds(spec), (None, None))
        self.assertEqual(reg._runtime_bounds(">=3.11,<3.15"), ("3.11.0", "3.15.0"))

    def test_unknown_runtime_bounds_block_compatibility_claim(self):
        client = Fake({("pypi", "pytest"): pypi(requires=">=3.11,!=3.12.*")})
        result = reg.candidates_for(
            "uv.lock", UV, repo=REPO, runtime="3.14.0",
            packages=["pytest"], source=client, now=NOW,
        )
        self.assertEqual(result["status"], "INCONCLUSIVE")
        self.assertEqual(result["findings"][0]["runtime_support"], "UNKNOWN")

    def test_registry_identity_and_missing_selected_fail_closed(self):
        cases = [
            Fake({("pypi", "pytest"): pypi(name="evil")}),
            Fake({("pypi", "pytest"): pypi(version="")}),
            Fake({("pypi", "pytest"): {"info": {"name": "pytest", "version": "8.4.2", "yanked": True}}}),
        ]
        for client in cases:
            with self.subTest(data=client.data), self.assertRaises(reg.RegistryUnavailable):
                reg.candidates_for("uv.lock", UV, repo=REPO,
                                   runtime="3.14.0", packages=["pytest"],
                                   source=client, now=NOW)
        with self.assertRaisesRegex(reg.RegistryUnavailable, "selected_package_invalid"):
            reg.candidates_for("uv.lock", UV, repo=REPO, runtime="3.14.0",
                               packages=["not_installed"], source=Fake({}), now=NOW)
        with self.assertRaisesRegex(reg.RegistryUnavailable, "selected_package_invalid"):
            reg.candidates_for("uv.lock", UV, repo=REPO, runtime="3.14.0",
                               packages=["pytest", "pytest"], source=Fake({}), now=NOW)

    def test_reject_unapproved_input_names_and_runtime(self):
        for name in ("../../etc/passwd", "https://evil.example/foo", "foo\nbar", ""):
            with self.subTest(name=name), self.assertRaises(reg.RegistryUnavailable):
                reg.candidates_for("uv.lock", UV, repo=REPO, runtime="3.14.0",
                                   packages=[name], source=Fake({}), now=NOW)
        with self.assertRaisesRegex(reg.RegistryUnavailable, "runtime_invalid"):
            reg.candidates_for("uv.lock", UV, repo=REPO, runtime="^3.14",
                               packages=["pytest"], source=Fake({}), now=NOW)
        with self.assertRaisesRegex(reg.RegistryUnavailable, "target_repo_invalid"):
            reg.candidates_for("uv.lock", UV, repo="user/private", runtime="3.14",
                               packages=["pytest"], source=Fake({}), now=NOW)
        with self.assertRaisesRegex(reg.RegistryUnavailable, "package_window_invalid"):
            reg.candidates_for("uv.lock", UV, repo=REPO, runtime="3.14",
                               packages=[], source=Fake({}), now=NOW)

    def test_http_requests_are_public_get_only_and_scope_encoded(self):
        reply = MagicMock()
        reply.status = 200
        reply.read.return_value = b'{"name":"@scope/demo","version":"1.0.0"}'
        reply.__enter__ = Mock(return_value=reply)
        reply.__exit__ = Mock(return_value=False)
        opener = Mock()
        opener.open.return_value = reply
        client = reg.PublicRegistry(opener=opener)
        result = client.get("npm", "@scope/demo")
        self.assertEqual(result["version"], "1.0.0")
        request = opener.open.call_args.args[0]
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(request.full_url, "https://registry.npmjs.org/%40scope%2Fdemo/latest")
        self.assertNotIn("authorization", [k.lower() for k in request.headers])
        self.assertEqual(opener.open.call_args.kwargs["timeout"], 6)

    def test_http_403_body_never_leaks(self):
        opener = Mock()
        opener.open.side_effect = urllib.error.HTTPError(
            url="https://pypi.org/pypi/pytest/json", code=403,
            msg="SECRET PASSWORD IN BODY", hdrs=None, fp=None,
        )
        client = reg.PublicRegistry(opener=opener)
        with self.assertRaisesRegex(reg.RegistryUnavailable, "registry_forbidden_or_limited") as caught:
            client.get("pypi", "pytest")
        self.assertNotIn("SECRET", str(caught.exception))

    def test_http_request_budget(self):
        reply = MagicMock()
        reply.status = 200
        reply.read.return_value = b'{}'
        reply.__enter__ = Mock(return_value=reply)
        reply.__exit__ = Mock(return_value=False)
        opener = Mock()
        opener.open.return_value = reply
        client = reg.PublicRegistry(opener=opener)
        for _ in range(reg.MAX_CALLS):
            self.assertEqual(client.get("pypi", "pytest"), {})
        with self.assertRaisesRegex(reg.RegistryUnavailable, "request_budget_exceeded"):
            client.get("pypi", "pytest")
        self.assertEqual(opener.open.call_count, reg.MAX_CALLS)

    def test_cli_inert_without_execute(self):
        buffer = io.StringIO()
        with patch.object(reg.PublicRegistry, "__init__", side_effect=AssertionError("must not connect")):
            with redirect_stdout(buffer):
                self.assertEqual(reg.main([]), 0)
        self.assertEqual(json.loads(buffer.getvalue()), {"status": "NOT_EXECUTED"})

    def test_cli_requires_explicit_lockfile_runtime_and_packages(self):
        output = io.StringIO()
        with redirect_stdout(output):
            code = reg.main(["--execute", "--repository", REPO])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue())["status"], "INCONCLUSIVE")


if __name__ == "__main__":
    unittest.main()
