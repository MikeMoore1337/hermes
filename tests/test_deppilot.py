"""H774 DepPilot offline lockfile parser and candidate metadata risk tests."""
from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
import hashlib
import io
import json
from contextlib import redirect_stdout
from pathlib import Path
import tempfile
import unittest

from qa_advisor.deppilot import DepPilotRefused, SCHEMA, main, plan

NOW = datetime(2026, 11, 5, 9, 0, tzinfo=UTC)
UV = b'''version = 1
requires-python = ">=3.11"

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
        "": {"name": "demo", "version": "1.0.0"},
        "node_modules/vite": {"version": "6.0.0"},
        "node_modules/@scope/util": {"version": "1.2.3"},
    },
}).encode()


def entry(name="pytest", version="8.4.2", ecosystem="pypi",
          minimum="3.11.0", maximum="3.15.0"):
    return {"ecosystem": ecosystem, "name": name,
            "candidate_version": version, "min_runtime": minimum,
            "max_runtime_exclusive": maximum}


def meta(lock=UV, items=None, repo="MikeMoore1337/hermes"):
    return {
        "schema": SCHEMA,
        "repo": repo,
        "lock_sha256": hashlib.sha256(lock).hexdigest(),
        "observed_at": "2026-11-05T08:55:00Z",
        "runtime_version": "3.14.0",
        "candidates": [entry()] if items is None else items,
    }


def check(raw=UV, md=None, lockname="uv.lock"):
    return plan(lockname, raw, meta(raw) if md is None else md, now=NOW)


class DepPilotTests(unittest.TestCase):
    def test_patch_candidate_is_not_automatically_accepted(self):
        report = check()
        self.assertEqual(report["status"], "REVIEW_REQUIRED")
        item = report["findings"][0]
        self.assertEqual(item["name"], "pytest")
        self.assertEqual(item["change"], "PATCH")
        self.assertEqual(item["installed_versions"], ["8.4.0"])
        self.assertEqual(item["runtime_support"], "SUPPORTED_BY_SUPPLIED_RANGE")
        self.assertEqual(item["tests_required"], [
            "lockfile_regeneration", "unit_regression",
            "integration_regression", "runtime_compatibility",
        ])
        self.assertFalse(report["candidate_source_verified"])
        self.assertFalse(report["latest_versions_verified"])
        self.assertFalse(report["dependency_constraints_verified"])
        self.assertEqual(report["vulnerability_scan"], "NOT_RUN")
        self.assertFalse(report["changes_written"])
        self.assertFalse(report["pull_requests_created"])
        self.assertFalse(report["production_authorized"])
        self.assertFalse(report["tests_executed"])

    def test_numeric_risk_classes_only(self):
        for old, new, expected in (
            ("8.4.0", "8.4.0", "NO_CHANGE"),
            ("8.4.0", "8.4.2", "PATCH"),
            ("8.4.0", "8.5.0", "MINOR"),
            ("8.4.0", "9.0.0", "MAJOR"),
            ("8.4.0", "8.3.9", "DOWNGRADE"),
            ("8.4.0", "8.5.0rc1", "UNORDERED"),
        ):
            with self.subTest(old=old, new=new):
                raw = UV.replace(b'8.4.0', old.encode())
                m = meta(raw, [entry(version=new)])
                r = check(raw, m)
                self.assertEqual(r["findings"][0]["change"], expected)

    def test_no_change_but_source_is_still_unverified(self):
        r = check(UV, meta(UV, [entry(version="8.4.0")]))
        self.assertEqual(r["status"], "NO_CHANGES_IN_SUPPLIED_CANDIDATES")
        self.assertFalse(r["latest_versions_verified"])
        self.assertEqual(r["findings"][0]["tests_required"], [])

    def test_runtime_bounds_and_unknown_ranges(self):
        raw = UV
        bad = meta(raw, [entry(minimum="3.15.0")])
        report = check(raw, bad)
        self.assertEqual(report["findings"][0]["runtime_support"], "UNSUPPORTED")
        self.assertEqual(report["status"], "INCONCLUSIVE")
        unknown = meta(raw, [entry(minimum=None, maximum=None)])
        self.assertEqual(check(raw, unknown)["findings"][0]["runtime_support"], "UNKNOWN")
        self.assertEqual(check(raw, unknown)["status"], "INCONCLUSIVE")

    def test_python_314_is_a_candidate_not_an_update_command(self):
        r = check(UV, meta(UV, [entry(minimum="3.11.0", maximum="3.15.0")]))
        self.assertEqual(r["findings"][0]["runtime_support"], "SUPPORTED_BY_SUPPLIED_RANGE")
        self.assertFalse(r["changes_written"])
        self.assertFalse(r["tests_executed"])

    def test_npm_scoped_package_and_missing_candidate(self):
        data = meta(NPM, [
            entry(name="@scope/util", version="1.3.0", ecosystem="npm",
                  minimum="18.0.0", maximum="26.0.0"),
            entry(name="missing", version="1.0.0", ecosystem="npm",
                  minimum=None, maximum=None),
        ])
        data["runtime_version"] = "22.16.0"
        result = check(NPM, data, "package-lock.json")
        self.assertEqual(result["ecosystem"], "npm")
        self.assertEqual(result["inventory_count"], 2)
        self.assertEqual(result["findings"][0]["name"], "@scope/util")
        self.assertEqual(result["findings"][0]["change"], "MINOR")
        self.assertEqual(result["findings"][1]["change"], "MISSING")
        self.assertEqual(result["status"], "INCONCLUSIVE")

    def test_multiple_nested_installed_versions_are_inconclusive(self):
        raw = json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "node_modules/a": {"version": "1.0.0"},
                "node_modules/b/node_modules/a": {"version": "2.0.0"},
            },
        }).encode()
        data = meta(raw, [entry("a", "3.0.0", "npm")])
        data["runtime_version"] = "22.16.0"
        r = check(raw, data, "package-lock.json")
        self.assertEqual(r["findings"][0]["change"], "MULTIPLE_INSTALLED")
        self.assertEqual(r["status"], "INCONCLUSIVE")

    def test_npm_hyphen_and_underscore_are_different_packages(self):
        raw = json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "node_modules/a-b": {"version": "1.0.0"},
                "node_modules/a_b": {"version": "2.0.0"},
            },
        }).encode()
        candidates = [
            entry(name="a_b", version="2.0.1", ecosystem="npm", minimum="18.0.0", maximum="26.0.0"),
            entry(name="a-b", version="1.0.1", ecosystem="npm", minimum="18.0.0", maximum="26.0.0"),
        ]
        data = meta(raw, candidates)
        data["runtime_version"] = "22.0.0"
        result = check(raw, data, "package-lock.json")
        self.assertEqual(result["inventory_count"], 2)
        versions = {row["name"]: row["installed_versions"] for row in result["findings"]}
        self.assertEqual(versions["a-b"], ["1.0.0"])
        self.assertEqual(versions["a_b"], ["2.0.0"])

    def test_empty_candidate_list_is_not_false_green(self):
        result = check(UV, meta(UV, []))
        self.assertEqual(result["status"], "INCONCLUSIVE")
        self.assertIn("candidate_list_empty", result["reasons"])
        self.assertFalse(result["latest_versions_verified"])

    def test_lock_hash_mismatch_prevents_stale_candidate_replay(self):
        wrong = meta(UV)
        with self.assertRaisesRegex(DepPilotRefused, "lock_hash_mismatch"):
            check(UV + b"\n# mutated", wrong)

    def test_stale_and_future_metadata_never_looks_fresh(self):
        for timestamp in ("2026-10-01T10:00:00Z", "2026-11-05T09:03:00Z"):
            with self.subTest(timestamp=timestamp):
                data = meta()
                data["observed_at"] = timestamp
                r = check(UV, data)
                self.assertIn("candidate_metadata_stale_or_future", r["reasons"])
                self.assertEqual(r["status"], "INCONCLUSIVE")

    def test_refuse_unknown_repo_metadata_fields_and_candidates(self):
        for changed in (
            {"repo": "other/repo"},
            {"schema": "next"},
            {"observed_at": "bad"},
            {"observed_at": "2026-11-05T10:55:00+03:00"},
            {"runtime_version": "python3.14"},
            {"candidates": "bad"},
            {"candidates": [{}]},
            {"candidates": [entry(), entry()]},
        ):
            with self.subTest(keys=changed.keys()):
                data = meta()
                data.update(changed)
                with self.assertRaises(DepPilotRefused):
                    check(UV, data)
        data = meta()
        data["token"] = "PRIVATE_TOKEN"
        with self.assertRaisesRegex(DepPilotRefused, "metadata_shape_invalid"):
            check(UV, data)

    def test_reject_bad_candidate_runtime_and_name(self):
        for changed in (
            {"ecosystem": "rubygems"},
            {"name": "../../secret"},
            {"name": "a\nb"},
            {"candidate_version": ""},
            {"min_runtime": ">=3.11"},
            {"max_runtime_exclusive": "lol"},
        ):
            with self.subTest(changed=changed):
                data = meta()
                data["candidates"][0].update(changed)
                with self.assertRaises(DepPilotRefused):
                    check(UV, data)
        data = meta()
        data["candidates"][0]["owner_approval"] = "YES"
        with self.assertRaisesRegex(DepPilotRefused, "candidate_shape_invalid"):
            check(UV, data)

    def test_unrecognized_lockfile_and_corrupt_data_refused(self):
        for name, raw in [
            ("pnpm-lock.yaml", UV),
            ("uv.lock", b"{}"),
            ("uv.lock", b"[[package]]\nname = 4\nversion = '1.0.0'\n"),
            ("package-lock.json", b"{}"),
            ("package-lock.json", b'{"lockfileVersion":3,"packages": []}'),
        ]:
            with self.subTest(name=name, raw=raw[:20]):
                with self.assertRaises(DepPilotRefused):
                    check(raw, meta(raw), name)

    def test_unknown_python_versions_do_not_invent_semver(self):
        raw = UV.replace(b'8.4.0', b'8.4.0rc1')
        data = meta(raw, [entry(version="8.4.2")])
        report = check(raw, data)
        self.assertEqual(report["findings"][0]["change"], "UNORDERED")
        self.assertEqual(report["status"], "INCONCLUSIVE")

    def test_safe_cli_no_input_files_are_not_modified(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            self.assertEqual(main([]), 0)
        self.assertEqual(json.loads(buffer.getvalue()), {"status": "NOT_EXECUTED"})
        with tempfile.TemporaryDirectory() as folder:
            lock = Path(folder) / "uv.lock"
            cand = Path(folder) / "candidates.json"
            lock.write_bytes(UV)
            stale = meta()
            stale["observed_at"] = "2000-01-01T00:00:00Z"  # deterministic CLI stale fixture
            cand.write_text(json.dumps(stale), encoding="utf-8")
            snapshot = lock.read_bytes()
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = main(["--lockfile", str(lock), "--candidates", str(cand)])
            self.assertEqual(code, 2)  # fixture is explicitly stale
            self.assertEqual(lock.read_bytes(), snapshot)
            self.assertEqual(json.loads(buffer.getvalue())["status"], "INCONCLUSIVE")
            symlink = Path(folder) / "alias.json"
            symlink.symlink_to(cand)
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                self.assertEqual(main(["--lockfile", str(lock), "--candidates", str(symlink)]), 2)
            self.assertEqual(json.loads(buffer.getvalue())["status"], "REFUSED")


if __name__ == "__main__":
    unittest.main()
