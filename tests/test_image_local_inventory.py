"""H-01 pinned immutable OS+Python inventory: offline, no network, no secrets."""
from __future__ import annotations
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from scripts.image_local_inventory import (
    IMAGE, DIGEST, InventoryDenied, commands, observe, parse,
    record_to_directory, main,
)

IMAGE_ID = ("sha256:" + DIGEST + " amd64").encode()

def raw(os_items=None, py_items=None):
    return json.dumps({
        "schema": "hermes-pinned-image-inspector-v1",
        "os_packages": (os_items if os_items is not None else [
            {"name": "base-files", "version": "13.8+deb13u1"},
            {"name": "libc6:amd64", "version": "2.41-12"},
        ]),
        "python_venv_packages": (py_items if py_items is not None else [
            {"name": "httpx", "version": "0.28.1"},
            {"name": "pydantic", "version": "2.12.3"},
        ]),
    }, separators=(",", ":")).encode()


class InventoryContracts(unittest.TestCase):
    def test_dry_run_never_reads_or_executes_docker(self):
        with patch("scripts.image_local_inventory.observe") as action:
            with patch("sys.stdout", new_callable=io.StringIO) as out:
                self.assertEqual(main([]), 0)
            action.assert_not_called()
        self.assertEqual(json.loads(out.getvalue()), {"status": "NOT_EXECUTED"})

    def test_commands_use_only_installed_exact_image_offline(self):
        inspect, run = commands()
        self.assertIn(IMAGE, inspect)
        self.assertIn(IMAGE, run)
        self.assertIn("--pull=never", run)
        self.assertIn("--network", run)
        self.assertEqual(run[run.index("--network") + 1], "none")
        self.assertIn("--read-only", run)
        self.assertIn("--cap-drop", run)
        self.assertEqual(run[run.index("--cap-drop") + 1], "ALL")
        self.assertIn("no-new-privileges", run)
        self.assertIn("/opt/hermes/.venv/bin/python", run)
        for token in ("--mount", "--volume", "--env-file", "--privileged",
                      "--publish", "host", "latest", "pull", "/var/run/docker.sock"):
            if token == "pull":
                self.assertNotIn("pull", run)
            else:
                self.assertNotIn(token, run)
        self.assertEqual(inspect[:3], ["docker", "image", "inspect"])

    def test_inventory_is_deterministic_and_no_unverified_claims(self):
        one = parse(raw(), inspected_image_id=IMAGE_ID.decode())
        two = parse(raw(
            os_items=[{"name":"libc6:amd64","version":"2.41-12"},
                      {"name":"base-files","version":"13.8+deb13u1"}],
            py_items=[{"name":"pydantic","version":"2.12.3"},
                      {"name":"httpx","version":"0.28.1"}]),
            inspected_image_id=IMAGE_ID.decode())
        self.assertEqual(one["inventory_sha256"], two["inventory_sha256"])
        self.assertEqual(one["os_packages_count"],2)
        self.assertEqual(one["python_venv_packages_count"],2)
        self.assertFalse(one["supplier_sbom_verified"])
        self.assertFalse(one["source_release_parity_verified"])
        self.assertFalse(one["transitive_dependency_completeness_verified"])
        self.assertEqual(len(one["components"]),4)

    def test_duplicate_package_is_retained_and_flagged_for_supply_chain_review(self):
        doc = parse(raw(py_items=[
            {"name": "hermes-agent", "version": "0.21.6"},
            {"name": "Hermes_Agent", "version": "0.21.6"},
        ]), inspected_image_id=IMAGE_ID.decode())
        self.assertEqual(doc["ambiguous_package_count"], 1)
        self.assertEqual(doc["ambiguous_package_names"], ["python-venv:hermes-agent"])
        self.assertEqual(doc["python_venv_packages_count"], 2)
        self.assertEqual(len(doc["components"]), 4)
        self.assertFalse(doc["supplier_sbom_verified"])

    def test_untrusted_image_tag_or_architecture_never_passes(self):
        for identity in ("sha256:" + DIGEST + " arm64",
                         "sha256:" + "0"*64 + " amd64",
                         "", IMAGE):
            with self.subTest(identity=identity):
                with self.assertRaisesRegex(InventoryDenied,"image_id_mismatch"):
                    parse(raw(), inspected_image_id=identity)

    def test_untrusted_inventory_poison_or_duplicates_fail_closed(self):
        for image,reason in (
            (raw(os_items=[]),"package_list_invalid"),
            (raw(py_items=[]),"package_list_invalid"),
            (raw(os_items=[{"name":"evil\nJWT=secret","version":"1"}]),"package_value_invalid"),
            (raw(py_items=[{"name":"hello","version":"file:///secret"}]),"package_value_invalid"),
            (raw(py_items=[{"name":"x","version":"1","secret":"TOKEN"}]),"package_schema_invalid"),
            (b'{"schema":"a","schema":"b"}',"duplicate_json_key"),
            (b"not-json","image_json_invalid"),
            (b"a"*131073,"image_response_invalid"),
        ):
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(InventoryDenied,reason):
                    parse(image,inspected_image_id=IMAGE_ID.decode())

    def test_subprocess_mocked_exact_one_inspect_and_one_offline_run(self):
        requests=[]
        def execute(command, **kwargs):
            requests.append(command)
            return Mock(returncode=0,stdout=IMAGE_ID + b"\n" if len(requests)==1 else raw())
        with patch("scripts.image_local_inventory.os.geteuid",return_value=0):
            got=observe(runner=execute)
        self.assertEqual(got["os_packages_count"],2)
        self.assertEqual(len(requests),2)
        self.assertIn("--network",requests[1])
        self.assertNotIn("--env-file",requests[1])

    def test_failure_in_inspection_never_starts_container(self):
        runner=Mock(return_value=Mock(returncode=1,stdout=b"",stderr=b"SECRET=never-output"))
        with patch("scripts.image_local_inventory.os.geteuid",return_value=0):
            with self.assertRaisesRegex(InventoryDenied,"image_inspect_failed"):
                observe(runner=runner)
        self.assertEqual(runner.call_count,1)

    def test_secure_atomic_file_write_with_symlink_denied(self):
        with tempfile.TemporaryDirectory() as d:
            folder=Path(d)
            folder.chmod(0o700)
            doc=parse(raw(),inspected_image_id=IMAGE_ID.decode())
            record_to_directory(doc,folder)
            path=folder/"local-components.json"
            self.assertEqual(path.stat().st_mode & 0o777,0o600)
            self.assertEqual(json.loads(path.read_bytes())["inventory_sha256"],
                             doc["inventory_sha256"])
            path.unlink()
            path.symlink_to("/etc/passwd")
            with self.assertRaisesRegex(InventoryDenied,"file_unsafe"):
                record_to_directory(doc,folder)

    def test_unsafe_directory_denied(self):
        with tempfile.TemporaryDirectory() as d:
            folder=Path(d)
            folder.chmod(0o755)
            doc=parse(raw(),inspected_image_id=IMAGE_ID.decode())
            with self.assertRaisesRegex(InventoryDenied,"directory_unsafe"):
                record_to_directory(doc,folder)

    def test_no_secret_echo_when_inspection_fails(self):
        with patch("scripts.image_local_inventory.observe",
                   side_effect=InventoryDenied("raw bearer token secret")):
            with patch("sys.stdout", new_callable=io.StringIO) as out:
                self.assertEqual(main(["--execute"]),2)
        result=json.loads(out.getvalue())
        self.assertEqual(result["status"],"UNKNOWN")
        self.assertNotIn("token",out.getvalue())


if __name__ == "__main__":
    unittest.main()
