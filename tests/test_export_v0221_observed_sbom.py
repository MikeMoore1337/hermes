"""Deterministic observed BOM: never network, change production or authorize AI."""
from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from scripts import export_v0221_observed_sbom as sbom
from scripts.bounded_subprocess import run_bounded
from scripts import verify_v0221_local_image as image

META = json.dumps([image.IMAGE]).encode() + b"|amd64"


def record(source=image.SOURCE_SHA, os_count=274, py_count=146, conflict=False):
    python = [{"name": f"package-{i}", "version": "2.0"} for i in range(py_count - 1)]
    python.append({"name": "package_0", "version": "3.0" if conflict else "2.0"})
    return json.dumps({
        "schema": "hermes-v0221-offline-inspector-v1",
        "embedded_commit": source,
        "embedded_version": "0.22.1",
        "embedded_distribution": "docker",
        "os_packages": [
            {"name": f"lib-{i}:amd64", "version": "1.2.3"} for i in range(os_count)
        ],
        "python_packages": python,
    }).encode()


class ObservedSbomTest(unittest.TestCase):
    def test_default_collector_uses_bounded_process_reader(self):
        self.assertIs(sbom.collect.__defaults__[0], run_bounded)

    def test_default_is_noop(self):
        with patch.object(sbom, "collect") as collect:
            with patch("sys.stdout", new_callable=io.StringIO) as out:
                self.assertEqual(sbom.main([]), 0)
        collect.assert_not_called()
        self.assertIn("NOT_EXECUTED", out.getvalue())

    def test_explicit_output_required_before_docker(self):
        with patch.object(sbom, "collect") as collect:
            with patch("sys.stdout", new_callable=io.StringIO):
                self.assertEqual(sbom.main(["--execute"]), 2)
        collect.assert_not_called()

    def test_only_two_existing_isolated_pinned_commands(self):
        calls = []
        def runner(command, **kwargs):
            calls.append(command)
            return Mock(returncode=0, stdout=META if len(calls) == 1 else record(),
                        stderr=b"PRIVATE TOKEN MUST NOT LEAK")
        bom, report = sbom.collect(runner=runner)
        self.assertEqual(calls, list(image.commands()))
        self.assertEqual(bom["bomFormat"], "CycloneDX")
        self.assertEqual(bom["specVersion"], "1.5")
        self.assertEqual(report["unique_components"], 419)
        self.assertEqual(report["duplicate_metadata_rows"], 1)
        self.assertFalse(report["complete_sbom_verified"])
        self.assertFalse(report["resident_agent_allowed"])
        self.assertNotIn("PRIVATE", str(report))

    def test_repeatable_and_unique_component_identifiers(self):
        bom, summary = sbom.build(META, record())
        other, next_report = sbom.build(META, record())
        self.assertEqual(bom, other)
        self.assertEqual(summary["bom_sha256"], next_report["bom_sha256"])
        refs = [component["bom-ref"] for component in bom["components"]]
        self.assertEqual(len(refs), len(set(refs)))
        self.assertTrue(all("licenses" not in item for item in bom["components"]))
        self.assertNotIn("dependencies", bom)
        self.assertTrue(all("purl" not in item for item in bom["components"]))

    def test_tampering_and_conflicting_versions_fail_closed(self):
        cases = [
            (b"[]|amd64", record()),
            (META, record(source="0" * 40)),
            (META, record(os_count=273)),
            (META, record(py_count=145)),
            (META, record(conflict=True)),
            (META, record().replace(b'"name":', b'"name":"secret","name":', 1)),
        ]
        for meta, inspector in cases:
            with self.subTest(response_size=len(inspector)):
                with self.assertRaises(sbom.SbomDenied):
                    sbom.build(meta, inspector)

    def test_no_overwrite_and_safe_new_artifact(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "bom.json"
            path.write_text("original", encoding="utf-8")
            evidence = sbom.build(META, record())
            with patch.object(sbom, "collect", return_value=evidence):
                with patch("sys.stdout", new_callable=io.StringIO) as out:
                    self.assertEqual(
                        sbom.main(["--execute", "--output", str(path)]), 2
                    )
            self.assertEqual(path.read_text(encoding="utf-8"), "original")
            self.assertIn("NO_DATA", out.getvalue())
            path.unlink()
            with patch.object(sbom, "collect", return_value=evidence):
                with patch("sys.stdout", new_callable=io.StringIO) as out:
                    self.assertEqual(
                        sbom.main(["--execute", "--output", str(path)]), 2
                    )
            self.assertEqual(json.loads(path.read_text())["bomFormat"], "CycloneDX")
            self.assertFalse(json.loads(out.getvalue())["resident_agent_allowed"])


if __name__ == "__main__":
    unittest.main()
