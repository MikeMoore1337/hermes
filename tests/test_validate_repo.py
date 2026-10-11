"""Негативные проверки структуры и границ bootstrap CI Hermes."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.validate_repo import REQUIRED_PATHS, ROOT, validate


class RepositoryValidationTests(unittest.TestCase):
    """Проверяет что валидатор обнаруживает отсутствие файлов и опасный workflow."""

    def test_real_bootstrap_has_required_files(self) -> None:
        self.assertEqual(validate(ROOT), [])

    def test_missing_file_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            errors = validate(Path(directory))
        self.assertIn(f"Нет обязательного файла: {REQUIRED_PATHS[0]}", errors)

    def test_forbidden_workflow_configuration_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workflow = root / ".github/workflows/quality.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text(
                "on: pull_request_target\npermissions: write-all\n"
                "jobs:\n  release:\n    steps:\n      - run: echo deploy\n",
                encoding="utf-8",
            )
            errors = validate(root)
        self.assertTrue(any("contents: read" in e for e in errors))
        self.assertTrue(any("pull_request_target" in e for e in errors))
        self.assertTrue(any("deploy/secrets" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
