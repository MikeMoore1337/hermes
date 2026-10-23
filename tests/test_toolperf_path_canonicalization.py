"""Issue #463: deterministic negative tests for benchmark path identities.

These are offline tests of the existing mock bus, not tests of live Hermes BRC,
OS confinement, model quality, or tool-use efficiency.
"""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from hermes_benchmark import core


class BenchmarkPathIdentityTests(unittest.TestCase):
    def assert_denied(self, paths):
        for value in paths:
            with self.subTest(path=repr(value)):
                with self.assertRaisesRegex(core.BenchmarkError, "invalid_fixture_path"):
                    core._path(value)

    def test_canonical_posix_path_is_accepted(self):
        self.assertEqual(core._path("src/task.txt"), Path("src/task.txt"))

    def test_empty_and_dot_paths_fail_closed(self):
        self.assert_denied(["", ".", "./", "./src/task.txt"])

    def test_parent_traversal_is_denied(self):
        self.assert_denied(["..", "../task.txt", "src/../task.txt"])

    def test_absolute_paths_are_denied(self):
        self.assert_denied(["/etc/passwd", "/src/task.txt"])

    def test_aliases_with_repeated_separators_are_denied(self):
        self.assert_denied(["src//task.txt", "src///task.txt"])

    def test_aliases_with_dot_or_trailing_slash_are_denied(self):
        self.assert_denied(["src/./task.txt", "src/", "src/task.txt/"])

    def test_windows_and_colon_variants_are_denied(self):
        self.assert_denied(["src\\task.txt", "C:/src/task.txt", "a:b"])

    def test_nul_byte_is_denied(self):
        self.assert_denied(["src/\x00task.txt"])

    def test_non_string_values_fail_as_benchmark_error(self):
        self.assert_denied([None, False, 7, Path("src/task.txt"), ["src/task.txt"]])

    def test_hidden_first_component_still_denied(self):
        self.assert_denied([".ssh/key", ".hidden"])

    def test_case_sensitive_names_remain_distinct(self):
        self.assertNotEqual(core._path("src/Task.txt"), core._path("src/task.txt"))

    def test_mock_write_rejects_allowlisted_alias_without_mutation(self):
        case = deepcopy(core.load_cases()[0])
        case["allowed_tools"] = ["mock_git"]
        case["allowed_operations"] = ["src//task.txt"]
        with tempfile.TemporaryDirectory() as root:
            bus = core.MockBus(case, Path(root))
            before = bus.snapshot()
            with self.assertRaisesRegex(core.BenchmarkError, "invalid_fixture_path"):
                bus.step({"op": "write", "path": "src//task.txt", "content": "changed\n"})
            self.assertEqual(bus.snapshot(), before)


if __name__ == "__main__":
    unittest.main()
