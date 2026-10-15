"""All v0.22.1 host-side Docker inspection entry points bound pipe output."""
from __future__ import annotations

import unittest

from scripts.bounded_subprocess import run_bounded
from scripts import (
    export_v0221_observed_sbom,
    verify_v0221_core_python,
    verify_v0221_local_image,
    verify_v0221_source_sample,
    verify_v0221_tools_python,
)


class PinnedInspectorEntryPoints(unittest.TestCase):
    def test_all_invocations_use_bounded_subprocess_default(self):
        for module in (
            export_v0221_observed_sbom,
            verify_v0221_core_python,
            verify_v0221_local_image,
            verify_v0221_source_sample,
            verify_v0221_tools_python,
        ):
            with self.subTest(module=module.__name__):
                callback = getattr(module, "observe", None) or module.collect
                self.assertIs(callback.__defaults__[0], run_bounded)


if __name__ == "__main__":
    unittest.main()
