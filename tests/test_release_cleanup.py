"""Hermes historical release cleanup: read-only-by-default + owner consent tests.

No production access, network traffic, actual Docker commands or deletions.
"""
from __future__ import annotations

import importlib.util
import io
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "hermes_release_cleanup", ROOT / "deploy" / "hermes-release-cleanup.py"
)
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)


class ReleaseCleanupContractTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        self.agent = self.root / "agent" / "releases"
        self.ui = self.root / "ui" / "releases"
        self.agent.mkdir(parents=True)
        self.ui.mkdir(parents=True)
        self.shas = [f"{i:012x}" + "a" * 28 for i in range(20)]
        for i, sha in enumerate(self.shas):
            for root in (self.agent, self.ui):
                path = root / ("main-" + sha)
                path.mkdir()
                os.utime(path, (1000 + i, 1000 + i))
            (self.agent / f".backup-{sha[:12]}-20261023T160000Z").mkdir()
        self.backup = self.agent / (
            f".backup-{self.shas[-1][:12]}-20261023T160000Z"
        )

    def test_preserves_current_previous_pins_and_newest_twelve(self):
        protected = {
            self.shas[0], self.shas[1], self.shas[17], self.shas[-1]
        }
        candidates, protected_count = HELPER.candidates_for(
            self.agent, self.ui, protected, self.backup
        )
        self.assertEqual(protected_count, 14)
        self.assertEqual(len(candidates), 18)
        self.assertNotIn(self.agent / ("main-" + self.shas[0]), candidates)
        self.assertNotIn(self.ui / ("main-" + self.shas[1]), candidates)
        self.assertNotIn(self.backup, candidates)
        self.assertIn(self.ui / ("main-" + self.shas[2]), candidates)
        self.assertIn(
            self.agent / f".backup-{self.shas[2][:12]}-20261023T160000Z",
            candidates,
        )
        self.assertTrue(all(p.exists() for p in candidates))

    def test_incomplete_release_rejected(self):
        (self.agent / ".incoming-recent").mkdir()
        with self.assertRaisesRegex(RuntimeError, "incomplete"):
            HELPER.candidates_for(self.agent, self.ui, set(), self.backup)

    def test_symlink_release_rejected(self):
        path = self.agent / ("main-" + self.shas[2])
        path.rmdir()
        path.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, "unsafe"):
            HELPER.candidates_for(self.agent, self.ui, set(), self.backup)

    def test_tty_approval_readonly_and_exact_confirm(self):
        with patch.object(HELPER.sys.stdout, "isatty", return_value=False):
            with self.assertRaisesRegex(RuntimeError, "interactive"):
                HELPER.ask(581)
        with patch.object(HELPER.sys.stdout, "isatty", return_value=True):
            with patch("builtins.open", return_value=io.BytesIO(b"DELETE 581\n")):
                self.assertTrue(HELPER.ask(581))
            with patch("builtins.open", return_value=io.BytesIO(b"DELETE 582\n")):
                self.assertFalse(HELPER.ask(581))

    def test_default_dry_run_and_denied_apply_never_delete(self):
        current = self.shas[-1]
        (self.ui.parent / "current").symlink_to(
            self.ui / ("main-" + current), target_is_directory=True
        )
        state = self.root / "last-success.sha"
        state.write_text(current)
        receipt = self.agent / ("main-" + current) / ".deployment-receipt.txt"
        receipt.write_text(
            f"SHA={current}\n"
            f"PREVIOUS_UI={self.ui / ('main-' + self.shas[-2])}\n"
            f"BACKUP={self.backup}\n"
        )
        with (
            patch.object(HELPER, "AGENT", self.agent),
            patch.object(HELPER, "UI", self.ui),
            patch.object(HELPER, "STATE", state),
            patch.object(HELPER, "LOCK", self.root / "lock"),
            patch.object(HELPER, "config_pins", return_value=set()),
            patch.object(HELPER, "live_pins", return_value=set()),
            patch.object(HELPER.os, "geteuid", return_value=0),
            patch.object(HELPER.os, "uname", return_value=types.SimpleNamespace(
                nodename="vps1777112993"
            )),
            patch.object(HELPER.shutil, "rmtree") as delete,
        ):
            with patch.object(HELPER.sys, "argv", ["cleanup.py"]):
                self.assertEqual(HELPER.main(), 0)
                delete.assert_not_called()
            with (
                patch.object(HELPER.sys, "argv", ["cleanup.py", "--apply"]),
                patch.object(HELPER, "ask", return_value=False),
            ):
                self.assertEqual(HELPER.main(), 0)
                delete.assert_not_called()
        self.assertTrue(receipt.exists())
        self.assertTrue(self.backup.exists())


if __name__ == "__main__":
    unittest.main()
