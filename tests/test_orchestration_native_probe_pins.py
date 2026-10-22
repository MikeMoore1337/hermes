"""Offline negative tests for provenance of the optional native Kanban probe.

Hermes #474 / #475. Uses tiny local Git fixture; no upstream network fetch,
model invocation, actual dispatcher, user data, or production dependencies.
"""
import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from scripts import orchestration_native_kanban_probe as probe


def blob_id(contents: bytes) -> str:
    return hashlib.sha1(("blob %d\0" % len(contents)).encode() + contents).hexdigest()


class PinnedCheckoutTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory(prefix="native-pin-probe-")
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name).resolve()
        pkg = self.root / "hermes_cli"
        pkg.mkdir()
        self.paths = {
            "hermes_cli/kanban_db.py": b"# clean fixture native DB\n",
            "hermes_cli/kanban_db_graph.py": b"# clean fixture native DAG\n",
        }
        for name, contents in self.paths.items():
            (self.root / name).write_bytes(contents)
        self.git("init", "-q")
        self.git("add", "--all")
        self.git("-c", "user.email=ci@example.invalid", "-c", "user.name=CI Fixture",
                 "commit", "-qm", "create clean fixture")
        commit = self.git("rev-parse", "HEAD").stdout.strip()
        pins = {name: blob_id(contents) for name, contents in self.paths.items()}
        x = mock.patch.object(probe, "UPSTREAM_COMMIT", commit)
        y = mock.patch.object(probe, "PINNED_BLOBS", pins)
        x.start()
        y.start()
        self.addCleanup(x.stop)
        self.addCleanup(y.stop)

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.root), *args],
                              capture_output=True, text=True, check=True, timeout=8)

    def test_clean_pinned_fixture_accepted(self):
        probe._verify_pinned_checkout(self.root)

    def test_modified_tracked_sibling_rejected(self):
        (self.root / "hermes_cli/kanban_db_graph.py").write_text("# edited\n")
        with self.assertRaisesRegex(RuntimeError, "upstream_checkout_dirty"):
            probe._verify_pinned_checkout(self.root)

    def test_untracked_module_rejected(self):
        (self.root / "hermes_cli/unexpected_agent.py").write_text("# not pinned\n")
        with self.assertRaisesRegex(RuntimeError, "upstream_checkout_dirty"):
            probe._verify_pinned_checkout(self.root)

    def test_ignored_python_module_rejected(self):
        (self.root / ".gitignore").write_text("rogue.py\n")
        self.git("add", ".gitignore")
        self.git("-c", "user.email=ci@example.invalid", "-c", "user.name=CI Fixture",
                 "commit", "-qm", "ignore new source")
        # Update only the independently verified commit identity to isolate
        # the ignored-importable guard from the pinned-commit check.
        with mock.patch.object(probe, "UPSTREAM_COMMIT",
                               self.git("rev-parse", "HEAD").stdout.strip()):
            (self.root / "rogue.py").write_text("# ignored code\n")
            with self.assertRaisesRegex(RuntimeError,
                                        "upstream_checkout_ignored_importables"):
                probe._verify_pinned_checkout(self.root)

    def test_pinned_commit_mismatch_rejected(self):
        with mock.patch.object(probe, "UPSTREAM_COMMIT", "f" * 40):
            with self.assertRaisesRegex(RuntimeError, "upstream_commit_mismatch"):
                probe._verify_pinned_checkout(self.root)

    def test_pinned_blob_mismatch_rejected(self):
        wrong = dict(probe.PINNED_BLOBS,
                     **{"hermes_cli/kanban_db.py": "f" * 40})
        with mock.patch.object(probe, "PINNED_BLOBS", wrong):
            with self.assertRaisesRegex(RuntimeError, "upstream_blob_mismatch"):
                probe._verify_pinned_checkout(self.root)

    def test_nested_path_not_accepted_as_checkout_root(self):
        with self.assertRaisesRegex(RuntimeError, "upstream_root_mismatch"):
            probe._verify_pinned_checkout(self.root / "hermes_cli")


if __name__ == "__main__":
    unittest.main()
