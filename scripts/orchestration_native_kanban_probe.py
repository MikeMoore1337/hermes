"""Isolated, zero-model proof of pinned native Hermes Kanban SQLite contracts.

Offline research-only for Hermes #474/#475. NEVER imports an installed Hermes
agent, launches a dispatcher/worker, reads a private vault or makes model calls.
Requires a separately staged PUBLIC upstream v0.22.2 checkout and its local
Python dependencies; has no network/install/production execution path.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

UPSTREAM_COMMIT = "d923a5eb487a17c0a68801bba9ef0f56c81040a8"
PINNED_BLOBS = {
    "hermes_cli/kanban_db.py": "36d5736f73ea708450e2e8306b6b0264c75d95cd",
    "hermes_cli/kanban_db_graph.py": "e3a1f306c46d076069c4c80334e04b4440aa1d18",
}


def _verify_pinned_checkout(root: Path) -> None:
    """Reject changed tracked files and any untracked files before imports.

    The pinned commit and two critical blob hashes alone are not proof that
    Python cannot import a modified companion module from this checkout.
    This check does not attest the Git remote, interpreter or dependencies.
    """
    root = root.resolve(strict=True)
    git = ["git", "-c", f"safe.directory={root}", "-C", str(root)]

    def checked(*args: str) -> str:
        return subprocess.run(
            [*git, *args], capture_output=True, text=True,
            check=True, timeout=8,
        ).stdout.strip()

    top = Path(checked("rev-parse", "--show-toplevel")).resolve(strict=True)
    if top != root:
        raise RuntimeError("upstream_root_mismatch")
    if checked("rev-parse", "HEAD") != UPSTREAM_COMMIT:
        raise RuntimeError("upstream_commit_mismatch")
    if checked("status", "--porcelain=v1", "--untracked-files=all"):
        raise RuntimeError("upstream_checkout_dirty")

    for relative, expected in PINNED_BLOBS.items():
        data = (root / relative).read_bytes()
        blob = hashlib.sha1(("blob %d\0" % len(data)).encode() + data).hexdigest()
        if blob != expected:
            raise RuntimeError("upstream_blob_mismatch:" + relative)


def run(source_dir: Path, deps_dir: Path | None = None) -> bool:
    source_dir = source_dir.resolve(strict=True)
    _verify_pinned_checkout(source_dir)
    if deps_dir is not None:
        sys.path.insert(0, str(deps_dir.resolve(strict=True)))
    sys.path.insert(0, str(source_dir))
    # All task data is confined to temporary SQLite databases.
    with tempfile.TemporaryDirectory(prefix="hermes-474-475-native-") as workspace:
        os.environ["HERMES_HOME"] = workspace
        os.environ["HERMES_KANBAN_DB"] = str(Path(workspace) / "root.sqlite")
        from hermes_cli import kanban_db as k
        from hermes_cli import kanban_db_connect as c

        class NativeKanbanTests(unittest.TestCase):
            def setUp(self):
                self.temporary = tempfile.TemporaryDirectory(
                    prefix="case-", dir=workspace,
                )
                self.addCleanup(self.temporary.cleanup)
                self.path = Path(self.temporary.name) / "board.sqlite"

            def pair(self, db):
                a = k.create_task(db, title="synthetic analysis",
                                  workspace_kind="scratch")
                b = k.create_task(db, title="synthetic security",
                                  workspace_kind="scratch")
                qa = k.create_task(db, title="synthetic QA", parents=[a, b],
                                   workspace_kind="scratch")
                return a, b, qa

            def test_parent_gate_and_reopen(self):
                with c.connect_closing(self.path) as db:
                    a, b, qa = self.pair(db)
                    self.assertEqual(k.get_task(db, qa).status, "todo")
                    self.assertFalse(k.complete_task(
                        db, qa, result="early", fire_lifecycle_hook=False))
                    self.assertTrue(k.complete_task(
                        db, a, result="analysis receipt",
                        fire_lifecycle_hook=False))
                    self.assertEqual(k.get_task(db, qa).status, "todo")
                    self.assertTrue(k.complete_task(
                        db, b, result="security receipt",
                        fire_lifecycle_hook=False))
                    self.assertEqual(k.get_task(db, qa).status, "ready")
                    self.assertTrue(k.complete_task(
                        db, qa, result="QA review",
                        fire_lifecycle_hook=False))
                with c.connect_closing(self.path) as db:
                    self.assertEqual(k.get_task(db, qa).result, "QA review")
                    self.assertEqual(k.get_task(db, qa).status, "done")

            def test_cycle_reject(self):
                with c.connect_closing(self.path) as db:
                    a, _, qa = self.pair(db)
                    with self.assertRaisesRegex(ValueError, "cycle"):
                        k.link_tasks(db, qa, a)
                    self.assertFalse(k.parent_ids(db, a))

            def test_self_and_unknown_parent_reject(self):
                with c.connect_closing(self.path) as db:
                    a = k.create_task(db, title="synthetic", workspace_kind="scratch")
                    with self.assertRaises(ValueError):
                        k.link_tasks(db, a, a)
                    with self.assertRaises(ValueError):
                        k.link_tasks(db, "t_unknown", a)

            def test_idempotent_creation(self):
                with c.connect_closing(self.path) as db:
                    a = k.create_task(db, title="once", workspace_kind="scratch",
                                      idempotency_key="test-unique-create")
                    b = k.create_task(db, title="repeat", workspace_kind="scratch",
                                      idempotency_key="test-unique-create")
                    self.assertEqual(a, b)

            def test_concurrent_claim_one_winner(self):
                with c.connect_closing(self.path) as db:
                    a = k.create_task(db, title="claim", workspace_kind="scratch")
                def claim(worker):
                    with c.connect_closing(self.path) as db:
                        return k.claim_task(db, a, ttl_seconds=30,
                                            claimer=worker) is not None
                with ThreadPoolExecutor(max_workers=2) as pool:
                    results = list(pool.map(claim, ("synthetic-A", "synthetic-B")))
                self.assertEqual(sorted(results), [False, True])

            def test_reopen_does_not_claim_running_again(self):
                with c.connect_closing(self.path) as db:
                    a = k.create_task(db, title="in flight",
                                      workspace_kind="scratch")
                    self.assertIsNotNone(k.claim_task(
                        db, a, ttl_seconds=120, claimer="owner-1"))
                with c.connect_closing(self.path) as db:
                    self.assertEqual(k.get_task(db, a).status, "running")
                    self.assertIsNone(k.claim_task(
                        db, a, ttl_seconds=120, claimer="owner-2"))

            def test_force_exit_after_claim_preserves_running_state(self):
                # Real synthetic Python child exits abruptly after a durable
                # SQLite claim. This is NOT a crash of a running LLM worker.
                with c.connect_closing(self.path) as db:
                    task = k.create_task(db, title="synthetic crash",
                                         workspace_kind="scratch")
                child_program = (
                    "import os,sys\n"
                    "from pathlib import Path\n"
                    "from hermes_cli import kanban_db as k, kanban_db_connect as c\n"
                    "with c.connect_closing(Path(sys.argv[1])) as db:\n"
                    "    if k.claim_task(db,sys.argv[2],ttl_seconds=120,"
                    "claimer='synthetic-child') is None: os._exit(40)\n"
                    "os._exit(29)\n"
                )
                local_env = {
                    "PATH": os.environ.get("PATH", ""),
                    "HOME": workspace,
                    "HERMES_HOME": workspace,
                    "HERMES_KANBAN_DB": str(self.path),
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "PYTHONPATH": os.pathsep.join(
                        [str(source_dir)] +
                        ([str(deps_dir.resolve())] if deps_dir else [])),
                }
                crashed = subprocess.run(
                    [sys.executable, "-B", "-c", child_program,
                     str(self.path), task],
                    cwd=str(source_dir), env=local_env, capture_output=True,
                    timeout=20, check=False,
                )
                self.assertEqual(crashed.returncode, 29)
                with c.connect_closing(self.path) as db:
                    self.assertEqual(k.get_task(db, task).status, "running")
                    self.assertIsNone(k.claim_task(
                        db, task, ttl_seconds=120, claimer="after-crash"))

            def test_archived_parent_unblocks_unproven_child(self):
                # Important native semantics: archived is a satisfied DAG
                # dependency, NOT independent evidence of successful analysis.
                with c.connect_closing(self.path) as db:
                    parent = k.create_task(db, title="archived parent",
                                           workspace_kind="scratch")
                    qa = k.create_task(db, title="QA child", parents=[parent],
                                       workspace_kind="scratch")
                    self.assertEqual(k.get_task(db, qa).status, "todo")
                    self.assertTrue(k.archive_task(db, parent))
                    self.assertEqual(k.get_task(db, qa).status, "ready")
                    self.assertIsNone(k.get_task(db, parent).result)

            def test_blocked_parent_cannot_complete_child(self):
                with c.connect_closing(self.path) as db:
                    a, _, qa = self.pair(db)
                    self.assertTrue(k.block_task(
                        db, a, reason="synthetic missing evidence"))
                    self.assertFalse(k.complete_task(
                        db, qa, result="premature", fire_lifecycle_hook=False))
                    self.assertEqual(k.get_task(db, qa).status, "todo")

            def test_completed_task_cannot_be_replayed(self):
                with c.connect_closing(self.path) as db:
                    a = k.create_task(db, title="complete", workspace_kind="scratch")
                    self.assertTrue(k.complete_task(
                        db, a, result="first", fire_lifecycle_hook=False))
                    self.assertFalse(k.complete_task(
                        db, a, result="second", fire_lifecycle_hook=False))
                    self.assertEqual(k.get_task(db, a).result, "first")

            def test_isolated_db_path(self):
                with c.connect_closing(self.path) as db:
                    actual = db.execute("PRAGMA database_list").fetchone()["file"]
                    self.assertEqual(Path(actual).resolve(), self.path.resolve())
                    self.assertIn(db.execute("PRAGMA journal_mode").fetchone()[0],
                                  {"wal", "delete"})

        print("UPSTREAM_NATIVE_COMMIT_VERIFIED", UPSTREAM_COMMIT, flush=True)
        print("SQLITE_ENGINE", sqlite3.sqlite_version, flush=True)
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(NativeKanbanTests)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        return result.wasSuccessful()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream-dir", type=Path, required=True)
    parser.add_argument("--deps-dir", type=Path)
    args = parser.parse_args()
    try:
        return 0 if run(args.upstream_dir, args.deps_dir) else 1
    except Exception as exc:
        print(f"NATIVE_PROBE_NOT_RUN: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
