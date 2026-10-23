"""Isolated, zero-model proof of pinned native Hermes Kanban SQLite contracts.

Offline research-only for Hermes #474/#475. NEVER imports an installed Hermes
agent, launches a dispatcher/worker, reads a private vault or makes model calls.
Requires a separately staged PUBLIC upstream v0.22.2 checkout and its local
Python dependencies; has no network/install/production execution path.
"""
from __future__ import annotations

import argparse
import ast
from concurrent.futures import ThreadPoolExecutor
import hashlib
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

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
            # Mounted Windows workspaces can need >8s for a cold tracked-tree
            # scan. Preserve strict fail-closed status/pin checks; allow only
            # the expensive inventory commands a bounded 30-second window.
            check=True, timeout=30 if args[0] in ("status", "ls-files") else 8,
        ).stdout.strip()

    top = Path(checked("rev-parse", "--show-toplevel")).resolve(strict=True)
    if top != root:
        raise RuntimeError("upstream_root_mismatch")
    if checked("rev-parse", "HEAD") != UPSTREAM_COMMIT:
        raise RuntimeError("upstream_commit_mismatch")
    if checked("status", "--porcelain=v1", "--untracked-files=all"):
        raise RuntimeError("upstream_checkout_dirty")
    # Ignored Python sources and extension modules can still be imported,
    # although git status suppresses them.
    if checked("ls-files", "--others", "--ignored", "--exclude-standard", "--",
               "*.py", "*.so", "*.pyd"):
        raise RuntimeError("upstream_checkout_ignored_importables")

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
        from tools import delegate_tool_toolsets as dt
        from tools import delegate_tool_config as dc

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

            def test_heartbeat_requires_exact_claim_owner(self):
                with c.connect_closing(self.path) as db:
                    task = k.create_task(
                        db, title="heartbeat synthetic", workspace_kind="scratch")
                    self.assertIsNotNone(k.claim_task(
                        db, task, ttl_seconds=30, claimer="owner-A"))
                    before = db.execute(
                        "SELECT claim_expires FROM tasks WHERE id=?", (task,)
                    ).fetchone()["claim_expires"]
                    self.assertFalse(k.heartbeat_claim(
                        db, task, claimer="wrong-owner", ttl_seconds=120))
                    self.assertTrue(k.heartbeat_claim(
                        db, task, claimer="owner-A", ttl_seconds=120))
                    after = db.execute(
                        "SELECT claim_expires FROM tasks WHERE id=?", (task,)
                    ).fetchone()["claim_expires"]
                    self.assertGreater(after, before)

            def test_expired_no_worker_claim_requeues_once(self):
                # This proves native task retry semantics; a real model
                # adapter MUST separately block a repeated inference call.
                with c.connect_closing(self.path) as db:
                    task = k.create_task(
                        db, title="expired synthetic", workspace_kind="scratch")
                    self.assertIsNotNone(k.claim_task(
                        db, task, ttl_seconds=120, claimer="owner-1"))
                    db.execute(
                        "UPDATE tasks SET claim_expires=0 WHERE id=?", (task,))
                    self.assertEqual(k.release_stale_claims(db), 1)
                    self.assertEqual(k.release_stale_claims(db), 0)
                    self.assertEqual(k.get_task(db, task).status, "ready")
                    self.assertIsNotNone(k.claim_task(
                        db, task, ttl_seconds=120, claimer="owner-2"))

            def test_manual_reclaim_idempotent_with_no_worker(self):
                # No PID/OS signal is involved in this synthetic case.
                with c.connect_closing(self.path) as db:
                    task = k.create_task(
                        db, title="operator synthetic", workspace_kind="scratch")
                    self.assertIsNotNone(k.claim_task(
                        db, task, ttl_seconds=120, claimer="owner-1"))
                    self.assertTrue(k.reclaim_task(
                        db, task, reason="synthetic cancel"))
                    self.assertFalse(k.reclaim_task(
                        db, task, reason="synthetic duplicate"))
                    self.assertEqual(k.get_task(db, task).status, "ready")

            def test_expired_claim_keeps_alive_verified_local_worker(self):
                # Expired SQLite TTL is not permission to duplicate work when
                # its fingerprinted local OS subprocess remains alive.
                from hermes_cli import kanban_db_dispatch as dispatch
                with c.connect_closing(self.path) as db:
                    task = k.create_task(
                        db, title="live-lease protection", workspace_kind="scratch")
                    claimed = k.claim_task(db, task, ttl_seconds=120)
                    self.assertIsNotNone(claimed)
                    child = subprocess.Popen(
                        [sys.executable, "-B", "-c", "import time; time.sleep(30)"],
                        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    try:
                        self.assertTrue(dispatch.adopt_worker_pid(
                            db, task, claimed.current_run_id, child.pid))
                        evidence = db.execute(
                            "SELECT claim_lock, worker_started_at FROM tasks WHERE id=?",
                            (task,)
                        ).fetchone()
                        self.assertTrue(evidence["claim_lock"].startswith(
                            k._host_prefix()))
                        self.assertIn("|", evidence["worker_started_at"])
                        db.execute(
                            "UPDATE tasks SET claim_expires=0 WHERE id=?", (task,))
                        self.assertEqual(k.release_stale_claims(db), 0)
                        after = k.get_task(db, task)
                        self.assertEqual(after.status, "running")
                        self.assertIsNone(k.claim_task(
                            db, task, ttl_seconds=120, claimer="second-claimer"))
                        self.assertIsNone(child.poll())
                        self.assertGreater(
                            db.execute("SELECT claim_expires FROM tasks "
                                       "WHERE id=?", (task,)).fetchone()[0],
                            0)
                    finally:
                        if child.poll() is None:
                            child.terminate()
                        try:
                            child.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            child.kill()
                            child.wait(timeout=3)

            def test_native_refuses_signals_without_verified_local_pid(self):
                # Actual live disposable OS child; NO signal is allowed for
                # unverified/foreign/recycled identity. Never an LLM worker.
                from hermes_cli import kanban_db_dispatch as dispatch
                child = subprocess.Popen(
                    [sys.executable, "-B", "-c", "import time; time.sleep(30)"],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                sent = []
                def forbid_signal(pid, sig):
                    sent.append((pid, sig))
                    self.fail("native signalled a non-verified child")
                try:
                    local_lock = k._host_prefix() + "synthetic-owner"
                    # A bare, living PID is NOT permission to kill.
                    unverified = dispatch._terminate_reclaimed_worker(
                        child.pid, local_lock, signal_fn=forbid_signal,
                        started_at=dispatch.UNVERIFIED_WORKER_FINGERPRINT)
                    self.assertTrue(unverified["signal_refused"])
                    self.assertFalse(unverified["termination_attempted"])
                    self.assertFalse(unverified["terminated"])
                    self.assertIsNone(child.poll())

                    # Foreign host claims must not be interpreted as local.
                    foreign = dispatch._terminate_reclaimed_worker(
                        child.pid, "foreign-host:other", signal_fn=forbid_signal,
                        started_at=None)
                    self.assertFalse(foreign["host_local"])
                    self.assertFalse(foreign["termination_attempted"])
                    self.assertIsNone(child.poll())

                    # Live PID with a fingerprint from a different process
                    # instantiation must also be left untouched.
                    fingerprint = dispatch._process_fingerprint(child.pid)
                    self.assertIsNotNone(fingerprint)
                    recycled = dispatch._terminate_reclaimed_worker(
                        child.pid, local_lock, signal_fn=forbid_signal,
                        started_at="different-instantiation|" + fingerprint)
                    self.assertTrue(recycled["pid_recycled"])
                    self.assertFalse(recycled["termination_attempted"])
                    self.assertIsNone(child.poll())
                    self.assertEqual(sent, [])
                finally:
                    if child.poll() is None:
                        child.terminate()
                    try:
                        child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=3)

            def test_archive_signals_only_verified_local_sleeper(self):
                # Actual local OS signal to an inert child in an ephemeral
                # runner. No model, provider, real worker or resident service.
                from hermes_cli import kanban_db_dispatch as dispatch
                with c.connect_closing(self.path) as db:
                    task = k.create_task(
                        db, title="ephemeral OS child", workspace_kind="scratch")
                    claimed = k.claim_task(db, task, ttl_seconds=120)
                    self.assertIsNotNone(claimed)
                    child = subprocess.Popen(
                        [sys.executable, "-B", "-c", "import time; time.sleep(30)"],
                        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    delivered = []
                    try:
                        self.assertTrue(dispatch.adopt_worker_pid(
                            db, task, claimed.current_run_id, child.pid))
                        row = db.execute(
                            "SELECT worker_pid, worker_started_at "
                            "FROM tasks WHERE id=?", (task,)
                        ).fetchone()
                        self.assertEqual(row["worker_pid"], child.pid)
                        # A real process fingerprint, not only a PID.
                        self.assertIn("|", row["worker_started_at"])

                        def signal_only_known_child(pid, signum):
                            self.assertEqual(pid, child.pid)
                            delivered.append(signum)
                            os.kill(pid, signum)

                        self.assertTrue(k.archive_task(
                            db, task, signal_fn=signal_only_known_child))
                        child.wait(timeout=8)
                        self.assertTrue(delivered)
                        self.assertNotEqual(child.returncode, 0)
                        self.assertEqual(k.get_task(db, task).status, "archived")
                        self.assertIsNone(k.claim_task(
                            db, task, ttl_seconds=120, claimer="other"))
                    finally:
                        if child.poll() is None:
                            child.terminate()
                        try:
                            child.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            child.kill()
                            child.wait(timeout=3)

            def test_archived_running_task_is_terminal(self):
                # Terminal archive is not proof of OS worker termination.
                with c.connect_closing(self.path) as db:
                    task = k.create_task(
                        db, title="archived synthetic", workspace_kind="scratch")
                    self.assertIsNotNone(k.claim_task(
                        db, task, ttl_seconds=120, claimer="owner-1"))
                    self.assertTrue(k.archive_task(db, task))
                    self.assertFalse(k.archive_task(db, task))
                    self.assertEqual(k.get_task(db, task).status, "archived")
                    self.assertIsNone(k.claim_task(
                        db, task, ttl_seconds=120, claimer="owner-2"))

            def test_stale_run_id_cannot_complete_new_claim(self):
                with c.connect_closing(self.path) as db:
                    task = k.create_task(
                        db, title="stale ownership", workspace_kind="scratch")
                    old = k.claim_task(
                        db, task, ttl_seconds=120, claimer="owner-1")
                    self.assertIsNotNone(old)
                    old_run_id = old.current_run_id
                    self.assertTrue(k.reclaim_task(
                        db, task, reason="synthetic restore"))
                    new = k.claim_task(
                        db, task, ttl_seconds=120, claimer="owner-2")
                    self.assertIsNotNone(new)
                    self.assertNotEqual(new.current_run_id, old_run_id)
                    self.assertFalse(k.complete_task(
                        db, task, result="stale result",
                        expected_run_id=old_run_id,
                        fire_lifecycle_hook=False))
                    self.assertEqual(k.get_task(db, task).status, "running")

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

        class NativeDelegationToolsetsTests(unittest.TestCase):
            """Execute the real pinned upstream resolver with inert parent objects.

            Tests actual Python function bodies with no AIAgent/LLM dispatch.
            Patching only configuration input prevents loading paid providers
            and credentials. Results reveal admission hazards, not OS rights.
            """

            def parent(self, enabled=("web",), disabled=()):
                return SimpleNamespace(
                    enabled_toolsets=list(enabled),
                    disabled_toolsets=list(disabled),
                )

            def test_explicit_child_request_cannot_add_non_parent_toolset(self):
                with patch.object(dc, "_cfg", return_value={"inherit_mcp_toolsets": False}):
                    enabled, disabled = dt._resolve_child_toolsets(
                        self.parent(enabled=("web",)), ["terminal", "web"],
                        "leaf")
                self.assertEqual(enabled, ["web"])
                self.assertNotIn("delegation", enabled)
                self.assertIn("kanban", disabled)

            def test_parent_disabled_toolset_passes_to_child(self):
                with patch.object(dc, "_cfg", return_value={"inherit_mcp_toolsets": False}):
                    enabled, disabled = dt._resolve_child_toolsets(
                        self.parent(enabled=("web", "file"), disabled=("file",)),
                        ["web"], "leaf")
                self.assertEqual(enabled, ["web"])
                self.assertIn("file", disabled)

            def test_empty_explicit_toolsets_do_not_mean_no_tools(self):
                parent = self.parent(enabled=("web", "terminal"))
                with patch.object(dc, "_cfg", return_value={"inherit_mcp_toolsets": False}):
                    unspecified, _ = dt._resolve_child_toolsets(parent, None, "leaf")
                    empty, _ = dt._resolve_child_toolsets(parent, [], "leaf")
                self.assertEqual(empty, unspecified)
                self.assertEqual(set(empty), {"web", "terminal"})

            def test_orchestrator_role_adds_delegation_outside_parent(self):
                # Upstream role exception is NOT a safe child-rights assertion.
                with patch.object(dc, "_cfg", return_value={"inherit_mcp_toolsets": False}):
                    enabled, _ = dt._resolve_child_toolsets(
                        self.parent(enabled=("web",)), ["web"], "orchestrator")
                self.assertIn("delegation", enabled)

            def test_default_config_inherits_parent_mcp_despite_narrow_request(self):
                # Native config defaults to inheritance. Textual child scopes
                # cannot be trusted to exclude MCP on their own.
                with patch.object(dc, "_cfg", return_value={}):
                    self.assertTrue(dc._get_inherit_mcp_toolsets())
                    enabled, _ = dt._resolve_child_toolsets(
                        self.parent(enabled=("web", "mcp-synthetic")),
                        ["web"], "leaf")
                self.assertEqual(enabled, ["web", "mcp-synthetic"])

            def test_disabled_delegation_does_not_constrain_orchestrator(self):
                # Caller-side authorization must reject privileged roles:
                # native role handling intentionally clears this inherited deny.
                with patch.object(dc, "_cfg", return_value={"inherit_mcp_toolsets": False}):
                    enabled, disabled = dt._resolve_child_toolsets(
                        self.parent(enabled=("web",), disabled=("delegation",)),
                        ["web"], "orchestrator")
                self.assertIn("delegation", enabled)
                self.assertNotIn("delegation", disabled)

            def test_disabled_mcp_inheritance_does_not_restrict_implicit_toolsets(self):
                # Disabling inheritance only helps for explicit nonempty
                # requests. Native delegate_task itself uses toolsets=None,
                # so the public path does not exercise the safe subcase.
                parent = self.parent(enabled=("web", "mcp-synthetic"))
                with patch.object(dc, "_cfg", return_value={"inherit_mcp_toolsets": False}):
                    none_enabled, _ = dt._resolve_child_toolsets(parent, None, "leaf")
                    empty_enabled, _ = dt._resolve_child_toolsets(parent, [], "leaf")
                self.assertIn("mcp-synthetic", none_enabled)
                self.assertIn("mcp-synthetic", empty_enabled)

            def test_upstream_public_delegate_path_passes_no_child_allowlist(self):
                # Source-shape assertion on the independently pinned original
                # implementation. Not an executed native child or runtime gate.
                tree = ast.parse(
                    (source_dir / "tools/delegate_tool.py").read_text(encoding="utf-8"))
                build = next(
                    node for node in tree.body
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and node.name == "_build_children")
                calls = [
                    node for node in ast.walk(build)
                    if isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "_build_child_preserving_parent_tools"
                ]
                self.assertEqual(len(calls), 1)
                allowlists = [kw.value for kw in calls[0].keywords if kw.arg == "toolsets"]
                self.assertEqual(len(allowlists), 1)
                self.assertIsInstance(allowlists[0], ast.Constant)
                self.assertIsNone(allowlists[0].value)

            def test_upstream_child_effective_role_is_depth_derived(self):
                # Do not mistake a user-visible "leaf" role parameter for
                # a native security control: this parameter is ignored.
                tree = ast.parse(
                    (source_dir / "tools/delegate_tool.py").read_text(encoding="utf-8"))
                build = next(
                    node for node in tree.body
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and node.name == "_build_child_agent")
                self.assertFalse(any(
                    isinstance(node, ast.Name) and node.id == "role"
                    and isinstance(node.ctx, ast.Load)
                    for node in ast.walk(build)))
                role_assignments = [
                    node.value for node in ast.walk(build)
                    if isinstance(node, ast.Assign)
                    and any(isinstance(t, ast.Name) and t.id == "effective_role"
                            for t in node.targets)
                ]
                self.assertEqual(len(role_assignments), 1)
                self.assertIsInstance(role_assignments[0], ast.IfExp)
                role_condition = ast.unparse(role_assignments[0].test)
                self.assertIn("_get_orchestrator_enabled()", role_condition)
                self.assertIn("child_depth < max_spawn", role_condition)
                with patch.object(dc, "_cfg", return_value={}):
                    self.assertEqual(dc._get_max_spawn_depth(), 1)
                    self.assertTrue(dc._get_orchestrator_enabled())
                with patch.object(dc, "_cfg", return_value={
                    "max_spawn_depth": 2, "orchestrator_enabled": False}):
                    self.assertEqual(dc._get_max_spawn_depth(), 2)
                    self.assertFalse(dc._get_orchestrator_enabled())

            def test_explicit_disabled_mcp_inheritance_is_narrow(self):
                with patch.object(dc, "_cfg", return_value={"inherit_mcp_toolsets": False}):
                    self.assertFalse(dc._get_inherit_mcp_toolsets())
                    enabled, _ = dt._resolve_child_toolsets(
                        self.parent(enabled=("web", "mcp-synthetic")),
                        ["web"], "leaf")
                self.assertEqual(enabled, ["web"])

        print("UPSTREAM_NATIVE_COMMIT_VERIFIED", UPSTREAM_COMMIT, flush=True)
        print("SQLITE_ENGINE", sqlite3.sqlite_version, flush=True)
        suite = unittest.TestSuite([
            unittest.defaultTestLoader.loadTestsFromTestCase(NativeKanbanTests),
            unittest.defaultTestLoader.loadTestsFromTestCase(NativeDelegationToolsetsTests),
        ])
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
