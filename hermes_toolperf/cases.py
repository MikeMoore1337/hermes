"""H-26: pinned synthetic tool workflows; no copied upstream source or live device calls."""
from __future__ import annotations

VERSION = 1


def _case(ident, category, files, expected, allowed_writes, required_reads,
          baseline, candidate, *, checks=(), budget=4):
    return {
        "task_id": ident, "version": VERSION, "category": category,
        "initial_files": files, "expected_files": expected,
        "allowed_writes": list(allowed_writes),
        "required_reads": {name: list(offsets) for name, offsets in required_reads.items()},
        "required_checks": list(checks), "call_budget": budget,
        "output_budget": 128, "baseline": baseline, "candidate": candidate,
    }


CASES = [
    _case(
        "tp-01-python-environment", "python_environment",
        {"pyproject.toml": 'requires-python = ">=3.11"\n'},
        {"pyproject.toml": 'requires-python = ">=3.11"\n'}, (), 
        {"pyproject.toml": (0,)},
        [{"op": "read", "path": "pyproject.toml", "limit": 50},
         {"op": "env", "version": "3.11"},
         {"op": "env", "version": "3.11", "retry": True}],
        [{"op": "read", "path": "pyproject.toml", "limit": 50},
         {"op": "env", "version": "3.11"}],
        checks=("env-ok",), budget=3,
    ),
    _case(
        "tp-02-duplicate-patch", "repeat_patch",
        {"src/task.txt": "old\n"}, {"src/task.txt": "new\n"},
        ("src/task.txt",), {},
        [{"op": "patch", "path": "src/task.txt", "old": "old", "new": "new"},
         {"op": "patch", "path": "src/task.txt", "old": "old", "new": "new",
          "retry": True}],
        [{"op": "patch", "path": "src/task.txt", "old": "old", "new": "new"}],
        budget=2,
    ),
    _case(
        "tp-03-ambiguous-patch", "ambiguous_patch",
        {"src/data.txt": "alpha\nalpha\n"}, {"src/data.txt": "alpha\nbeta\n"},
        ("src/data.txt",), {},
        [{"op": "patch", "path": "src/data.txt", "old": "alpha", "new": "beta"}],
        [{"op": "write", "path": "src/data.txt", "content": "alpha\nbeta\n"}],
        budget=1,
    ),
    _case(
        "tp-04-case-sensitive-path", "case_sensitive_paths",
        {"README.md": "draft\n"}, {"README.md": "final\n"},
        ("README.md",), {},
        [{"op": "patch", "path": "readme.md", "old": "draft", "new": "final"}],
        [{"op": "patch", "path": "README.md", "old": "draft", "new": "final"}],
        budget=1,
    ),
    _case(
        "tp-05-hidden-file", "hidden_file_visibility",
        {".config/policy.txt": "deny\n"}, {".config/policy.txt": "deny\n"},
        (), {".config/policy.txt": (0,)},
        [{"op": "list", "hidden": False}, {"op": "claim", "success": True}],
        [{"op": "list", "hidden": True},
         {"op": "read", "path": ".config/policy.txt", "limit": 16}],
        budget=2,
    ),
    _case(
        "tp-06-large-output", "bounded_output",
        {"logs/events.txt": "L" * 512}, {"logs/events.txt": "L" * 512},
        (), {"logs/events.txt": (0,)},
        [{"op": "read", "path": "logs/events.txt", "limit": 512}],
        [{"op": "read", "path": "logs/events.txt", "limit": 64}],
        budget=1,
    ),
    _case(
        "tp-07-multiple-directories", "directory_scoping",
        {"project-a/src/task.txt": "old\n", "project-b/src/task.txt": "old\n"},
        {"project-a/src/task.txt": "old\n", "project-b/src/task.txt": "fixed\n"},
        ("project-b/src/task.txt",), {},
        [{"op": "write", "path": "project-a/src/task.txt", "content": "fixed\n"}],
        [{"op": "write", "path": "project-b/src/task.txt", "content": "fixed\n"}],
        budget=1,
    ),
    _case(
        "tp-08-inline-script", "inline_script_denial",
        {"src/task.txt": "ready\n"}, {"src/task.txt": "ready\n"},
        (), {},
        [{"op": "run", "script": "python -c 'print(123)'"},
         {"op": "claim", "success": True}],
        [{"op": "check", "path": "src/task.txt", "expected": "ready\n"}],
        checks=("check-ok",), budget=2,
    ),
    _case(
        "tp-09-large-file-read", "chunked_read",
        {"docs/large.txt": "x" * 4096}, {"docs/large.txt": "x" * 4096},
        (), {"docs/large.txt": (0, 4064)},
        [{"op": "read", "path": "docs/large.txt", "limit": 4096}],
        [{"op": "read", "path": "docs/large.txt", "offset": 0, "limit": 64},
         {"op": "read", "path": "docs/large.txt", "offset": 4064, "limit": 32}],
        budget=2,
    ),
]
