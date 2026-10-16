"""Read-only, no-import inventory of Python risk surfaces at exact upstream v0.22.2.

This is *source* inspection, not a runtime tool policy, sandbox or image attestation.
Never execute upstream code. All success-like observations keep resident NO-GO.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
from typing import Any

UPSTREAM_COMMIT = "d923a5eb487a17c0a68801bba9ef0f56c81040a8"
SOURCE_IMAGE = ("nousresearch/hermes-agent@sha256:"
                "a11574b7fe8e1631d7d88d556677dac693bc058abf558cdeb899155688c1bf05")
MAX_PY_BYTES = 1_500_000
MAX_TOTAL_BYTES = 150_000_000
MAX_PY_FILES = 15_000
JWT_TRIGGER = re.compile(rb"\b(?:jwt\b|verify_jwt\b)", re.I)
XML_TRIGGER = re.compile(rb"\b(?:xml|lxml|defusedxml|xmltodict)\b", re.I)
SSH_TRIGGER = re.compile(rb"\b(?:ssh|paramiko|asyncssh)\b", re.I)
HMAC_ALGORITHMS = frozenset({"HS256", "HS384", "HS512"})
ASYMMETRIC_ALGORITHMS = frozenset({"RS256", "RS384", "RS512",
                                  "PS256", "PS384", "PS512", "ES256",
                                  "ES384", "ES512", "EdDSA"})


class SourceAuditDenied(ValueError):
    """Fixed error types. Never embed untrusted source code or private paths."""


def _git(repo: Path, *args: str) -> bytes:
    if repo.is_symlink() or not repo.is_dir():
        raise SourceAuditDenied("invalid_source_root")
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo), *args], check=False,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=45,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0"},
        )
    except (OSError, subprocess.TimeoutExpired):
        raise SourceAuditDenied("local_git_unavailable") from None
    if proc.returncode:
        raise SourceAuditDenied("git_snapshot_verification_failed")
    return proc.stdout


def _verified_git_filenames(repo: Path) -> list[str]:
    commit = _git(repo, "rev-parse", "--verify", "HEAD").decode("ascii", "strict").strip()
    if commit != UPSTREAM_COMMIT:
        raise SourceAuditDenied("wrong_upstream_commit")
    if _git(repo, "status", "--porcelain", "--untracked-files=no").strip():
        raise SourceAuditDenied("dirty_upstream_source")
    paths = _git(repo, "ls-files", "-z", "--", "*.py").split(b"\0")
    if paths[-1] != b"":
        raise SourceAuditDenied("invalid_git_filename_stream")
    try:
        names = [p.decode("utf-8") for p in paths[:-1]]
    except UnicodeError:
        raise SourceAuditDenied("invalid_git_filename_stream") from None
    if not 100 <= len(names) <= MAX_PY_FILES or len(names) != len(set(names)):
        raise SourceAuditDenied("incomplete_git_python_inventory")
    for name in names:
        rel = PurePosixPath(name)
        if (not rel.parts or rel.is_absolute() or ".." in rel.parts
                or not name.endswith(".py") or chr(92) in name):
            raise SourceAuditDenied("unsafe_git_file_path")
    return names


def _literal_list(node: ast.AST) -> list[str] | None:
    if isinstance(node, (ast.List, ast.Tuple)):
        values = node.elts
        if values and all(isinstance(x, ast.Constant) and type(x.value) is str for x in values):
            return [x.value for x in values]
    return None


def _signature_disabled(node: ast.Call) -> bool:
    for kw in node.keywords:
        if kw.arg != "options" or not isinstance(kw.value, ast.Dict):
            continue
        for key, value in zip(kw.value.keys, kw.value.values):
            if (isinstance(key, ast.Constant) and key.value == "verify_signature"
                    and isinstance(value, ast.Constant) and value.value is False):
                return True
    return False


def _jwt_sites(filename: str, tree: ast.AST) -> tuple[list[dict[str, Any]], int]:
    module_aliases: set[str] = set()
    decode_imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "jwt":
                    module_aliases.add(alias.asname or "jwt")
        elif isinstance(node, ast.ImportFrom) and node.module == "jwt":
            for alias in node.names:
                if alias.name in {"decode", "decode_complete"}:
                    decode_imports.add(alias.asname or alias.name)

    calls: list[dict[str, Any]] = []
    wrapper_calls = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        target = node.func
        direct = ((isinstance(target, ast.Attribute)
                   and target.attr in {"decode", "decode_complete"}
                   and isinstance(target.value, ast.Name)
                   and target.value.id in module_aliases)
                  or (isinstance(target, ast.Name) and target.id in decode_imports))
        if isinstance(target, ast.Name) and target.id == "verify_jwt":
            wrapper_calls += 1
        if not direct:
            continue
        keyword = next((item.value for item in node.keywords if item.arg == "algorithms"), None)
        literal = _literal_list(keyword) if keyword is not None else None
        unsafe_mixed = bool(literal and
                            set(literal).intersection(HMAC_ALGORITHMS) and
                            set(literal).intersection(ASYMMETRIC_ALGORITHMS))
        calls.append({
            "file": filename, "line": node.lineno,
            "signature_verification_disabled_literal": _signature_disabled(node),
            "literal_mixed_hs_asymmetric_algorithms": unsafe_mixed,
            "algorithms_static_literal": literal is not None,
            "has_expanded_kwargs": any(kw.arg is None for kw in node.keywords),
        })
    return calls, wrapper_calls


def scan_source_blobs(blobs: dict[str, bytes]) -> dict[str, Any]:
    """Only parses syntax of selected candidate blobs; never executes them."""
    hash_stream = hashlib.sha256()
    total = 0
    jwt: list[dict[str, Any]] = []
    xml_import_files: list[str] = []
    ssh_reference_files: list[str] = []
    jwt_wrapper_calls = 0
    python_parse_errors = 0
    for name, data in sorted(blobs.items()):
        if (type(name) is not str or type(data) is not bytes
                or not name.endswith(".py")
                or len(data) > MAX_PY_BYTES):
            raise SourceAuditDenied("invalid_source_file")
        total += len(data)
        if total > MAX_TOTAL_BYTES:
            raise SourceAuditDenied("oversized_upstream_source")
        hash_stream.update(name.encode("utf-8") + b"\0" + hashlib.sha256(data).digest())
        wants_jwt = bool(JWT_TRIGGER.search(data))
        wants_xml = bool(XML_TRIGGER.search(data))
        wants_ssh = bool(SSH_TRIGGER.search(data))
        if not (wants_jwt or wants_xml or wants_ssh):
            continue
        try:
            tree = ast.parse(data, filename="<external>", feature_version=None)
        except (SyntaxError, ValueError, UnicodeError):
            python_parse_errors += 1
            continue
        if wants_jwt:
            cases, wrappers = _jwt_sites(name, tree)
            jwt.extend(cases)
            jwt_wrapper_calls += wrappers
        segments = PurePosixPath(name).parts
        production = not ({"tests", "evals", "examples", "benchmarks"} & set(segments)
                          or PurePosixPath(name).name.startswith("test_"))
        if production and wants_xml:
            imports = [x for x in ast.walk(tree)
                       if isinstance(x, ast.Import)
                       and any(alias.name.split(".")[0] in {"xml", "lxml", "defusedxml", "xmltodict"}
                               for alias in x.names)]
            imports += [x for x in ast.walk(tree)
                        if isinstance(x, ast.ImportFrom)
                        and x.module and x.module.split(".")[0] in {"xml", "lxml", "defusedxml", "xmltodict"}]
            if imports:
                xml_import_files.append(name)
        if production and wants_ssh:
            ssh_reference_files.append(name)
    return {
        "python_files_examined": len(blobs),
        "python_bytes_examined": total,
        "file_content_digest_sha256": hash_stream.hexdigest(),
        "candidate_python_parse_errors": python_parse_errors,
        "jwt_decode_sites": sorted(jwt, key=lambda c: (c["file"], c["line"])),
        "jwt_verify_wrapper_calls": jwt_wrapper_calls,
        "production_xml_import_files": sorted(xml_import_files),
        "production_ssh_text_reference_file_count": len(ssh_reference_files),
        "production_ssh_example_files": sorted(ssh_reference_files)[:15],
        "all_possible_dynamic_calls_proven_absent": False,
        "signed_source_image_provenance_verified": False,
        "native_tool_enforcement_verified": False,
        "resident_agent_allowed": False,
    }


def audit(repo: Path) -> dict[str, Any]:
    repo = repo.resolve(strict=True)
    paths = _verified_git_filenames(repo)
    blobs: dict[str, bytes] = {}
    for name in paths:
        file = repo.joinpath(*PurePosixPath(name).parts)
        if file.is_symlink() or not file.is_file() or not file.resolve().is_relative_to(repo):
            raise SourceAuditDenied("untrusted_tracked_path")
        try:
            blobs[name] = file.read_bytes()
        except OSError:
            raise SourceAuditDenied("unreadable_tracked_python") from None
    result = scan_source_blobs(blobs)
    return {
        "status": "SOURCE_STATIC_REVIEW_ONLY",
        "source_commit": UPSTREAM_COMMIT,
        "image_ref": SOURCE_IMAGE,
        "git_head_and_clean_tracked_worktree_verified": True,
        **result,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="v0.22.2 all tracked Python risk surface inventory")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--source-tree", type=Path)
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"status": "NOT_EXECUTED", "resident_agent_allowed": False}))
        return 0
    if args.source_tree is None:
        print(json.dumps({"status": "INCONCLUSIVE", "resident_agent_allowed": False}))
        return 2
    try:
        result = audit(args.source_tree)
    except (SourceAuditDenied, OSError, ValueError, RecursionError):
        result = {"status": "INCONCLUSIVE", "resident_agent_allowed": False}
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
