"""H-18: inspect Python JWT callsite syntax in a *supplied* stopped image snapshot.

No Docker, Git, network, upstream import/execution, secrets, CVE exploits or writes.
Exact v0.22.2 Git blob parity for five security-relevant installed files is
necessary but NOT source-to-image provenance or complete package coverage.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import warnings
from pathlib import Path
from typing import Any

ROOTS = ("agent", "hermes_cli", "gateway", "cron", "plugins", "tools", "acp_adapter", "pm")
EXPECTED_BLOBS = {
    "plugins/cron_providers/chronos/verify.py": "2503f4a1a8cd21ad28bc1717c2f92494186103d6",
    "plugins/dashboard_auth/_shared.py": "e12fb5896c51096589b25172468d413ce22eef5d",
    "plugins/dashboard_auth/nous/__init__.py": "66723b5a75e481d6f5936a354245c1beef639915",
    "plugins/dashboard_auth/self_hosted/__init__.py": "f65a24ec34882687bc6558410f882c2d4479fb3e",
    "pyproject.toml": "5145f275d14a0ab119802821c715a33123b15551",
}
COMMIT = "d923a5eb487a17c0a68801bba9ef0f56c81040a8"
IMAGE_DIGEST = "sha256:a11574b7fe8e1631d7d88d556677dac693bc058abf558cdeb899155688c1bf05"
MAX_FILE = 2_000_000
MAX_FILES = 10_000
MAX_TOTAL = 150_000_000
VERDICT = "P0_REVIEW_REQUIRED"


class EvidenceInvalid(ValueError):
    """Static fixed reason codes, never leak untrusted paths or source."""


def _read(path: Path, *, allow_empty: bool = False) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise EvidenceInvalid("missing_or_symlinked_source")
    if path.stat().st_size > MAX_FILE or (not allow_empty and path.stat().st_size == 0):
        raise EvidenceInvalid("source_size_denied")
    content = path.read_bytes()
    if len(content) > MAX_FILE or (not allow_empty and not content):
        raise EvidenceInvalid("source_size_denied")
    return content


def _git_blob(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def _walk(root: Path) -> list[tuple[str, Path]]:
    if root.is_symlink() or not root.is_dir():
        raise EvidenceInvalid("invalid_root")
    paths: list[tuple[str, Path]] = []
    for group in ROOTS:
        directory = root / group
        if directory.is_symlink() or not directory.is_dir():
            raise EvidenceInvalid("missing_or_symlinked_scope")
        for current, dirs, files in os.walk(directory, followlinks=False):
            if any((Path(current) / sub).is_symlink() for sub in dirs):
                raise EvidenceInvalid("symlinked_subtree")
            dirs[:] = [sub for sub in sorted(dirs) if sub not in (
                ".git", "__pycache__", ".venv", "node_modules")]
            for name in sorted(files):
                if not name.endswith(".py"):
                    continue
                p = Path(current) / name
                if p.is_symlink():
                    raise EvidenceInvalid("symlinked_source")
                paths.append((p.relative_to(root).as_posix(), p))
                if len(paths) > MAX_FILES:
                    raise EvidenceInvalid("unbounded_source_count")
    return sorted(paths)


def _name_of_call(node: ast.Call, jwt_aliases: set[str], decode_aliases: set[str]) -> str | None:
    fn = node.func
    if isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name):
        if fn.value.id in jwt_aliases and fn.attr in ("decode", "decode_complete"):
            return fn.attr
    if isinstance(fn, ast.Name) and fn.id in decode_aliases:
        return fn.id
    return None


def _literal(value: ast.AST) -> Any:
    try:
        return ast.literal_eval(value)
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        return None


def _classification(call: ast.Call) -> tuple[str, bool, bool]:
    keywords = {kw.arg: kw.value for kw in call.keywords if kw.arg is not None}
    # PyJWT.decode(jwt, key, algorithms=None, options=None, ...).
    # Positional arguments must be classified too: ignoring them can hide
    # HS/asymmetric mixing or an explicit verify_signature=False.
    opts_node = keywords.get("options", call.args[3] if len(call.args) > 3 else None)
    opts = _literal(opts_node) if opts_node is not None else None
    if type(opts) is dict and opts.get("verify_signature") is False:
        return "UNVERIFIED_DECODE", False, True
    algo_node = keywords.get("algorithms", call.args[2] if len(call.args) > 2 else None)
    algo = _literal(algo_node) if algo_node is not None else None
    literal = type(algo) in (tuple, list) and all(type(v) is str for v in algo)
    mixed = bool(literal and set(algo) & {"HS256", "HS384", "HS512"}
                 and set(algo) & {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256"})
    if mixed:
        return "MIXED_HS_ASYMMETRIC_LITERAL", True, False
    if any(kw.arg is None for kw in call.keywords):
        return "DYNAMIC_KWARGS", False, False
    if not literal:
        return "DYNAMIC_OR_MISSING_ALGORITHMS", False, False
    return "LITERAL_ALGORITHMS_REQUIRE_KEY_REVIEW", False, False


def analyze(root: Path) -> dict:
    if root.is_symlink() or not root.is_dir():
        raise EvidenceInvalid("invalid_root")
    for relative, sha in EXPECTED_BLOBS.items():
        path = root / relative
        if any(parent.is_symlink() for parent in path.parents if parent != root.parent):
            raise EvidenceInvalid("symlinked_source")
        if _git_blob(_read(path)) != sha:
            raise EvidenceInvalid("installed_source_differs_from_exact_tag")
    files = _walk(root)
    if not files:
        raise EvidenceInvalid("missing_python_scope")
    findings = []
    total = 0
    for relative, p in files:
        data = _read(p, allow_empty=True)
        total += len(data)
        if total > MAX_TOTAL:
            raise EvidenceInvalid("unbounded_source_bytes")
        # Parse all files, not just files with 'jwt' text; failures must be visible.
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", SyntaxWarning)
                tree = ast.parse(data.decode("utf-8-sig"), filename="<image-python>")
        except (SyntaxError, UnicodeError, RecursionError, ValueError):
            raise EvidenceInvalid("unparseable_installed_source") from None
        jwt_aliases = {a.asname or "jwt" for node in ast.walk(tree)
                       if isinstance(node, ast.Import) for a in node.names if a.name == "jwt"}
        decode_aliases = {a.asname or a.name for node in ast.walk(tree)
                          if isinstance(node, ast.ImportFrom) and node.module == "jwt"
                          for a in node.names if a.name in ("decode", "decode_complete")}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _name_of_call(node, jwt_aliases, decode_aliases)
            if name is None:
                continue
            cls, mixed, unverified = _classification(node)
            findings.append({
                "relative_path": relative,
                "line": node.lineno,
                "entrypoint": name,
                "review_reason": cls,
                "mixed_algorithms_literal": mixed,
                "verified_signature_disabled_literal": unverified,
            })
    findings.sort(key=lambda f: (f["relative_path"], f["line"]))
    return {
        "schema": "hermes-h18-installed-jwt-survey-v1",
        "status": VERDICT,
        "source_commit_claim": COMMIT,
        "pinned_image_digest_claim": IMAGE_DIGEST,
        "tag_blob_parity_checked": True,
        "tag_blob_checks": len(EXPECTED_BLOBS),
        "first_party_roots_scanned": list(ROOTS),
        "first_party_python_files_parsed": len(files),
        "jwt_decode_callsites_found": len(findings),
        "callsites": findings,
        "non_python_or_outside_scope_covered": False,
        "dynamic_dispatch_fully_analyzed": False,
        "third_party_site_packages_covered": False,
        "binary_source_provenance_verified": False,
        "total_installed_source_provenance_verified": False,
        "runtime_reachability_verified": False,
        "resident_agent_allowed": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline installed Hermes JWT AST scan")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--source-dir", type=Path)
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"status": "NOT_EXECUTED", "resident_agent_allowed": False}))
        return 0
    try:
        if args.source_dir is None:
            raise EvidenceInvalid("missing_source")
        out = analyze(args.source_dir)
    except (EvidenceInvalid, OSError, RecursionError):
        out = {"schema": "hermes-h18-installed-jwt-survey-v1",
               "status": "INCONCLUSIVE", "error_code": "source_evidence_invalid",
               "resident_agent_allowed": False}
    print(json.dumps(out, sort_keys=True))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
