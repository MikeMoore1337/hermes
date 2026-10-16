"""Offline, fail-closed static review of exact upstream Hermes v0.22.2 JWT sites.

Requires locally supplied upstream source files matching their Git object IDs.
No imports, execution of upstream code, model calls, network, Docker, or writes.
A passing static source observation NEVER permits a resident Hermes agent.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
from pathlib import Path
from typing import Any

UPSTREAM_COMMIT = "d923a5eb487a17c0a68801bba9ef0f56c81040a8"
IMAGE = ("nousresearch/hermes-agent@sha256:"
         "a11574b7fe8e1631d7d88d556677dac693bc058abf558cdeb899155688c1bf05")
FILE_GIT_BLOB_IDS = {
    "plugins/cron_providers/chronos/verify.py": "2503f4a1a8cd21ad28bc1717c2f92494186103d6",
    "plugins/dashboard_auth/_shared.py": "e12fb5896c51096589b25172468d413ce22eef5d",
    "plugins/dashboard_auth/nous/__init__.py": "66723b5a75e481d6f5936a354245c1beef639915",
    "plugins/dashboard_auth/self_hosted/__init__.py": "f65a24ec34882687bc6558410f882c2d4479fb3e",
    "pyproject.toml": "5145f275d14a0ab119802821c715a33123b15551",
}
HS = frozenset({"HS256", "HS384", "HS512"})
AS = frozenset({"RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
                "ES256", "ES384", "ES512", "EdDSA"})
MAX_BYTES = 150_000


class AuditDenied(ValueError):
    """Fixed diagnostics only; do not log raw files, paths or secrets."""


def git_blob_id(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def _read_exact(root: Path, name: str, expected_sha: str) -> str:
    path = root / name
    # Non-follow symlinks at every hop to prevent private-data reads.
    if root.is_symlink() or any(p.is_symlink() for p in (path, *path.parents)
                                if p != root.anchor and p != Path(".")):
        raise AuditDenied("symlink_denied")
    if not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise AuditDenied("missing_or_oversized_source")
    data = path.read_bytes()
    if not data or len(data) > MAX_BYTES or git_blob_id(data) != expected_sha:
        raise AuditDenied("upstream_blob_mismatch")
    try:
        return data.decode("utf-8-sig")
    except UnicodeError:
        raise AuditDenied("invalid_encoding") from None


def _func(tree: ast.Module, name: str) -> ast.FunctionDef:
    matching = [node for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name == name]
    if len(matching) != 1:
        raise AuditDenied("unexpected_source_structure")
    return matching[0]


def _algorithms_literal(value: ast.AST, *, constants: dict[str, tuple[str, ...]]
                        ) -> tuple[str, ...]:
    if isinstance(value, (ast.Tuple, ast.List)):
        vals = value.elts
    elif (isinstance(value, ast.Call) and isinstance(value.func, ast.Name)
          and value.func.id == "list" and len(value.args) == 1
          and not value.keywords and isinstance(value.args[0], ast.Name)):
        return constants.get(value.args[0].id) or ()
    else:
        return ()
    if not vals or any(not isinstance(v, ast.Constant) or type(v.value) is not str
                       for v in vals):
        return ()
    return tuple(v.value for v in vals)


def _call_kwargs(node: ast.Call) -> dict[str, ast.AST]:
    if any(k.arg is None for k in node.keywords):
        raise AuditDenied("unverifiable_keyword_expansion")
    return {k.arg: k.value for k in node.keywords}


def _selected_call(fn: ast.FunctionDef, called: str) -> ast.Call:
    calls = [c for c in ast.walk(fn) if isinstance(c, ast.Call)
             and isinstance(c.func, ast.Name) and c.func.id == called]
    if len(calls) != 1:
        raise AuditDenied("unexpected_jwt_call_count")
    return calls[0]


def _chronos(tree: ast.Module) -> tuple[str, ...]:
    fn = _func(tree, "verify_nas_fire_token")
    calls = [c for c in ast.walk(fn)
             if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)
             and c.func.id == "dict"
             and "algorithms" in {k.arg for k in c.keywords}]
    if len(calls) != 1:
        raise AuditDenied("unexpected_chronos_algo_source")
    algos = _algorithms_literal(_call_kwargs(calls[0])["algorithms"], constants={})
    jwt_decode = [c for c in ast.walk(fn) if isinstance(c, ast.Call)
                  and isinstance(c.func, ast.Attribute)
                  and isinstance(c.func.value, ast.Name)
                  and c.func.value.id == "jwt" and c.func.attr == "decode"]
    if (len(jwt_decode) != 1 or
            not any(k.arg is None and isinstance(k.value, ast.Name)
                    and k.value.id == "decode_kwargs" for k in jwt_decode[0].keywords)
            or not any(isinstance(c, ast.Call)
                       and isinstance(c.func, ast.Attribute)
                       and c.func.attr == "get_signing_key_from_jwt"
                       for c in ast.walk(fn))):
        raise AuditDenied("unexpected_chronos_verification_flow")
    return algos


def _providers(tree: ast.Module, name: str,
               constants: dict[str, tuple[str, ...]]) -> tuple[str, ...]:
    fn = _func(tree, name)
    call = _selected_call(fn, "verify_jwt")
    kw = _call_kwargs(call)
    return _algorithms_literal(kw.get("algorithms"), constants=constants)


def _self_hosted_constant(tree: ast.Module) -> dict[str, tuple[str, ...]]:
    named = {}
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            node = stmt.targets[0]
            if isinstance(node, ast.Name) and node.id == "_ALLOWED_ID_TOKEN_ALGS":
                named[node.id] = _algorithms_literal(stmt.value, constants={})
    if "_ALLOWED_ID_TOKEN_ALGS" not in named:
        raise AuditDenied("self_hosted_algorithms_unknown")
    return named


def _shared_decode_is_jwks_bound(tree: ast.Module) -> bool:
    fn = _func(tree, "verify_jwt")
    decode = [c for c in ast.walk(fn) if isinstance(c, ast.Call)
              and isinstance(c.func, ast.Attribute)
              and isinstance(c.func.value, ast.Name)
              and c.func.value.id == "jwt" and c.func.attr == "decode"]
    # 1 verified jwt.decode + 1 intentionally unverified diagnostic decode.
    if len(decode) != 2:
        raise AuditDenied("unexpected_shared_decode_calls")
    verified = [c for c in decode if any(k.arg == "algorithms" for k in c.keywords)]
    if len(verified) != 1:
        raise AuditDenied("unverifiable_shared_decode")
    kw = _call_kwargs(verified[0])
    a = kw["algorithms"]
    if not isinstance(a, ast.Name) or a.id != "algorithms":
        raise AuditDenied("unverifiable_shared_algorithms")
    if not any(isinstance(c, ast.Call)
               and isinstance(c.func, ast.Attribute)
               and c.func.attr == "get_signing_key_from_jwt"
               for c in ast.walk(fn)):
        raise AuditDenied("unverifiable_shared_jwks")
    return True


def inspect_sources(content: dict[str, str]) -> dict[str, Any]:
    if set(content) != set(FILE_GIT_BLOB_IDS):
        raise AuditDenied("incomplete_source_snapshot")
    try:
        trees = {name: ast.parse(contents, filename="<upstream>")
                 for name, contents in content.items() if name.endswith(".py")}
    except (SyntaxError, ValueError):
        raise AuditDenied("invalid_upstream_python") from None
    parsed = {
        "chronos": _chronos(trees["plugins/cron_providers/chronos/verify.py"]),
        "nous": _providers(trees["plugins/dashboard_auth/nous/__init__.py"],
                           "_claims_for", {}),
        "self_hosted": _providers(
            trees["plugins/dashboard_auth/self_hosted/__init__.py"],
            "_verify_id_token",
            _self_hosted_constant(trees["plugins/dashboard_auth/self_hosted/__init__.py"])),
    }
    _shared_decode_is_jwks_bound(trees["plugins/dashboard_auth/_shared.py"])
    if not re.search(r'["\']PyJWT\[crypto\]==2\.13\.0;', content["pyproject.toml"]):
        raise AuditDenied("pyjwt_pin_not_verified")
    for name, algos in parsed.items():
        if (not algos or len(algos) != len(set(algos))
                or any(a not in (HS | AS) for a in algos)):
            raise AuditDenied("unknown_provider_algorithms")
    mixed = {name: bool(set(algos) & HS and set(algos) & AS)
             for name, algos in parsed.items()}
    return {
        "status": "P0_REVIEW_REQUIRED",
        "source_commit": UPSTREAM_COMMIT,
        "image_digest": IMAGE,
        "source_git_blob_ids_checked": True,
        "image_contains_same_git_source_verified": False,
        "reviewed_jwt_paths": {name: {"algorithms": list(algos),
                                     "mixed_hmac_asymmetric": mixed[name]}
                               for name, algos in parsed.items()},
        "pyjwt_dependency_version": "2.13.0",
        "pyjwt_fixed_version": "2.14.0",
        "pyjwt_risky_configuration_observed_in_reviewed_paths": any(mixed.values()),
        "jwt_all_callsites_exhaustively_reviewed": False,
        "critical_cve_applicability_confirmed": False,
        "source_to_image_provenance_verified": False,
        "production_deployed": False,
        "resident_agent_allowed": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Pinned v0.22.2 offline JWT review")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--source-dir", type=Path)
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"status": "NOT_EXECUTED", "resident_agent_allowed": False}))
        return 0
    if args.source_dir is None:
        print(json.dumps({"status": "INCONCLUSIVE",
                          "reason": "local_snapshot_required",
                          "resident_agent_allowed": False}))
        return 2
    try:
        contents = {name: _read_exact(args.source_dir, name, expected)
                    for name, expected in FILE_GIT_BLOB_IDS.items()}
        report = inspect_sources(contents)
    except (AuditDenied, OSError, RecursionError):
        report = {"status": "INCONCLUSIVE", "reason": "source_verification_failed",
                  "resident_agent_allowed": False}
    print(json.dumps(report, ensure_ascii=True, sort_keys=True))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
