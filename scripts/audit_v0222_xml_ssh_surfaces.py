"""H-18: pinned, source-only XML/SSH CVE reachability signals, never GO."""
from __future__ import annotations
import argparse
import ast
import hashlib
import json
from pathlib import Path
from scripts.audit_v0222_python_surface import _verified_git_filenames, SourceAuditDenied

TARGETS = (
    "plugins/platforms/wecom/wecom_crypto.py",
    "tools/read_extract.py",
    "tools/environments/ssh.py",
    "hermes_cli/setup_terminal.py",
)
MAX_SIZE = 1_000_000
FORBIDDEN = {"lxml", "libxml2", "xmlsec", "defusedxml"}
ALLOWED_XML = {"xml.etree", "xml.etree.ElementTree"}
class ScopeDenied(ValueError):
    pass

def inspect_bytes(files: dict[str,bytes]) -> dict:
    if set(files) != set(TARGETS):
        raise ScopeDenied("exact_scope_required")
    signal = {}
    for name in TARGETS:
        raw=files[name]
        if type(raw) is not bytes or not 0<len(raw)<=MAX_SIZE:
            raise ScopeDenied("invalid_source_bytes")
        try:
            tree=ast.parse(raw.decode("utf-8-sig"),filename="<untrusted-source>")
        except (SyntaxError,UnicodeError,ValueError,RecursionError):
            raise ScopeDenied("invalid_syntax") from None
        imports=set()
        process_calls=[]
        xml_calls=[]
        for node in ast.walk(tree):
            if isinstance(node,ast.Import):
                imports.update(alias.name for alias in node.names)
            elif isinstance(node,ast.ImportFrom) and node.module:
                imports.add(node.module)
            elif isinstance(node,ast.Call):
                fn=node.func
                if isinstance(fn,ast.Attribute) and isinstance(fn.value,ast.Name):
                    if fn.value.id=="subprocess" and fn.attr in ("run","Popen","call","check_output"):
                        process_calls.append(node.lineno)
                    if fn.value.id=="ET" and fn.attr in ("fromstring","parse","XMLParser"):
                        xml_calls.append(node.lineno)
        signal[name]={
            "sha256":hashlib.sha256(raw).hexdigest(),
            "xml_stdlib_etree_import":bool(imports & ALLOWED_XML),
            "non_stdlib_xml_import_observed":any(v.split(".")[0] in FORBIDDEN for v in imports),
            "etree_parse_call_lines":sorted(xml_calls),
            "subprocess_call_lines":sorted(process_calls),
            "ssh_backend_path":name=="tools/environments/ssh.py",
            "requires_runtime_reachability_review":True,
        }
    return {
        "schema":"hermes-h18-xml-ssh-static-v1",
        "status":"P0_REVIEW_REQUIRED",
        "source_files_verified":len(TARGETS),
        "paths":signal,
        "absence_of_libxml2_runtime_dependency_proven":False,
        "ssh_egress_denied_at_os_layer_proven":False,
        "dynamic_dispatch_covered":False,
        "compiled_and_vendor_code_covered":False,
        "resident_agent_allowed":False,
    }

def inspect_tree(root:Path)->dict:
    paths=set(_verified_git_filenames(root))
    if not set(TARGETS)<=paths:
        raise ScopeDenied("missing_tracked_targets")
    blobs={}
    for name in TARGETS:
        path=root.joinpath(*name.split("/"))
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root.resolve()):
            raise ScopeDenied("unsafe_target")
        if path.stat().st_size>MAX_SIZE:
            raise ScopeDenied("oversized_target")
        blobs[name]=path.read_bytes()
    return inspect_bytes(blobs)

def main(argv=None)->int:
    ap=argparse.ArgumentParser()
    ap.add_argument("--execute",action="store_true")
    ap.add_argument("--source-tree",type=Path)
    args=ap.parse_args(argv)
    if not args.execute:
        print(json.dumps({"status":"NOT_EXECUTED","resident_agent_allowed":False}))
        return 0
    try:
        if args.source_tree is None: raise ScopeDenied("missing_source")
        result=inspect_tree(args.source_tree)
    except (ScopeDenied,SourceAuditDenied,OSError,ValueError,RecursionError):
        result={"status":"INCONCLUSIVE","resident_agent_allowed":False}
    print(json.dumps(result,sort_keys=True))
    return 2

if __name__=="__main__":
    raise SystemExit(main())
