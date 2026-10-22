#!/usr/bin/env python3
"""#454: authenticate and verify the newest reusable source-pinned BRC OCI.

This runs on an explicitly authorized owner host. Never grants Docker to BRC.
Default operation never loads an image or changes the live relay. A prior
candidate is allowed only when its source is a proven ancestor of main and
the entire relevant BRC build/upgrade input scope is unchanged.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
from scripts.h15_brc_offline_image_bundle import verify, BundleDenied
from scripts.h15_brc_upgrade_preflight import admit, UpgradeDenied

REPO="MikeMoore1337/hermes"
WORKFLOW="h15-remote-commander-candidate.yml"
ARTIFACT="h15-brc-relay-offline-oci-amd64"
SHA=re.compile(r"[0-9a-f]{40}\Z")
IMAGE=re.compile(r"sha256:[0-9a-f]{64}\Z")
HASH=re.compile(r"[0-9a-f]{64}\Z")
# All BRC input and release-operator paths: err on the side of refusal.
# We intentionally do not count independent unrelated quality.yml changes
# as alterations of an already built OCI image.
BRC_INPUT_PREFIXES=(
    "deploy/h15/",
    "scripts/h15_",
    "tests/test_h15_",
    "docs/security/h15-brc",
)
BRC_INPUT_EXACT={
    ".github/workflows/h15-remote-commander-candidate.yml",
    "pnpm-lock.yaml", "pnpm-workspace.yaml", "package.json",
    "pyproject.toml", "uv.lock",
}
MAX_UNRELATED_COMMITS=80


class StagingDenied(ValueError):
    pass

def refuse(message):
    raise StagingDenied(message)

def run(*args, cap=3000000):
    if shutil.which("gh") is None:
        refuse("authenticated_github_cli_required")
    try:
        p=subprocess.run(["gh",*args],capture_output=True,text=True,timeout=150)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise StagingDenied("github_cli_unavailable") from exc
    if p.returncode or len(p.stdout)>cap:
        refuse("github_cli_failed")
    return p.stdout

def api(endpoint):
    try:
        obj=json.loads(run("api",endpoint,cap=1000000))
    except ValueError as exc:
        raise StagingDenied("github_api_invalid") from exc
    if not isinstance(obj,dict):
        refuse("github_api_not_object")
    return obj

def is_brc_input(path):
    return (isinstance(path,str) and
            (path in BRC_INPUT_EXACT or
             any(path.startswith(prefix) for prefix in BRC_INPUT_PREFIXES)))

def require_unchanged_brc_inputs(candidate, main):
    """Confirm ancestry and untouched inputs; GitHub compare is the authority."""
    if candidate == main:
        return False
    if not SHA.fullmatch(candidate) or not SHA.fullmatch(main):
        refuse("invalid_lineage_sha")
    result=api(f"repos/{REPO}/compare/{candidate}...{main}")
    merge_base=(result.get("merge_base_commit") or {}).get("sha")
    changes=result.get("files")
    if (result.get("status")!="ahead" or merge_base!=candidate
            or type(result.get("behind_by")) is not int or result["behind_by"]!=0
            or type(result.get("ahead_by")) is not int
            or not 1<=result["ahead_by"]<=MAX_UNRELATED_COMMITS
            or not isinstance(changes,list)
            or len(changes)>=300):
        refuse("unverified_candidate_ancestry_or_truncated_diff")
    for item in changes:
        if not isinstance(item,dict):
            refuse("invalid_compare_file")
        filename=item.get("filename")
        prior=item.get("previous_filename")
        if not isinstance(filename,str) or not filename:
            refuse("invalid_compare_filename")
        if is_brc_input(filename) or (prior is not None and
                                      (not isinstance(prior,str) or is_brc_input(prior))):
            refuse("brc_input_modified_requires_fresh_candidate")
    return True

def discover():
    sha=(api(f"repos/{REPO}/branches/main").get("commit") or {}).get("sha")
    if not isinstance(sha,str) or SHA.fullmatch(sha) is None:
        refuse("main_sha_invalid")
    runs=api(f"repos/{REPO}/actions/workflows/{WORKFLOW}/runs?branch=main&event=push&per_page=60")
    eligible=[r for r in runs.get("workflow_runs",[]) if isinstance(r,dict)
              and isinstance(r.get("head_sha"),str)
              and SHA.fullmatch(r["head_sha"]) is not None
              and r.get("head_branch")=="main"
              and r.get("event")=="push" and r.get("conclusion")=="success"
              and r.get("status")=="completed"
              and r.get("name")=="H-15 pinned Remote Commander candidate (isolated CI only)"
              and type(r.get("id")) is int and r["id"]>0]
    if not eligible:
        refuse("successful_main_candidate_missing")
    selected=max(eligible,key=lambda r:r["id"])
    source_sha=selected["head_sha"]
    lineage_reuse=require_unchanged_brc_inputs(source_sha,sha)
    run_id=selected["id"]
    items=api(f"repos/{REPO}/actions/runs/{run_id}/artifacts")
    matching=[x for x in items.get("artifacts",[]) if isinstance(x,dict)
              and x.get("name")==ARTIFACT and x.get("expired") is False
              and type(x.get("size_in_bytes")) is int
              and 10000000<=x["size_in_bytes"]<=1000000000
              and type(x.get("id")) is int]
    if len(matching)!=1:
        refuse("exact_run_artifact_expired_or_ambiguous")
    log=run("run","view",str(run_id),"--repo",REPO,"--log",cap=16000000)
    def evidence(label,pattern):
        matches=set(re.findall(r"(?:^|\s)"+re.escape(label)+r"=([a-z0-9:]+)(?:\s|$)",log,re.M))
        if len(matches)!=1:
            refuse("ci_log_pin_missing_or_ambiguous")
        value=next(iter(matches))
        if pattern.fullmatch(value) is None:
            refuse("ci_log_pin_invalid")
        return value
    return {"sha":source_sha,"run_id":run_id,"artifact_id":matching[0]["id"],
            "image":evidence("H15_OFFLINE_BUNDLE_IMAGE_ID",IMAGE),
            "archive":evidence("H15_OFFLINE_BUNDLE_ARCHIVE_SHA256",HASH),
            "current_main_sha":sha,"ancestor_candidate_reused":lineage_reuse}

def private(directory):
    if directory.is_symlink() or not directory.is_dir():
        refuse("private_directory_missing")
    info=directory.stat()
    if info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)&0o077:
        refuse("private_directory_permissions")

def stage(directory,entry,load=False):
    private(directory)
    sha,image,archive=entry["sha"],entry["image"],entry["archive"]
    if (not SHA.fullmatch(sha) or not IMAGE.fullmatch(image)
        or not HASH.fullmatch(archive)
        or type(entry["run_id"]) is not int or entry["run_id"]<1):
        refuse("invalid_pinned_candidate")
    target=directory/("main-"+sha)
    if target.is_symlink():
        refuse("unsafe_existing_target")
    reused=target.exists()
    if reused:
        private(target)
        try:
            verify(directory=target,expected_archive_sha=archive,
                   expected_image_id=image,expected_hermes_sha=sha)
        except (BundleDenied,OSError,ValueError) as exc:
            raise StagingDenied("existing_archive_invalid_not_overwritten") from exc
    else:
        temp=Path(tempfile.mkdtemp(prefix=".h454-",dir=directory))
        try:
            os.chmod(temp,0o700)
            run("run","download",str(entry["run_id"]),"--repo",REPO,
                "--name",ARTIFACT,"--dir",str(temp),cap=5000)
            files=list(temp.rglob("*"))
            if (len(files)>24 or any(p.is_symlink() or not p.is_file() for p in files)):
                refuse("unexpected_archive_entries")
            verify(directory=temp,expected_archive_sha=archive,
                   expected_image_id=image,expected_hermes_sha=sha)
            if target.exists() or target.is_symlink():
                refuse("concurrent_staging")
            temp.rename(target)
        except (StagingDenied,BundleDenied,OSError,ValueError) as exc:
            raise StagingDenied("download_or_verification_failed") from exc
        finally:
            if temp.exists():
                shutil.rmtree(temp)
    state="VERIFIED_OFFLINE_ONLY"
    if load:
        if os.geteuid()!=0:
            refuse("root_required_to_load")
        loader=Path(__file__).resolve().parents[1]/"deploy/h15/load-verified-image.sh"
        if loader.is_symlink() or not loader.is_file():
            refuse("immutable_loader_missing")
        try:
            p=subprocess.run(["bash",str(loader),"load",str(target),archive,image,sha],
                             capture_output=True,text=True,timeout=300)
        except (OSError,subprocess.TimeoutExpired) as exc:
            raise StagingDenied("image_load_unavailable") from exc
        if p.returncode or "H15_BRC_IMAGE_OFFLINE_LOAD=PASS" not in p.stdout:
            refuse("image_load_refused")
        try:
            preflight=admit(target,image,archive,sha)
        except (UpgradeDenied,OSError,ValueError) as exc:
            raise StagingDenied("host_relay_preflight_refused_after_safe_load") from exc
        if preflight.get("status")!="PREFLIGHT_PASS":
            refuse("host_relay_preflight_incomplete")
        state="IMAGE_LOADED_PREFLIGHT_PASS_NO_CUTOVER"
    return {"status":state,"source_sha":sha,
            "current_main_sha":entry.get("current_main_sha",sha),
            "ancestor_candidate_reused":entry.get("ancestor_candidate_reused",False),
            "image_id":image,
            "archive_sha256":archive,"run_id":entry["run_id"],
            "artifact_id":entry["artifact_id"],"staging_dir":str(target),
            "reused":reused,"live_relay_changed":False}

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--directory",type=Path,required=True)
    p.add_argument("--load",action="store_true")
    args=p.parse_args(argv)
    try:
        result=stage(args.directory,discover(),args.load)
    except (StagingDenied,OSError,ValueError) as exc:
        print(json.dumps({"status":"REFUSED","reason":str(exc) if isinstance(exc,StagingDenied) else "staging_failed"}))
        return 2
    print(json.dumps(result,sort_keys=True))
    return 0

if __name__=="__main__":
    raise SystemExit(main())
