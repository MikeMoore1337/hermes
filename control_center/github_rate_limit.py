"""Optional GitHub REST token-scoped rate limits (GET /rate_limit only).

No repos, user profile, issues, requests or private data are collected.
A separate owner-approved read-only credential is necessary for the given
token's quota to mean anything; never reuse a GitHub Actions or OAuth token.
"""
from __future__ import annotations
import datetime as dt
import json
import math
import os
from pathlib import Path
import re
import tempfile
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

OUTPUT = Path("/var/lib/hermes-provider-quota/github-rate-limits.json")
MAX_BYTES = 32768
SCHEMA = 1
SOURCE = "github-rest-rate-limit"
RESOURCES = ("core", "search", "graphql", "integration_manifest",
             "code_search", "actions", "dependency_snapshots")
STATUSES = frozenset({"ok", "auth_required", "throttled", "unknown", "unavailable"})
STALE_AFTER = dt.timedelta(minutes=30)


class GitHubQuotaError(Exception):
    pass


def utc(date):
    if not isinstance(date, dt.datetime) or date.tzinfo is None:
        raise ValueError("timezone")
    return date.astimezone(dt.timezone.utc)


def iso(date):
    return utc(date).isoformat(timespec="seconds").replace("+00:00","Z")


def error(status, now):
    if status not in STATUSES-{"ok"}:
        raise ValueError("status")
    return {"schema":SCHEMA,"source":SOURCE,"status":status,
            "observed_at":iso(now),"scope":"configured_token", "resources":[]}


def parse(body: bytes, *, now: dt.datetime):
    if len(body)>MAX_BYTES:
        raise GitHubQuotaError("response_too_large")
    try: raw=json.loads(body)
    except (UnicodeDecodeError,ValueError) as exc:
        raise GitHubQuotaError("invalid_json") from exc
    if not isinstance(raw,dict) or not isinstance(raw.get("resources"),dict):
        raise GitHubQuotaError("invalid_body")
    resources=[]
    for name in RESOURCES:
        obj=raw["resources"].get(name)
        if not isinstance(obj,dict):
            continue
        limit=obj.get("limit");used=obj.get("used");left=obj.get("remaining")
        reset=obj.get("reset")
        if (any(type(v) is not int for v in (limit,used,left,reset)) or
                limit<0 or used<0 or left<0 or left>limit or
                reset<0 or reset>253402300799):
            raise GitHubQuotaError("invalid_rate_limit")
        # A zero limit from GitHub is a disabled resource, not a usable grant.
        status="unknown" if limit==0 else "exhausted" if left==0 else (
            "low" if left/limit<=.2 else "ok")
        resources.append({
            "resource":name,"quota_limit":limit,"used":used,"remaining":left,
            "reset_at_utc":dt.datetime.fromtimestamp(reset,dt.timezone.utc)
            .isoformat(timespec="seconds").replace("+00:00","Z"),
            "status":status,
        })
    if not resources:
        return error("unknown",now)
    return {"schema":SCHEMA,"source":SOURCE,"status":"ok",
            "observed_at":iso(now),"scope":"configured_token","resources":resources}


def read(token: Path, *, now: dt.datetime|None=None, transport=urlopen):
    when=utc(now or dt.datetime.now(dt.timezone.utc))
    if token.is_symlink() or not token.is_file():
        raise GitHubQuotaError("missing_token")
    st=token.stat()
    if st.st_mode & 0o077 or not 20<=st.st_size<=512:
        raise GitHubQuotaError("token_permissions")
    secret=token.read_text(encoding="ascii").strip()
    if not re.fullmatch(r"[\x21-\x7e]{20,512}",secret):
        raise GitHubQuotaError("invalid_token")
    request=Request("https://api.github.com/rate_limit",headers={
        "Authorization":"Bearer "+secret,
        "Accept":"application/vnd.github+json",
        "User-Agent":"hermes-provider-quota/1",
        "X-GitHub-Api-Version":"2022-11-28",
    },method="GET")
    try:
        with transport(request,timeout=7) as response:
            status=response.status
            body=response.read(MAX_BYTES+1)
    except HTTPError as exc:
        # GitHub returns 403 for either an authorization problem or a
        # PRIMARY/SECONDARY rate limit. Without authoritative headers/body
        # this is ambiguous. Never label it definitely auth_required.
        return error("auth_required" if exc.code==401 else
                     "unknown" if exc.code==403 else
                     "throttled" if exc.code==429 else "unavailable",when)
    except (OSError,URLError,TimeoutError):
        return error("unavailable",when)
    if status!=200:
        return error("auth_required" if status==401 else
                     "unknown" if status==403 else
                     "throttled" if status==429 else "unavailable",when)
    try:return parse(body,now=when)
    except GitHubQuotaError:return error("unknown",when)


def save(value:dict,path:Path=OUTPUT,*,group:str|None=None):
    if not isinstance(value,dict) or set(value)!={"schema","source","status",
            "observed_at","scope","resources"}:
        raise GitHubQuotaError("snapshot")
    if value["schema"]!=SCHEMA or value["source"]!=SOURCE or value["status"] not in STATUSES:
        raise GitHubQuotaError("snapshot")
    if not isinstance(value["resources"],list) or len(value["resources"])>len(RESOURCES):
        raise GitHubQuotaError("resources")
    if path.is_symlink():
        raise GitHubQuotaError("symlink")
    path.parent.mkdir(mode=0o750,parents=True,exist_ok=True)
    target_gid=None
    if group:
        import grp
        target_gid=grp.getgrnam(group).gr_gid
        state=path.parent.lstat()
        # systemd StateDirectory and Group provision ownership *before*
        # sandboxing. A capless collector must never call chown at runtime.
        if (not path.parent.is_dir() or path.parent.is_symlink()
                or state.st_uid!=os.geteuid() or state.st_gid!=target_gid
                or (state.st_mode & 0o777)!=0o750):
            raise GitHubQuotaError("unsafe_state_directory")
    tmp=None
    try:
        with tempfile.NamedTemporaryFile(mode="w",encoding="utf-8",
              dir=path.parent,prefix=".gh-quota-",delete=False) as out:
            tmp=Path(out.name)
            json.dump(value,out,separators=(",",":"))
            out.write("\n");out.flush()
            os.fchmod(out.fileno(),0o640)
            if target_gid is not None:
                owner=os.fstat(out.fileno())
                if owner.st_uid!=os.geteuid() or owner.st_gid!=target_gid:
                    raise GitHubQuotaError("unsafe_snapshot_group")
            os.fsync(out.fileno())
        os.replace(tmp,path)
    finally:
        if tmp is not None:tmp.unlink(missing_ok=True)


def snapshot(path:Path=OUTPUT,*,now:dt.datetime|None=None):
    current=utc(now or dt.datetime.now(dt.timezone.utc))
    try:
        # The production quota file is readable only to its owning service.
        # Non-root offline tests and unprivileged callers must fail closed
        # without exposing the file or aborting repository deployment.
        if path.is_symlink() or not path.is_file():
            return error("unknown",current)
        if path.stat().st_size>8192:raise ValueError("oversize")
        raw=json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw,dict) or set(raw)!={"schema","source","status",
                "observed_at","scope","resources"}:
            raise ValueError("fields")
        if raw["schema"]!=1 or raw["source"]!=SOURCE or raw["scope"]!="configured_token":
            raise ValueError("source")
        if raw["status"] not in STATUSES or type(raw["resources"]) is not list:
            raise ValueError("status")
        moment=utc(dt.datetime.fromisoformat(raw["observed_at"].replace("Z","+00:00")))
        if moment-current>dt.timedelta(minutes=2) or current-moment>STALE_AFTER:
            return error("unknown",current)
        if len(raw["resources"])>len(RESOURCES):
            raise ValueError("resources")
        seen=set()
        fresh=[]
        for item in raw["resources"]:
            if not isinstance(item,dict) or set(item)!={"resource","quota_limit","used",
                     "remaining","reset_at_utc","status"}:
                raise ValueError("item")
            name=item["resource"]
            if name not in RESOURCES or name in seen:
                raise ValueError("duplicate")
            seen.add(name)
            for key in ("quota_limit","used","remaining"):
                if type(item[key]) is not int or item[key]<0 or item[key]>1e9:
                    raise ValueError("value")
            if item["remaining"]>item["quota_limit"] or item["status"] not in (
                    "ok","low","exhausted","unknown"):
                raise ValueError("inconsistent")
            reset=utc(dt.datetime.fromisoformat(item["reset_at_utc"].replace("Z","+00:00")))
            # A source can be younger than 30 minutes but its one-minute
            # search/reset window already expired. Never claim an old
            # exhaustion, or a false allowance, after that reset.
            if reset <= current:
                continue
            fresh.append(item)
        if not fresh:
            return error("unknown",current)
        result=dict(raw)
        result["resources"]=fresh
        return result
    except (ValueError,TypeError,KeyError,OSError,OverflowError):
        return error("unknown",current)


def main():
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument("--token-file",type=Path,default=Path(os.environ.get(
        "HERMES_GITHUB_QUOTA_TOKEN_FILE","/etc/hermes/github-rate-limit-read.token")))
    parser.add_argument("--output",type=Path,default=OUTPUT)
    args=parser.parse_args()
    try:
        result=read(args.token_file)
        save(result,args.output,group="hermes-control")
        if result["status"]=="ok":
            try:
                from control_center.github_rate_history import append
                append(result,group="hermes-control")
            except (OSError,ValueError):
                print("GITHUB_QUOTA_HISTORY=unavailable")
        print("GITHUB_QUOTA_READ="+result["status"])
        return 0 if result["status"]=="ok" else 1
    except (OSError,GitHubQuotaError,ValueError):
        print("GITHUB_QUOTA_READ=unavailable")
        return 1


if __name__=="__main__":
    raise SystemExit(main())
