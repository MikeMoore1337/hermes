#!/usr/bin/env python3
"""#454: owner-host BRC relay live image cutover; no ChatGPT MCP host access."""
from __future__ import annotations
import argparse
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import runpy
import stat
import subprocess
import tempfile
import time
from urllib.request import build_opener, ProxyHandler
from scripts.h15_brc_upgrade_preflight import admit, inspect, current_gate, UpgradeDenied

NAME = "hermes-brc-relay"
CHECKPOINT = "hermes-brc-relay-h454-rollback"
APPROVAL = Path("/etc/hermes-brc-relay/relay-upgrade-approval.json")
LOCK = Path("/run/lock/hermes-brc-relay-upgrade.lock")
SECRETS = Path("/etc/hermes-brc-relay/relay.env")
DB = Path("/var/lib/hermes-brc-relay/relay.sqlite")
BACKUPS = Path("/var/backups/hermes-brc-relay")
HEX64 = re.compile(r"[a-f0-9]{64}\Z")
CONTAINER_ID = HEX64

class CutoverDenied(Exception):
    pass

def demand(ok, reason):
    if not ok:
        raise CutoverDenied(reason)

def approve(doc, new, old, archive, commit):
    demand(isinstance(doc, dict) and set(doc) == {
        "schema", "decision", "scope", "image_id", "previous_image_id",
        "archive_sha256", "hermes_commit"}, "APPROVAL_SCHEMA")
    demand(type(doc["schema"]) is int and doc["schema"] == 1
           and doc["decision"] == "OWNER_APPROVED_LIVE_BRC_RELAY_CUTOVER"
           and doc["scope"] == "EXISTING_PAIRED_DEVICES_NO_HOST_PERMISSION_CHANGE"
           and doc["image_id"] == new and doc["previous_image_id"] == old
           and doc["archive_sha256"] == archive
           and doc["hermes_commit"] == commit, "APPROVAL_SCOPE_OR_PINS")

def private(path, mode, is_dir=False):
    s = path.lstat()
    demand(s.st_uid == 0 and s.st_gid == 0 and stat.S_IMODE(s.st_mode) == mode
           and (stat.S_ISDIR(s.st_mode) if is_dir else stat.S_ISREG(s.st_mode)),
           "UNSAFE_PRIVATE_FILE")

def approval_file(new, old, archive, commit):
    private(APPROVAL.parent, 0o700, True)
    private(APPROVAL, 0o600)
    demand(APPROVAL.stat().st_size <= 4096, "APPROVAL_TOO_LARGE")
    def unique(items):
        obj = {}
        for k, v in items:
            demand(k not in obj, "DUPLICATE_APPROVAL_KEY")
            obj[k] = v
        return obj
    doc = json.loads(APPROVAL.read_text(encoding="utf-8"),
                     object_pairs_hook=unique)
    approve(doc, new, old, archive, commit)

@contextmanager
def lock():
    fd = os.open(LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        s = os.fstat(fd)
        demand(s.st_uid == 0 and stat.S_ISREG(s.st_mode)
               and stat.S_IMODE(s.st_mode) == 0o600, "UNSAFE_LOCK")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise CutoverDenied("ALREADY_RUNNING") from exc
        yield
    finally:
        os.close(fd)

def docker(*args, optional=False, timeout=45):
    try:
        p = subprocess.run(["docker", *args], capture_output=True,
                           text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CutoverDenied("DOCKER_UNAVAILABLE") from exc
    if p.returncode and not optional:
        raise CutoverDenied("DOCKER_COMMAND_FAILED")
    return p.stdout.strip() if p.returncode == 0 else ""

def exists(name):
    return bool(docker("container", "inspect", "--format", "{{.Id}}", name,
                       optional=True))

def check_files():
    private(SECRETS.parent, 0o700, True)
    private(SECRETS, 0o600)
    demand(BACKUPS.is_dir() and not BACKUPS.is_symlink()
           and DB.is_file() and not DB.is_symlink(), "STATE_FILES_UNSAFE")

def snapshot():
    root = Path(__file__).resolve().parents[1]
    backup = runpy.run_path(str(root / "deploy/h15/backup-relay.py"))["backup_sqlite"]
    rehearsal = runpy.run_path(str(root / "deploy/h15/rehearse-restore.py"))["rehearse_restore"]
    filename = backup(DB, BACKUPS)
    with tempfile.TemporaryDirectory(prefix="h454-restoration-", dir=BACKUPS) as directory:
        r = rehearsal(filename, Path(directory))
    demand(r["status"] == "PASS_DISPOSABLE_ONLY" and
           r["live_sqlite_modified"] is False, "RESTORE_REHEARSAL_FAILED")
    return str(filename)

def devices():
    # The internal bridge must never be routed through HTTP(S)_PROXY.
    opener = build_opener(ProxyHandler({}))
    with opener.open("http://172.29.251.2:3000/health", timeout=3) as response:
        body = json.loads(response.read(2048))
        demand(response.status == 200 and body.get("ok") is True
               and type(body.get("devices")) is int
               and 0 <= body["devices"] <= 25, "HEALTH_INVALID")
        return body["devices"]

def healthy(count, tries=60):
    for _ in range(tries):
        try:
            if devices() >= count:
                return True
        except (OSError, ValueError, CutoverDenied):
            pass
        time.sleep(1)
    return False

def run_args(image, user):
    uid, gid = user.split(":")
    return ["run", "-d", "--name", NAME,
        "--label", "com.hermes.scope=h15-brc-owner-relay",
        "--network", "hermes-brc-internal", "--ip", "172.29.251.2",
        "--read-only", "--user", user,
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--memory", "512m", "--cpus", "0.50", "--pids-limit", "80",
        "--restart", "no", "--stop-timeout", "20",
        "--mount", "type=bind,src=/var/lib/hermes-brc-relay,dst=/state",
        "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,uid=" + uid + ",gid=" + gid + ",mode=0700,size=16m",
        "--env-file", str(SECRETS), "-e", "HOST=0.0.0.0", "-e", "PORT=3000",
        "-e", "PUBLIC_URL=https://mcp.mikemoore.top", "-e", "TRUST_PROXY=false", image]

def swap(image, old, baseline):
    before = inspect(["container", "inspect", NAME])
    user = (before.get("Config") or {}).get("User")
    demand(before.get("Image") == old and isinstance(user, str) and
           re.fullmatch(r"[1-9][0-9]*:[1-9][0-9]*", user) is not None, "OLD_RUNTIME_CHANGED")
    demand(not exists(CHECKPOINT), "CHECKPOINT_ALREADY_EXISTS")
    demand(healthy(baseline, tries=1), "OLD_RELAY_UNHEALTHY")
    stopped = renamed = False
    try:
        docker("stop", "--time", "20", NAME, timeout=40)
        stopped = True
        docker("update", "--restart", "no", NAME)
        docker("rename", NAME, CHECKPOINT)
        renamed = True
        cid = docker(*run_args(image, user))
        demand(bool(CONTAINER_ID.fullmatch(cid)), "CANDIDATE_ID_INVALID")
        new = inspect(["container", "inspect", NAME])
        demand(new.get("Image") == image
               and (new.get("Config") or {}).get("User") == user
               and ((new.get("Config") or {}).get("Labels") or {}).get("com.hermes.scope") == "h15-brc-owner-relay",
               "CANDIDATE_RUNTIME_CHANGED")
        demand(healthy(baseline), "CANDIDATE_HEALTH_OR_RECONNECT_FAILED")
        docker("update", "--restart", "unless-stopped", NAME)
        demand(current_gate(inspect(["container", "inspect", NAME]), old) == image,
               "CANDIDATE_SECURITY_CONTRACT_MISMATCH")
        return {"status": "SWITCHED_PENDING_LIVE_CLIENT_E2E", "candidate_image": image,
                "old_image": old, "checkpoint": CHECKPOINT,
                "rollback_container_retained": True, "sqlite_backup_retained": True}
    except (CutoverDenied, UpgradeDenied, OSError, ValueError) as exc:
        if not stopped:
            # docker stop may have succeeded but its reply was lost.
            # Never assume either stopped or running without inspecting.
            try:
                current = inspect(["container", "inspect", NAME])
                demand(current.get("Image") == old and
                       ((current.get("Config") or {}).get("Labels") or {}).get("com.hermes.scope") == "h15-brc-owner-relay",
                       "STOP_RESULT_AMBIGUOUS")
                if ((current.get("State") or {}).get("Running") is False):
                    docker("start", NAME)
                    demand(healthy(baseline, tries=40), "OLD_RELAY_RECONNECT_FAILED")
            except (CutoverDenied, UpgradeDenied, OSError, ValueError) as uncertain:
                raise CutoverDenied("STOP_RESULT_AMBIGUOUS_MANUAL_RECOVERY") from uncertain
            raise CutoverDenied("STOP_FAILED_OR_UNCERTAIN_OLD_RELAY_RETAINED") from exc
        try:
            if not renamed and exists(CHECKPOINT):
                checkpoint = inspect(["container", "inspect", CHECKPOINT])
                demand(checkpoint.get("Image") == old and
                       (checkpoint.get("Config") or {}).get("User") == user and
                       ((checkpoint.get("Config") or {}).get("Labels") or {}).get("com.hermes.scope") == "h15-brc-owner-relay",
                       "FOREIGN_ROLLBACK_CHECKPOINT")
                renamed = True
            if renamed:
                if exists(NAME):
                    other = inspect(["container", "inspect", NAME])
                    demand(other.get("Image") == image and
                           ((other.get("Config") or {}).get("Labels") or {}).get("com.hermes.scope") == "h15-brc-owner-relay",
                           "FOREIGN_NEW_CONTAINER_DO_NOT_REMOVE")
                    docker("rm", "-f", NAME)
                docker("rename", CHECKPOINT, NAME)
            docker("update", "--restart", "unless-stopped", NAME)
            docker("start", NAME)
            demand(healthy(baseline, tries=40), "OLD_RELAY_RECONNECT_FAILED")
        except (CutoverDenied, UpgradeDenied, OSError, ValueError) as rollback_exc:
            raise CutoverDenied("ROLLBACK_INCOMPLETE_MANUAL_DB_RECOVERY_REQUIRED") from rollback_exc
        raise CutoverDenied("SWITCH_FAILED_OLD_RELAY_RESTORED") from exc

def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode", choices=["plan", "cutover"])
    p.add_argument("--bundle-dir", type=Path, required=True)
    p.add_argument("--image", required=True)
    p.add_argument("--archive-sha", required=True)
    p.add_argument("--hermes-sha", required=True)
    p.add_argument("--execute", action="store_true")
    a = p.parse_args(argv)
    try:
        demand(os.geteuid() == 0, "ROOT_REQUIRED")
        demand(a.mode == "plan" or a.execute, "EXPLICIT_EXECUTE_REQUIRED")
        with lock():
            v = admit(a.bundle_dir, a.image, a.archive_sha, a.hermes_sha)
            old = v["current_image"]
            if a.mode == "plan":
                out = {"status": "PLAN_ONLY", "candidate_image": a.image,
                       "previous_image": old, "changed": False}
            else:
                approval_file(a.image, old, a.archive_sha, a.hermes_sha)
                check_files()
                baseline = devices()
                demand(baseline >= 1, "NO_BASELINE_DEVICES")
                snapshot()
                out = swap(a.image, old, baseline)
    except (CutoverDenied, UpgradeDenied, OSError, ValueError, KeyError) as exc:
        print(json.dumps({"status":"REFUSED",
                          "reason":str(exc) if isinstance(exc,CutoverDenied) else type(exc).__name__},
                         sort_keys=True))
        return 2
    print(json.dumps(out, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
