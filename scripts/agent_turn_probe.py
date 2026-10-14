"""Single bounded Cloudflare-only Hermes turn; no raw model or credential logging."""
from __future__ import annotations
import argparse
import json
import os
import pwd
import re
import sqlite3
import stat
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path("/opt/hermes-agent-owner")
STATE = Path("/var/lib/hermes-agent")
IMAGE = "nousresearch/hermes-agent@sha256:32d095e84190ae7266afbb361579e6921f2c633e899f5eacfb88111b9c851a22"
MODEL = "@cf/openai/gpt-oss-20b"
NAME = "hermes-agent-test"
MAX_LOAD_START = 1.10
MAX_LOAD_DURING = 1.30
MAX_DURATION = 130
MAX_TOOL_DURATION = 205


class Rejected(Exception):
    """Safe category, never constructed from an external response."""


def run_command(parts: list[str], limit: int = 10) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(parts, capture_output=True, text=True, timeout=limit, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Rejected("local_command_unavailable") from exc


def ok(*args: str) -> bool:
    return run_command(list(args)).returncode == 0


def preflight() -> None:
    """Protect the news lane and verify exact private-network restrictions."""
    if os.geteuid() != 0:
        raise Rejected("root_required")
    secret = STATE / ".env"
    uid = pwd.getpwnam("hermes-agent").pw_uid
    if (STATE.is_symlink() or secret.is_symlink() or not secret.is_file()
        or stat.S_IMODE(STATE.stat().st_mode) != 0o700
        or stat.S_IMODE(secret.stat().st_mode) != 0o600
        or secret.stat().st_uid != uid):
        raise Rejected("unsafe_agent_credentials")
    if os.getloadavg()[0] > MAX_LOAD_START:
        raise Rejected("host_high_load")
    if not ok("python3", str(ROOT / "scripts/host_capacity.py"),
              "--reserve-mib", "640", "--margin-mib", "256"):
        raise Rejected("resource_guard_denied")
    for timer in ("hermes-discovery.timer", "hermes-ops-watch.timer"):
        if not ok("systemctl", "is-active", "--quiet", timer):
            raise Rejected("existing_timer_inactive")
    if ok("systemctl", "is-active", "--quiet", "hermes-cloudflare-proxy.service"):
        raise Rejected("proxy_already_running")
    if ok("systemctl", "is-enabled", "--quiet", "hermes-cloudflare-proxy.service"):
        raise Rejected("proxy_autoenabled")
    if ok("docker", "inspect", NAME):
        raise Rejected("overlapping_agent")
    network = run_command(["docker", "network", "inspect",
                           "--format", "{{.Internal}}", "hermes-agent-isolated"])
    if network.returncode != 0 or network.stdout.strip().lower() != "true":
        raise Rejected("private_network_missing")
    nft = run_command(["nft", "list", "table", "inet", "hermes_agent_isolation"])
    checks = ('iifname "br-hcf-agent"', "172.29.250.2", "172.29.250.1",
              "18573", "forward", "drop")
    if nft.returncode != 0 or any(item not in nft.stdout for item in checks):
        raise Rejected("firewall_not_verified")


def docker_args(*, tool_test: bool = False) -> list[str]:
    """Allow only private state, todo tools and free Cloudflare model."""
    user = pwd.getpwnam("hermes-agent")
    return [
        "docker", "run", "--rm", "--name", NAME, "--init",
        "--pull=never", "--platform", "linux/amd64",
        "--network", "hermes-agent-isolated", "--ip", "172.29.250.2",
        "--read-only", "--user", f"{user.pw_uid}:{user.pw_gid}",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--pids-limit", "96", "--cpus", "0.30",
        "--memory", "640m", "--memory-swap", "896m",
        "--tmpfs", "/tmp:rw,nosuid,nodev,size=32m",
        "--tmpfs", "/run:rw,nosuid,nodev,size=16m",
        "--mount", f"type=bind,src={STATE},dst=/opt/data",
        "--env-file", str(STATE / ".env"),
        "--env", "HERMES_HOME=/opt/data",
        "--env", "HTTPS_PROXY=http://172.29.250.1:18573",
        "--env", "HTTP_PROXY=http://172.29.250.1:18573",
        "--env", "NO_PROXY=localhost,127.0.0.1",
        "--env", "NO_COLOR=1",
        "--entrypoint", "/opt/hermes/bin/hermes", IMAGE,
        "-z", (
            "Use the todo_list tool to create one completed in-memory task: "
            "id=smoke-1, content=ephemeral diagnostic, status=completed. "
            "Then reply exactly TOOL_OK." if tool_test
            else "Reply exactly with OK. Do not use tools."
        ),
        "--provider", "workers-ai", "-m", MODEL,
        "-t", "todo", "--reasoning", "low",
    ]


def summarize(raw: str, rc: int, cause: str | None, elapsed: float, *,
              tool_test: bool = False, todo_delta: int = 0) -> dict:
    """Never echo raw inference, bearer keys, user content or account numbers."""
    flags = {
        "auth": bool(re.search(r"\b401\b|invalid.api.key|authentication", raw, re.I)),
        "quota": bool(re.search(r"\b429\b|quota.exceeded", raw, re.I)),
        "http_400": bool(re.search(r"\b400\b", raw)),
        "pm_lock": bool(re.search(r"\.install\.lock|pm repair|dependency.lock", raw, re.I)),
        "network": bool(re.search(r"proxy.error|connect.error|network.unreachable", raw, re.I)),
    }
    expected = "TOOL_OK" if tool_test else "OK"
    success = (rc == 0 and raw.strip() == expected and cause is None
               and (not tool_test or todo_delta > 0))
    return {
        "status": "pass" if success else "stopped" if cause else "incomplete",
        "reason": cause, "exit_code": rc, "seconds": round(elapsed, 1),
        "signals": flags, "lines": len(raw.splitlines()),
        "todo_tool_calls_verified": todo_delta if tool_test else None,
    }


def _count_todo_tool_events(path: Path = STATE / 'state.db') -> int:
    """Count persisted todo tool call/result rows, never read message content."""
    if path.is_symlink() or not path.is_file():
        raise Rejected('session_db_unavailable')
    try:
        with sqlite3.connect(f'file:{path}?mode=ro', uri=True, timeout=2) as db:
            row = db.execute(
                "SELECT count(*) FROM messages WHERE active=1 AND ("
                "(role='tool' AND tool_name='todo_list') OR "
                "(role='assistant' AND tool_calls LIKE '%todo_list%'))"
            ).fetchone()
            return int(row[0])
    except sqlite3.Error as exc:
        raise Rejected('session_db_unavailable') from exc


def guarded_turn(*, tool_test: bool = False) -> dict:
    preflight()
    prior_tool_events = _count_todo_tool_events() if tool_test else 0
    started = False
    process: subprocess.Popen | None = None
    start = time.monotonic()
    try:
        if not ok("systemctl", "start", "hermes-cloudflare-proxy.service"):
            raise Rejected("proxy_start_failed")
        started = True
        if not ok("systemctl", "is-active", "--quiet", "hermes-cloudflare-proxy.service"):
            raise Rejected("proxy_unhealthy")
        if os.getloadavg()[0] > MAX_LOAD_START:
            raise Rejected("host_high_load")
        with tempfile.TemporaryFile(mode="w+b", dir="/run") as logfile:
            process = subprocess.Popen(docker_args(tool_test=tool_test), stdout=logfile,
                                       stderr=subprocess.STDOUT, close_fds=True)
            reason = None
            while process.poll() is None:
                if os.getloadavg()[0] > MAX_LOAD_DURING:
                    reason = "news_load_pressure"
                    break
                if time.monotonic() - start >= (MAX_TOOL_DURATION if tool_test else MAX_DURATION):
                    reason = "time_budget"
                    break
                time.sleep(2)
            if reason:
                run_command(["docker", "rm", "-f", NAME])
            try:
                rc = process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
                rc, reason = -9, reason or "time_budget"
            logfile.seek(0)
            raw = logfile.read(65536).decode("utf-8", errors="replace")
            delta = max(0, _count_todo_tool_events() - prior_tool_events) if tool_test else 0
            return summarize(raw, rc, reason, time.monotonic() - start,
                             tool_test=tool_test, todo_delta=delta)
    finally:
        if process is not None and process.poll() is None:
            run_command(["docker", "rm", "-f", NAME])
            process.kill()
            process.wait(timeout=5)
        if started:
            run_command(["systemctl", "stop", "hermes-cloudflare-proxy.service"])


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--execute", action="store_true", help="Run one real Workers Free turn")
    p.add_argument("--tool-test", action="store_true", help="Use a single in-memory todo tool")
    args = p.parse_args()
    if not args.execute:
        print(json.dumps({"status": "not_executed"}))
        return 0
    try:
        result = guarded_turn(tool_test=args.tool_test)
    except Rejected as exc:
        result = {"status": "rejected", "reason": str(exc)}
    except (OSError, ValueError, subprocess.TimeoutExpired):
        result = {"status": "rejected", "reason": "unexpected_local_failure"}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
