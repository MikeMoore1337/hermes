"""H-01 #33: bounded, event-driven Hermes v0.22.2 Ops agent on the existing VPS.

The only autonomous capability is analysis of validated local Ops Watch codes.
No arbitrary terminal, browser, MCP, tool calls, publishing or remediation.
One eligible event per UTC day at most; reservations are durable before Docker.
"""
from __future__ import annotations

import fcntl
import json
import os
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from ops_watch.advisor_adapter import AdvisorAdapterError, read_events
from ops_watch.incident_advisor import (
    AdvisorInputError, AdvisorOutputError, build_prompt, evaluate_result,
    prepare_context, validate_result,
)
from scripts.bounded_subprocess import BoundedProcessError, run_bounded
from scripts.host_capacity import read_host_facts

ROOT = Path("/opt/hermes-agent-owner")
OPS_DATA = Path("/var/lib/hermes-agent/ops-watch")
AGENT_ENV = Path("/var/lib/hermes-agent/.env")
STATE = Path("/var/lib/hermes-h01")
CONFIG = Path("/etc/hermes-agent/h01-image.env")
MODEL = "@cf/openai/gpt-oss-20b"
EXPECTED_BASE = "d923a5eb487a17c0a68801bba9ef0f56c81040a8"
IMAGE_PATTERN = re.compile(r"HERMES_AGENT_RUNTIME_IMAGE=(sha256:[a-f0-9]{64})\Z")
MAX_DURATION_SECONDS = 205
MAX_CALLS_PER_UTC_DAY = 1
MAX_LOAD1 = 1.30
MIN_AVAILABLE_MIB = 1664
MAX_SWAP_MIB = 1024
MIN_DISK_MIB = 5120
REQUIRED_UNITS = (
    "hermes-control-center.service", "hermes-discovery.timer",
    "hermes-ops-watch.timer", "hermes-cloudflare-network-guard.service",
    "hermes-cloudflare-proxy.service",
)
CLI_CONFIG = """model:
  provider: workers-ai
  default: "@cf/openai/gpt-oss-20b"
agent:
  max_turns: 1
  api_max_retries: 1
  auto_recovery_cycles: 0
  reasoning_effort: low
  disabled_toolsets:
    - hermes-cli
auxiliary:
  title_generation:
    enabled: false
memory:
  memory_enabled: false
  user_profile_enabled: false
"""


class H01Denied(ValueError):
    """Sanitized operational refusal."""


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def safe_image(path: Path = CONFIG) -> str:
    if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise H01Denied("image_config_unavailable")
    match = IMAGE_PATTERN.fullmatch(path.read_text(encoding="ascii").strip())
    if not match:
        raise H01Denied("image_pin_invalid")
    image = match.group(1)
    try:
        proc = subprocess.run(
            ["docker", "image", "inspect", image, "--format",
             '{{.Id}}|{{.Architecture}}|{{index .Config.Labels "hermes.base.commit"}}|'
             '{{index .Config.Labels "hermes.native.tool.policy"}}'],
            capture_output=True, timeout=8, check=False, text=True,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise H01Denied("image_inspection_failed") from None
    if proc.returncode or proc.stdout.strip() != (
        f"{image}|amd64|{EXPECTED_BASE}|bounded-v0222"
    ):
        raise H01Denied("patched_image_not_verified")
    return image


def verify_host() -> None:
    if sys.platform != "linux" or os.geteuid() != 0:
        raise H01Denied("linux_root_required")
    try:
        facts = read_host_facts(Path("/var/lib/hermes"))
        if facts.load1 > MAX_LOAD1:
            raise H01Denied("load_above_operating_limit")
        if facts.news_phase_active:
            raise H01Denied("news_job_active")
        if facts.available_mib < MIN_AVAILABLE_MIB or facts.swap_used_mib > MAX_SWAP_MIB:
            raise H01Denied("insufficient_memory_headroom")
        if facts.disk_free_mib < MIN_DISK_MIB:
            raise H01Denied("insufficient_disk_headroom")
        for name in REQUIRED_UNITS:
            if subprocess.run(
                ["systemctl", "is-active", "--quiet", name],
                timeout=3, check=False, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            ).returncode:
                raise H01Denied("required_service_unavailable")
        guard = subprocess.run(
            [sys.executable, str(ROOT / "scripts/ensure_cloudflare_egress.py"), "--check"],
            timeout=18, check=False, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if guard.returncode:
            raise H01Denied("network_guard_unverified")
    except (OSError, subprocess.TimeoutExpired, KeyError, ValueError) as exc:
        if isinstance(exc, H01Denied):
            raise
        raise H01Denied("host_preflight_unavailable") from None


def verify_credentials() -> None:
    if AGENT_ENV.is_symlink() or not AGENT_ENV.is_file():
        raise H01Denied("credentials_missing")
    details = AGENT_ENV.stat()
    if stat.S_IMODE(details.st_mode) != 0o600 or details.st_uid != pwd.getpwnam("hermes-agent").pw_uid:
        raise H01Denied("credentials_permissions")


def stage_fixture(path: Path) -> None:
    """Stage ONLY allowlisted static code/config, never tokens or production state."""
    plugin_source = ROOT / "plugins/cloudflare-workers-ai-free"
    dest = path / "plugins/cloudflare-workers-ai-free"
    dest.mkdir(parents=True)
    for name in ("__init__.py", "plugin.yaml", "LICENSE"):
        src = plugin_source / name
        if src.is_symlink() or not src.is_file() or src.stat().st_size > 64_000:
            raise H01Denied("provider_plugin_missing")
        (dest / name).write_bytes(src.read_bytes())
        (dest / name).chmod(0o644)
    (path / "config.yaml").write_text(CLI_CONFIG, encoding="utf-8")
    (path / "config.yaml").chmod(0o644)
    path.chmod(0o755)


def docker_command(path: Path, image: str, prompt: str) -> list[str]:
    home_script = (
        "mkdir -p /tmp/hermes-home/plugins && "
        "cp /opt/hermes-input/config.yaml /tmp/hermes-home/config.yaml && "
        "cp -r /opt/hermes-input/plugins/cloudflare-workers-ai-free "
        "/tmp/hermes-home/plugins/ && "
        "export HERMES_HOME=/tmp/hermes-home HOME=/tmp/hermes-home && "
        "exec /opt/hermes/.venv/bin/hermes --ignore-rules --in /tmp/hermes-home "
        "-z \"$1\" --provider workers-ai -m @cf/openai/gpt-oss-20b "
        "--reasoning low -t bot_room"
    )
    uid = pwd.getpwnam("hermes-agent")
    return [
        "docker", "run", "--rm", "--init", "--name", "hermes-h01-ops-model",
        "--pull=never", "--platform", "linux/amd64",
        "--network", "hermes-agent-isolated", "--ip", "172.29.250.2",
        "--read-only", "--user", f"{uid.pw_uid}:{uid.pw_gid}",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--pids-limit", "96", "--cpus", "0.30", "--memory", "640m",
        "--memory-swap", "896m",
        "--tmpfs", "/tmp:rw,nosuid,nodev,size=48m",
        "--tmpfs", "/run:rw,nosuid,nodev,size=8m",
        "--mount", f"type=bind,src={path.resolve()},dst=/opt/hermes-input,readonly",
        "--env-file", str(AGENT_ENV),
        "--env", "HTTPS_PROXY=http://172.29.250.1:18573",
        "--env", "HTTP_PROXY=http://172.29.250.1:18573",
        "--env", "NO_PROXY=localhost,127.0.0.1",
        "--entrypoint", "/bin/sh", image,
        "-c", home_script, "hermes-h01-ops", prompt,
    ]


def model_once(image: str, context: dict[str, object]) -> dict[str, object]:
    prompt = build_prompt(context)
    try:
        with tempfile.TemporaryDirectory(prefix="fixture-", dir=STATE) as raw:
            path = Path(raw)
            stage_fixture(path)
            proc = run_bounded(
                docker_command(path, image, prompt),
                timeout=MAX_DURATION_SECONDS,
                stdout_limit=64 * 1024, stderr_limit=16 * 1024,
            )
        if proc.returncode:
            raise H01Denied("agent_process_nonzero")
        raw_answer = proc.stdout.decode("utf-8", "strict").strip()
        result = validate_result(raw_answer, context)
        return {"status": "PASS", "result": result,
                "quality": evaluate_result(context, result)["deterministic_quality"]}
    except (OSError, UnicodeError, AdvisorInputError, AdvisorOutputError, BoundedProcessError) as exc:
        # Never leak provider details or model output into the journal.
        raise H01Denied("agent_result_unverified") from None


def _read_state(path: Path) -> dict[str, object]:
    if not path.exists():
        return {"utc_date": "", "calls": 0, "last_event_id": 0, "last_status": "NEW"}
    if path.is_symlink() or path.stat().st_size > 8192:
        raise H01Denied("invalid_prior_state")
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        raise H01Denied("invalid_prior_state") from None
    if (type(doc) is not dict or
            set(doc) != {"utc_date", "calls", "last_event_id", "last_status"} or
            type(doc["utc_date"]) is not str or type(doc["calls"]) is not int or
            not 0 <= doc["calls"] <= MAX_CALLS_PER_UTC_DAY or
            type(doc["last_event_id"]) is not int or doc["last_event_id"] < 0 or
            type(doc["last_status"]) is not str or len(doc["last_status"]) > 80):
        raise H01Denied("invalid_prior_state")
    return doc


def _write_state(path: Path, data: dict[str, object]) -> None:
    fd, name = tempfile.mkstemp(prefix=".h01-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, 0o600)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def run() -> dict[str, object]:
    verify_host()
    verify_credentials()
    image = safe_image()
    if STATE.is_symlink():
        raise H01Denied("unsafe_state_directory")
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    if stat.S_IMODE(STATE.stat().st_mode) != 0o700:
        raise H01Denied("unsafe_state_permissions")
    with (STATE / "run.lock").open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        path = STATE / "state.json"
        previous = _read_state(path)
        day = datetime.now(UTC).date().isoformat()
        if previous["utc_date"] != day:
            previous["utc_date"], previous["calls"] = day, 0
        rows = read_events(OPS_DATA, provenance="readonly_snapshot")
        candidates = [
            row for row in rows if row["analysis"]["decision"] == "ADVISOR_CANDIDATE"
        ]
        if not candidates:
            return {"status": "NO_ADVISOR_CANDIDATE", "calls_today": previous["calls"]}
        item = max(candidates, key=lambda row: row["event_id"])
        event_id = item["event_id"]
        if event_id <= previous["last_event_id"]:
            return {"status": "EVENT_ALREADY_HANDLED", "event_id": event_id}
        if previous["calls"] >= MAX_CALLS_PER_UTC_DAY:
            return {"status": "DAILY_CALL_LIMIT_REACHED", "event_id": event_id}
        context = prepare_context(item["event"])
        # Write-ahead reservation: never retry a failed, interrupted or 429 turn.
        previous["calls"] += 1
        previous["last_event_id"] = event_id
        previous["last_status"] = "RESERVED_NO_RETRY"
        _write_state(path, previous)
        try:
            result = model_once(image, context)
            previous["last_status"] = result["status"]
            return {
                "status": result["status"], "event_id": event_id,
                "calls_today": previous["calls"],
                "quality": result["quality"],
                "result": result["result"],
            }
        except H01Denied as exc:
            previous["last_status"] = str(exc)
            raise
        finally:
            _write_state(path, previous)


def main() -> int:
    try:
        record = run()
        passed = record["status"] in {"PASS", "NO_ADVISOR_CANDIDATE", "EVENT_ALREADY_HANDLED", "DAILY_CALL_LIMIT_REACHED"}
    except (H01Denied, AdvisorAdapterError, AdvisorInputError, OSError, BlockingIOError) as exc:
        reason = str(exc) if isinstance(exc, H01Denied) else "source_or_lock_unavailable"
        transient = reason in {"load_above_operating_limit", "news_job_active", "insufficient_memory_headroom", "insufficient_disk_headroom", "required_service_unavailable", "network_guard_unverified"}
        record = {"status": "SKIPPED_PRECHECK" if transient else "BLOCKED", "reason": reason}
        passed = transient
    # Validated, sanitized JSON only. Never log credentials, raw model text or HTTP bodies.
    print(json.dumps({"observed_at": utc_now(), **record}, ensure_ascii=False, sort_keys=True))
    return 0 if passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
