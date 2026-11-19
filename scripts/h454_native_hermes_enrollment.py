#!/usr/bin/env python3
"""H454: original Hermes VPS owner-bound native READ enrollment, OFF by default.

PLAN is read-only. ENROLL requires separate owner authorization and two real
root-TTY challenges. It uses an ephemeral unprivileged Docker exec to POST to
the existing BRC relay over its OWN loopback, with no published port, proxy,
SSH credential, new MCP listener, or token/code in argv, logs or GitHub.
The relay alone issues a bearer after the exact owner-bound SQLite approval.
An interrupted transaction is never retried or silently cleaned up.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import pwd
import re
import socket
import sqlite3
import stat
import subprocess
import sys
import tarfile
import time

from device_fabric.native_brc_enrollment import (
    NAME, IDENTITY, TOKEN, start as native_start, poll as native_poll,
)
from device_fabric.native_install_preview import parse_candidate
from scripts.h454_native_linux_runtime import SCHEMA as CONFIG_SCHEMA, _parse_config
from scripts.h454_native_owner_pair import (
    approve as approve_owner, pending as pending_owner,
)
from scripts.h15_brc_owner_private_pair import (
    DB, host_db_preflight,
)

RELEASE = "30db4fbab46626985b078d574dbe0b839872840e"
OWNER_SOURCE = "82a51cc0d718e16e6d0be8869436359a06fc94b7"
RELAY = "c10587c6bdb51bcbdd4ccea65d5020a6a18deefaa13fb9f9d04eca4661b848d0"
RELAY_IMAGE = "sha256:3488e1ff44bb0843ecbc62a1951277ccbf118d1f3ba899b7636a66aa84d55e06"
WSS = "196e5eb6760addf709377d4f9560515fadbb2d074a3df80d99878d8935df23bb"
WSS_IMAGE = "sha256:6e5f74ae35d38713ba8cd4c7b7167eb92f57a2ea439c91b4c29d5aa8b7f2a589"
IP = "172.29.251.2"
NETWORK = "hermes-brc-internal"
# Existing H15 Hermes VPS sandbox is a separate, already approved BRC client.
# Admission is confined to this exact image and bridge endpoint, not a label
# or a broadly trusted network CIDR. Unknown peers still fail closed.
H15_PEER_NAME = "/hermes-h15-hermes-agent"
H15_PEER_SCOPE = "h15-permanent-hermes-v1"
H15_PEER_IMAGE = "sha256:1d5b144c8b145dd18dca58e13eaefadc06b615c20c278d3be06ba44d8da0db11"
H15_PEER_IP = "172.29.251.3"
H15_PEER_CIDR = H15_PEER_IP + "/28"
SERVICE = "hermes-commander-native"
STATE = Path("/var/lib/hermes-commander-native")
UNIT = Path("/etc/systemd/system/hermes-commander-native.service")
TRUST = Path("/opt/hermes-commander-native/trust")
PINS = Path("/var/lib/hermes-h454-wss-sidecar/pins.json")
SOURCE = Path("/opt/hermes-agent-owner/releases/main-" + OWNER_SOURCE)
NATIVE = Path("/opt/hermes-commander-native/releases/main-" + RELEASE)
TMP_NAME = ".h454-hermes-enrollment.pending"
MAX_CONFIG = 8192
SOURCE_BLOBS = {
    "device_fabric/native_brc_enrollment.py": "6f17835d5a67869e2fdc1dbcbcb2bc373b0372ec",
    "device_fabric/native_install_preview.py": "72b1e8661bb170db81412203f29deea40fddf56e",
    "scripts/h454_native_linux_runtime.py": "b6e4383e8746d473fda745e351b02323c2bfb8b2",
    "scripts/h454_native_owner_pair.py": "dce81b9f97dc03e71ec1a5f7ad1cfddc9bc57423",
    "scripts/h15_brc_owner_private_pair.py": "a3e7a154c9e2fba4e21c3c5b900e50eed12a87d5",
}


class EnrollmentHold(ValueError):
    """Fixed error only; no token, code, device ID, path or raw HTTP body."""


class PlanStageHold(EnrollmentHold):
    """Expose only the fixed failing read-only gate, never the exception."""

    ALLOWED = frozenset({"SOURCE", "SERVICE", "RUNTIME", "COMPILED_BRC"})

    def __init__(self, stage: str):
        if stage not in self.ALLOWED:
            raise EnrollmentHold("INVALID_PLAN_STAGE")
        self.stage = stage
        super().__init__("NATIVE_READ_ONLY_STAGE_HOLD")


def gate(value: bool, code: str) -> None:
    if not value:
        raise EnrollmentHold(code)


def _blob(raw: bytes) -> str:
    return hashlib.sha1(
        b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw
    ).hexdigest()


def canonical(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _absent(parent: Path, name: str) -> bool:
    try:
        (parent / name).lstat()
    except FileNotFoundError:
        return True
    except OSError:
        raise EnrollmentHold("NATIVE_CONFIG_PATH_UNVERIFIABLE") from None
    return False


def _dir(path: Path, *, owner: int, mode: int) -> None:
    gate(path.is_absolute(), "INVALID_DIRECTORY")
    entry = path.lstat()
    gate(stat.S_ISDIR(entry.st_mode) and entry.st_uid == owner
         and stat.S_IMODE(entry.st_mode) == mode,
         "UNSAFE_DIRECTORY")
    for parent in path.parents:
        info = parent.lstat()
        gate(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
             and not info.st_mode & 0o022, "UNSAFE_PARENT")


def _read(path: Path, *, owner: int, modes: tuple[int, ...],
          maximum: int = 16384) -> bytes:
    before = path.lstat()
    gate(stat.S_ISREG(before.st_mode) and before.st_uid == owner
         and before.st_nlink == 1
         and stat.S_IMODE(before.st_mode) in modes
         and 0 < before.st_size <= maximum, "UNSAFE_FILE")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        inside = os.fstat(fd)
        raw = os.read(fd, maximum + 1)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid",
              "st_nlink", "st_size", "st_mtime_ns")
    gate(len(raw) == before.st_size and all(
        getattr(before, field) == getattr(inside, field) == getattr(after, field)
        for field in fields), "FILE_DRIFT")
    return raw


def _source_gate() -> None:
    # main deploy creates SOURCE as 0755, then chmod -R a-w makes it
    # immutable 0555. Requiring 0755 accidentally rejects the deployed
    # original owner source, while accepting an unnecessarily writable mode.
    # The native release is installed separately and remains root:root 0755.
    _dir(SOURCE, owner=0, mode=0o555)
    _dir(NATIVE, owner=0, mode=0o755)
    for rel, expected in SOURCE_BLOBS.items():
        gate(_blob(_read(SOURCE / rel, owner=0, modes=(0o444, 0o644),
                         maximum=80000)) == expected, "TRUSTED_SOURCE_DRIFT")
    gate(_blob(_read(NATIVE / "device_fabric/native_private_tls.py",
                     owner=0, modes=(0o444, 0o644), maximum=30000))
         == "9d2fe1fd5d98b791a00cb57799b49d9582ae9849",
         "NATIVE_PRIVATE_SOURCE_DRIFT")
    # Source bytes are not enough if PYTHONPATH imported different modules.
    for function, relative in (
        (native_start, "device_fabric/native_brc_enrollment.py"),
        (native_poll, "device_fabric/native_brc_enrollment.py"),
        (parse_candidate, "device_fabric/native_install_preview.py"),
        (_parse_config, "scripts/h454_native_linux_runtime.py"),
        (approve_owner, "scripts/h454_native_owner_pair.py"),
        (pending_owner, "scripts/h454_native_owner_pair.py"),
        (host_db_preflight, "scripts/h15_brc_owner_private_pair.py"),
    ):
        gate(Path(function.__code__.co_filename).resolve(strict=True)
             == SOURCE / relative, "TRUSTED_IMPORT_PATH_DRIFT")


def _docker_inspect(*items: str) -> dict:
    result = subprocess.run(["/usr/bin/docker", "inspect", *items],
                            capture_output=True, stdin=subprocess.DEVNULL,
                            timeout=15, check=True)
    document = json.loads(result.stdout)
    gate(type(document) is list and len(document) == 1
         and type(document[0]) is dict, "DOCKER_IDENTITY_MISSING")
    return document[0]


def _bridge_peers_gate(network: dict) -> None:
    """Admit relay alone or one exact, isolated H15 Hermes sandbox peer.

    The WSS proxy shares the relay's network namespace and therefore is not
    a separate bridge endpoint. Never disconnect a peer as a preflight repair.
    """
    peers = network.get("Containers")
    gate(type(peers) is dict and RELAY in peers and len(peers) in (1, 2),
         "FOREIGN_BRIDGE_PEER_OR_ADDRESS")
    if len(peers) == 1:
        return
    peer_id = next(cid for cid in peers if cid != RELAY)
    endpoint = peers[peer_id]
    gate(type(peer_id) is str and re.fullmatch(r"[a-f0-9]{64}", peer_id)
         is not None and type(endpoint) is dict
         and endpoint.get("Name") == H15_PEER_NAME.lstrip("/")
         and endpoint.get("IPv4Address") == H15_PEER_CIDR,
         "FOREIGN_BRIDGE_PEER_OR_ADDRESS")
    peer = _docker_inspect(peer_id)
    host = peer.get("HostConfig") or {}
    config = peer.get("Config") or {}
    networks = (peer.get("NetworkSettings") or {}).get("Networks") or {}
    ports = (peer.get("NetworkSettings") or {}).get("Ports") or {}
    gate(peer.get("Id") == peer_id
         and peer.get("Name") == H15_PEER_NAME
         and peer.get("Image") == H15_PEER_IMAGE
         and (peer.get("State") or {}).get("Running") is True
         and (config.get("Labels") or {}).get("com.hermes.scope")
         == H15_PEER_SCOPE
         and host.get("NetworkMode") == NETWORK
         and host.get("ReadonlyRootfs") is True
         and host.get("Privileged") is False
         and set(host.get("CapDrop") or []) == {"ALL"}
         and "no-new-privileges" in {
             str(opt).split(":", 1)[0]
             for opt in (host.get("SecurityOpt") or [])
         }
         and not host.get("PortBindings")
         and not host.get("PublishAllPorts")
         and not any(ports.values())
         and set(networks) == {NETWORK}
         and networks[NETWORK].get("IPAddress") == H15_PEER_IP
         and networks[NETWORK].get("NetworkID") == network.get("Id")
         and all(
             m.get("Destination") not in
             ("/var/run/docker.sock", "/run/docker.sock")
             for m in (peer.get("Mounts") or [])
             if type(m) is dict
         ), "FOREIGN_BRIDGE_PEER_OR_ADDRESS")

def _runtime_gate() -> None:
    relay = _docker_inspect("hermes-brc-relay")
    wss = _docker_inspect("hermes-h454-wss-proxy")
    network = _docker_inspect(NETWORK)
    gate(relay.get("Id") == RELAY and relay.get("Image") == RELAY_IMAGE
         and relay.get("Name") == "/hermes-brc-relay"
         and relay.get("State", {}).get("Running") is True,
         "RELAY_IDENTITY_CHANGED")
    gate(wss.get("Id") == WSS and wss.get("Image") == WSS_IMAGE
         and wss.get("State", {}).get("Running") is True
         and wss.get("HostConfig", {}).get("NetworkMode") == "container:" + RELAY,
         "WSS_IDENTITY_CHANGED")
    attached = relay.get("NetworkSettings", {}).get("Networks") or {}
    gate(set(attached) == {NETWORK}
         and attached[NETWORK].get("IPAddress") == IP
         and attached[NETWORK].get("NetworkID") == network.get("Id")
         and network.get("Internal") is True
         and network.get("Driver") == "bridge",
         "FOREIGN_BRIDGE_PEER_OR_ADDRESS")
    _bridge_peers_gate(network)
    host = relay.get("HostConfig", {})
    ports = relay.get("NetworkSettings", {}).get("Ports") or {}
    mounts = relay.get("Mounts", [])
    gate(not host.get("PortBindings") and not host.get("PublishAllPorts")
         and not any(value for value in ports.values())
         and all(not str(m.get("Destination", "")).startswith("/opt/brc")
                 for m in mounts), "RELAY_EXPOSED_OR_SOURCE_MOUNTED")
    environ = relay.get("Config", {}).get("Env") or []
    gate(environ.count("HOST=0.0.0.0") == 1 and
         environ.count("PORT=3000") == 1, "RELAY_BINDING_CHANGED")
    # No token or request with GET /health; no public listener is exposed.
    conn = http.client.HTTPConnection(IP, 3000, timeout=4)
    try:
        conn.request("GET", "/health", headers={
            "Host": "brc-agent.internal", "Connection": "close"})
        response = conn.getresponse()
        gate(response.status == 200, "RELAY_HEALTH_UNAVAILABLE")
    finally:
        conn.close()


def _compiled_gate() -> None:
    # docker cp ... - returns a bounded tar stream in RAM; no local writes.
    result = subprocess.run([
        "/usr/bin/docker", "cp",
        "hermes-brc-relay:/opt/brc/packages/relay/dist/app.js", "-",
    ], capture_output=True, stdin=subprocess.DEVNULL, timeout=20, check=True)
    gate(0 < len(result.stdout) <= 2_000_000,
         "RELAY_APP_UNVERIFIABLE")
    with tarfile.open(fileobj=io.BytesIO(result.stdout), mode="r:") as reader:
        members = reader.getmembers()
        gate(len(members) == 1 and members[0].isfile()
             and members[0].name.split("/")[-1] == "app.js"
             and 0 < members[0].size <= 1_000_000,
             "RELAY_APP_UNEXPECTED_ARCHIVE")
        stream = reader.extractfile(members[0])
        gate(stream is not None, "RELAY_APP_UNREADABLE")
        raw = stream.read(1_000_001)
    guard_pos = raw.find(b"native_pairing_scope_denied")
    fallback_pos = raw.find(b"const deviceId = device_id || row.device_id")
    gate(0 <= guard_pos < fallback_pos and all(
        x in raw for x in (
            b"nativeProfile", b"nativeReserved",
            b"device_id !== undefined",
            b"store.getDevice(row.device_id)",
            b"/device/native-status", b"getDeviceByToken",
        )), "OWNER_BOUND_RELAY_GUARD_ABSENT")


def _service_gate() -> tuple[object, object, str]:
    entry = pwd.getpwnam(SERVICE)
    gate(entry.pw_uid == 972 and entry.pw_gid == 968
         and entry.pw_shell in ("/usr/sbin/nologin", "/sbin/nologin"),
         "SERVICE_IDENTITY_CHANGED")
    _dir(STATE, owner=entry.pw_uid, mode=0o700)
    gate(_absent(STATE, "device.json") and _absent(STATE, TMP_NAME),
         "DEVICE_ALREADY_PAIRED_OR_INTERRUPTED")
    raw = _read(STATE / "manifest.json", owner=entry.pw_uid,
                modes=(0o600,), maximum=MAX_CONFIG)
    candidate = parse_candidate(raw, expected_release=RELEASE,
                                expected_target="hermes-vps")
    gate(candidate.service_identity == SERVICE
         and candidate.service_name == SERVICE + ".service",
         "INVALID_NATIVE_MANIFEST")
    digest = hashlib.sha256(raw).hexdigest()

    unit = _read(UNIT, owner=0, modes=(0o644,), maximum=16000)
    gate(b"--run-once" in unit
         and ("--release-sha " + RELEASE).encode() in unit
         and ("--manifest-sha256 " + digest).encode() in unit
         and b"IPAddressDeny=any" in unit
         and unit.count(("IPAddressAllow=" + IP + "/32").encode()) == 1
         and unit.count(b"IPAddressAllow=") == 1
         and b"NoNewPrivileges=yes" in unit
         and b"ProtectSystem=strict" in unit
         and b"RestrictSUIDSGID=no" in unit,
         "NATIVE_UNIT_PIN_CHANGED")
    checked = subprocess.run([
        "/usr/bin/systemctl", "show", SERVICE + ".service", "--no-pager",
        "--property=LoadState,ActiveState,UnitFileState,NeedDaemonReload",
    ], capture_output=True, stdin=subprocess.DEVNULL, timeout=10, check=True)
    gate(set(checked.stdout.decode("ascii").splitlines()) ==
         {"LoadState=loaded", "ActiveState=inactive",
          "UnitFileState=disabled", "NeedDaemonReload=no"},
         "NATIVE_UNIT_ALREADY_STARTED_OR_DRIFTED")

    _dir(TRUST, owner=0, mode=0o755)
    trust_raw = _read(TRUST / "private-relay.json", owner=0,
                      modes=(0o444, 0o644), maximum=2048)
    trust = json.loads(trust_raw)
    gate(type(trust) is dict and canonical(trust) == trust_raw and
         set(trust) == {"schema", "target", "release_sha", "relay_ipv4",
                        "ca_sha256", "server_name", "port"} and
         trust.get("target") == "hermes-vps"
         and trust.get("release_sha") == RELEASE
         and trust.get("relay_ipv4") == IP
         and trust.get("server_name") == "brc-agent.internal"
         and type(trust.get("port")) is int and trust["port"] == 3001,
         "PRIVATE_TRUST_DRIFT")
    ca = _read(TRUST / "ca.crt", owner=0,
               modes=(0o444, 0o644), maximum=8192)
    pins = json.loads(_read(PINS, owner=0, modes=(0o600,)))
    gate(hashlib.sha256(ca).hexdigest() ==
         trust["ca_sha256"] == pins["ca_sha256"]
         and pins["relay_id"] == RELAY
         and pins["sidecar_id"] == WSS
         and pins["relay_ipv4"] == IP,
         "NATIVE_CA_OR_PROXY_DRIFT")
    gate((Path("/opt/hermes-commander-native/deps") /
          ("main-" + RELEASE) / "websockets/sync/client.py").is_file(),
         "PINNED_DEPENDENCY_MISSING")
    return entry, candidate, digest


def plan() -> dict:
    gate(os.geteuid() == 0 and
         socket.gethostname().split(".")[0] == "vps1777112993",
         "ORIGINAL_ROOT_REQUIRED")
    try:
        _source_gate()
    except Exception:
        raise PlanStageHold("SOURCE") from None
    try:
        _, candidate, manifest_sha = _service_gate()
    except Exception:
        raise PlanStageHold("SERVICE") from None
    try:
        _runtime_gate()
    except Exception:
        raise PlanStageHold("RUNTIME") from None
    try:
        _compiled_gate()
    except Exception:
        raise PlanStageHold("COMPILED_BRC") from None
    return {
        "status": "H454_HERMES_NATIVE_ENROLL_PLAN_PASS",
        "manifest_sha256": manifest_sha,
        "roots_checked": len(candidate.roots),
        "relay_verified": True,
        "transport": "PINNED_DOCKER_EXEC_LOCAL_LOOPBACK",
        "device_paired": False,
        "service_started": False,
        "owner_pairing_approval": "NOT_GRANTED",
        "mutations": False,
    }


def _tty_confirm(phrase: str, description: str) -> None:
    gate(sys.stdin.isatty() and sys.stdout.isatty(),
         "ORIGINAL_OWNER_TTY_REQUIRED")
    with open("/dev/tty", "r", encoding="ascii") as reader, \
         open("/dev/tty", "w", encoding="ascii", buffering=1) as writer:
        writer.write(description + "\nConfirm exactly:\n" + phrase + "\n> ")
        gate(reader.readline(300).strip() == phrase, "OWNER_DECLINED")


def _docker_post(path: str, body: bytes) -> tuple[int, bytes]:
    """Private relay loopback only, ephemeral nonroot node - no secrets in argv.

    Node script and JSON input are sent via docker exec's stdin; the only
    stdout is a length-bounded response, captured in memory, never logged.
    """
    gate(path in ("/device/start", "/device/poll")
         and type(body) is bytes and 0 < len(body) <= 2048,
         "UNAPPROVED_ENROLLMENT_POST")
    _runtime_gate()
    request = json.loads(body.decode("ascii"))
    gate(type(request) is dict and
         (request == {"client_name": NAME["hermes-vps"]}
          if path == "/device/start"
          else set(request) == {"device_code", "name", "platform"}
          and request["name"] == NAME["hermes-vps"]
          and request["platform"] == "linux"),
         "FOREIGN_PAIR_REQUEST")
    js = (
        "const p=" + json.dumps(path) + ";"
        + "const data=" + json.dumps(body.decode("ascii")) + ";"
        + "const control=new AbortController();"
        + "const timer=setTimeout(()=>control.abort(),5000);"
        + "try{const r=await fetch('http://127.0.0.1:3000'+p,"
        + "{method:'POST',headers:{'content-type':'application/json',"
        + "'accept':'application/json'},body:data,signal:control.signal,"
        + "redirect:'manual'});"
        + "const t=await r.text();"
        + "if(t.length>2048)throw Error('response');"
        + "process.stdout.write(JSON.stringify({status:r.status,body:t}));"
        + "}catch{process.stdout.write(JSON.stringify({status:599,body:''}));}"
        + "finally{clearTimeout(timer);}"
    )
    done = subprocess.run([
        "/usr/bin/docker", "exec", "--interactive",
        "--user", "65534:65534", RELAY, "node", "--input-type=module", "-",
    ], input=js.encode("ascii"), capture_output=True,
        timeout=12, check=False)
    gate(done.returncode == 0 and 0 < len(done.stdout) <= 4096,
         "PRIVATE_RELAY_POST_UNVERIFIED")
    try:
        document = json.loads(done.stdout.decode("ascii"))
    except (ValueError, UnicodeError, TypeError):
        raise EnrollmentHold("PRIVATE_RELAY_POST_UNVERIFIED") from None
    gate(type(document) is dict and set(document) == {"status", "body"}
         and type(document["status"]) is int
         and document["status"] in (200, 400)
         and type(document["body"]) is str
         and 0 < len(document["body"]) <= 2048,
         "PRIVATE_RELAY_POST_UNVERIFIED")
    _runtime_gate()
    return document["status"], document["body"].encode("ascii")


def _approve_pending(code: str) -> None:
    """One independent unprivileged child does EXACT owner CAS in live DB."""
    # Separate verified root -> relay identity; do not touch SQLite as root.
    identity = host_db_preflight()
    pid = os.fork()
    if pid == 0:
        try:
            os.setgroups([])
            os.setgid(identity.pw_gid)
            os.setuid(identity.pw_uid)
            conn = sqlite3.connect("file:" + str(DB) + "?mode=rw",
                                   uri=True, timeout=3, isolation_level=None)
            conn.row_factory = sqlite3.Row
            try:
                gate(conn.execute("PRAGMA journal_mode").fetchone()[0].lower()
                     == "wal", "RELAY_DATABASE_NOT_WAL")
                observed = pending_owner(conn, "hermes-vps", code,
                                         int(time.time() * 1000))
                approve_owner(conn, target="hermes-vps", user_code=code,
                              original=observed,
                              new_hex=os.urandom(16).hex(),
                              now_ms=int(time.time() * 1000))
            finally:
                conn.close()
            os._exit(0)
        except BaseException:
            os._exit(2)
    waited, status = os.waitpid(pid, 0)
    gate(waited == pid and os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0,
         "OWNER_DEVICE_APPROVAL_FAILED")


def _write_device(state: Path, uid: int, gid: int, data: bytes) -> None:
    """No overwrite; pre-fsync and verify service-owned exact bytes."""
    gate(type(data) is bytes and 0 < len(data) <= MAX_CONFIG,
         "DEVICE_CONFIG_INVALID")
    dfd = os.open(state, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(dfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        gate(_absent(state, "device.json") and _absent(state, TMP_NAME),
             "DEVICE_FILE_ALREADY_PRESENT")
        fd = os.open(TMP_NAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dfd)
        try:
            os.fchown(fd, uid, gid)
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as file:
                fd = -1
                file.write(data)
                file.flush()
                os.fsync(file.fileno())
        finally:
            if fd >= 0:
                os.close(fd)
        staged = os.stat(TMP_NAME, dir_fd=dfd, follow_symlinks=False)
        gate(staged.st_uid == uid and staged.st_gid == gid and
             staged.st_nlink == 1 and stat.S_IMODE(staged.st_mode) == 0o600
             and staged.st_size == len(data),
             "DEVICE_FILE_STAGING_DRIFT")
        # Hardlink fails if a foreign device.json already exists. Neither
        # the old file nor a created bearer is deleted on uncertainty.
        os.link(TMP_NAME, "device.json", src_dir_fd=dfd,
                dst_dir_fd=dfd, follow_symlinks=False)
        os.fsync(dfd)
        active = os.stat("device.json", dir_fd=dfd, follow_symlinks=False)
        gate((staged.st_dev, staged.st_ino) ==
             (active.st_dev, active.st_ino) and active.st_nlink == 2,
             "DEVICE_FILE_LINK_DRIFT")
        os.unlink(TMP_NAME, dir_fd=dfd)
        os.fsync(dfd)
        active = os.stat("device.json", dir_fd=dfd, follow_symlinks=False)
        gate(active.st_nlink == 1 and active.st_uid == uid and
             active.st_gid == gid and active.st_size == len(data)
             and stat.S_IMODE(active.st_mode) == 0o600,
             "DEVICE_FILE_READBACK_DRIFT")
    finally:
        os.close(dfd)


def enroll() -> dict:
    checked = plan()
    _tty_confirm(
        "H454 ENROLL READ ONLY HERMES VPS " + checked["manifest_sha256"],
        "Enroll ONE new original Hermes VPS native device. This creates "
        "one pending BRC code, owner-binds it and stores a service-owned "
        "0600 bearer. It does NOT start systemd or access project files.",
    )
    gate(plan() == checked, "HOST_DRIFT_AFTER_APPROVAL")
    service, candidate, digest = _service_gate()
    current = native_start("hermes-vps", post=_docker_post)
    # Only the short user-code is ever displayed, on private owner TTY.
    _tty_confirm("PAIR H454 hermes-vps " + current.user_code,
                 "Approve the exact fresh, expiring native Hermes device code "
                 "on this ORIGINAL trusted root terminal.")
    gate(plan() == checked, "HOST_DRIFT_BEFORE_PAIRING")
    _approve_pending(current.user_code)
    paired = native_poll(
        current, post=_docker_post, expected_ws_url="wss://hermes.mikemoore.top/ws"
    )
    gate(paired.target == "hermes-vps"
         and IDENTITY["hermes-vps"].fullmatch(paired.device_id) is not None
         and TOKEN.fullmatch(paired.token) is not None,
         "ISSUED_DEVICE_IDENTITY_UNTRUSTED")
    payload = canonical({
        "schema": CONFIG_SCHEMA,
        "target": "hermes-vps",
        "device_id": paired.device_id,
        "token": paired.token,
        "url": paired.ws_url,
        "release_sha": RELEASE,
        "manifest_sha256": digest,
        "roots": [
            {"project": project, "path": path} for project, path in candidate.roots
        ],
    })
    _parse_config(payload, candidate)
    _write_device(STATE, service.pw_uid, service.pw_gid, payload)
    # No service start/enable, no shell, no new public ingress.
    unit_state = subprocess.run([
        "/usr/bin/systemctl", "is-active", SERVICE + ".service",
    ], capture_output=True, timeout=5, check=False)
    gate(unit_state.stdout.strip() == b"inactive", "SERVICE_ACTIVATION_DRIFT")
    return {
        "status": "H454_HERMES_NATIVE_OWNER_DEVICE_PAIRED_SERVICE_OFF",
        "device_paired": True,
        "credential_persisted_service_0600": True,
        "service_started": False,
        "brc_wss_changed": False,
        "owner_approved": True,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("plan", "enroll"))
    parser.add_argument("--execute", action="store_true")
    arguments = parser.parse_args(argv)
    try:
        gate((arguments.action == "enroll") == arguments.execute,
             "EXPLICIT_EXECUTE_REQUIRED")
        report = enroll() if arguments.execute else plan()
        print(json.dumps(report, sort_keys=True))
        return 0
    except Exception as exc:
        # No access tokens, current codes, paths or Docker errors in output.
        result = {
            "status": "H454_HERMES_NATIVE_ENROLLMENT_HOLD",
            "no_auto_retry": True,
            "service_started": False,
        }
        if isinstance(exc, PlanStageHold):
            result["failed_stage"] = exc.stage
        print(json.dumps(result, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
