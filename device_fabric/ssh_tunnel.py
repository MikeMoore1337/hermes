"""Reconnectable outbound SSH local-forward transport for presence-only WSS.

No remote command: OpenSSH -N -T -L only. Dedicated restricted authorized_keys
grant must constrain the target to 127.0.0.1:38177 on Hermes VPS.
"""
from __future__ import annotations

import asyncio
import shutil
from pathlib import Path
import re

ALIAS = re.compile(r"^[a-zA-Z][a-zA-Z0-9_.-]{0,99}$")
HOST = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$")


def ssh_arguments(*, remote_host: str, remote_user: str, ssh_key: Path,
                  known_hosts: Path, local_port: int, ssh_bin: str = "ssh") -> list[str]:
    if local_port not in (38178, 38179):
        raise ValueError("unapproved_local_port")
    if not isinstance(remote_host, str) or not HOST.fullmatch(remote_host):
        raise ValueError("invalid_ssh_host")
    if not isinstance(remote_user, str) or not ALIAS.fullmatch(remote_user):
        raise ValueError("invalid_ssh_user")
    if not isinstance(ssh_bin, str) or ssh_bin not in ("ssh", "ssh.exe"):
        raise ValueError("invalid_ssh_binary")
    if shutil.which(ssh_bin) is None:
        raise ValueError("ssh_client_unavailable")
    ssh_key, known_hosts = Path(ssh_key), Path(known_hosts)
    if (ssh_key.is_symlink() or not ssh_key.is_file() or
            known_hosts.is_symlink() or not known_hosts.is_file()):
        raise ValueError("missing_ssh_identity_or_host_key")
    return [
        ssh_bin, "-F", "none", "-N", "-T", "-p", "25566",
        "-i", str(ssh_key), "-o", "IdentitiesOnly=yes",
        "-o", "BatchMode=yes", "-o", "PasswordAuthentication=no",
        "-o", "KbdInteractiveAuthentication=no",
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={known_hosts}",
        "-o", "ForwardAgent=no", "-o", "ClearAllForwardings=no",
        "-o", "ExitOnForwardFailure=yes",
        "-o", "GatewayPorts=no", "-o", "ServerAliveInterval=15",
        "-o", "ServerAliveCountMax=2",
        "-L", f"127.0.0.1:{local_port}:127.0.0.1:38177",
        f"{remote_user}@{remote_host}"
    ]


async def keep_tunnel_open(argv: list[str], stop: asyncio.Event, *,
                           retry_delay: float = 3.0) -> None:
    if not 0.05 <= retry_delay <= 60:
        raise ValueError("invalid_retry_delay")
    while not stop.is_set():
        print("DEVICE_TUNNEL=CONNECTING", flush=True)
        proc = await asyncio.create_subprocess_exec(
            *argv, stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL)
        try:
            waiter = asyncio.create_task(proc.wait())
            stopped = asyncio.create_task(stop.wait())
            done, pending = await asyncio.wait({waiter, stopped},
                                               return_when=asyncio.FIRST_COMPLETED)
            for t in pending:
                t.cancel()
            if not stop.is_set():
                print("DEVICE_TUNNEL=DISCONNECTED", flush=True)
        finally:
            if proc.returncode is None:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), 2)
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
        if stop.is_set():
            break
        try:
            await asyncio.wait_for(stop.wait(), retry_delay)
        except asyncio.TimeoutError:
            pass
