"""Owner-scoped presence agent for Windows and Linux via outbound SSH + WSS.

No filesystem, shell, process, MCP command handler or queued requests exist.
The owner provisions an SSH tunnel separately; this client only speaks to
wss://localhost and validates the server's pinned pilot certificate.
"""
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
import signal
import ssl
import sys

from device_fabric.presence import NAME
from device_fabric.read_only_agent import observe, connect
from device_fabric.ssh_tunnel import ssh_arguments, keep_tunnel_open


class InvalidAgentConfig(ValueError):
    pass


class AgentDependencyUnavailable(RuntimeError):
    pass


def require_websockets() -> None:
    """Fail before establishing SSH; no raw traceback or repeated reconnect."""
    try:
        import websockets
        if connect is not None and websockets.__version__ == "16.0":
            return
    except ImportError:
        pass
    raise AgentDependencyUnavailable("websockets_16_required")


def load_config(path: Path) -> dict[str, str]:
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 8192:
        raise InvalidAgentConfig("invalid_config_file")
    # On Windows restrict ACLs manually; chmod is not a Windows access boundary.
    if sys.platform != "win32" and path.stat().st_mode & 0o077:
        raise InvalidAgentConfig("config_permissions_must_be_0600")
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise InvalidAgentConfig("invalid_config_json") from exc
    if not isinstance(config, dict) or set(config) != {
            "schema", "device_id", "endpoint", "token", "server_ca_pem"}:
        raise InvalidAgentConfig("invalid_config_fields")
    if config["schema"] != 1:
        raise InvalidAgentConfig("unsupported_config_schema")
    identity, url, token, pem = (
        config["device_id"], config["endpoint"], config["token"], config["server_ca_pem"])
    if not isinstance(identity, str) or not NAME.fullmatch(identity):
        raise InvalidAgentConfig("invalid_device")
    # A local SSH -L channel is required; never connect to a public raw WSS URL.
    if not isinstance(url, str) or url not in {
            "wss://localhost:38178", "wss://localhost:38179"}:
        raise InvalidAgentConfig("local_ssh_tunnel_required")
    if not isinstance(token, str) or len(token) < 40 or len(token) > 200:
        raise InvalidAgentConfig("invalid_token")
    if not isinstance(pem, str) or not pem.startswith("-----BEGIN CERTIFICATE-----\n") or len(pem) > 6144:
        raise InvalidAgentConfig("invalid_ca_certificate")
    # Fail before making any network calls when trust material is malformed.
    try:
        tls_context(config)
    except (ValueError, ssl.SSLError) as exc:
        raise InvalidAgentConfig("invalid_ca_certificate") from exc
    return config


def tls_context(config: dict) -> ssl.SSLContext:
    return ssl.create_default_context(cadata=config["server_ca_pem"])


async def run_agent(config: dict, stop: asyncio.Event, *,
                    heartbeat_interval: float = 10.0,
                    reconnect_delay: float = 2.0,
                    max_attempts: int | None = None,
                    connected: asyncio.Event | None = None) -> int:
    """Reconnect with bounded backoff; never buffer or replay a command."""
    if not 0.05 <= heartbeat_interval <= 60 or not 0.05 <= reconnect_delay <= 60:
        raise ValueError("invalid_intervals")
    if max_attempts is not None and not 1 <= max_attempts <= 100:
        raise ValueError("invalid_max_attempts")
    attempt = 0
    while not stop.is_set():
        attempt += 1
        print(f"DEVICE_AGENT_CONNECT_ATTEMPT={attempt}", flush=True)
        try:
            await observe(config["endpoint"], config["device_id"], config["token"],
                          tls=tls_context(config), stop=stop,
                          heartbeat_interval=heartbeat_interval, connected=connected)
        except asyncio.CancelledError:
            raise
        except (OSError, TimeoutError, ssl.SSLError, ValueError) as exc:
            # No credentials, URLs, hostnames, exception arguments or tracebacks in logs.
            if str(exc) == "pairing_denied":
                print("DEVICE_AGENT_PAIRING=DENIED", flush=True)
                return 3
            print("DEVICE_AGENT_CONNECTION=UNAVAILABLE", flush=True)
        if stop.is_set():
            print("DEVICE_AGENT_STOPPED=YES", flush=True)
            return 0
        if max_attempts is not None and attempt >= max_attempts:
            print("DEVICE_AGENT_MAX_ATTEMPTS=REACHED", flush=True)
            return 2
        delay = min(30.0, reconnect_delay * 2 ** min(attempt - 1, 4))
        try:
            await asyncio.wait_for(stop.wait(), delay)
        except asyncio.TimeoutError:
            pass
    return 0


async def _main_async(config: dict, *, seconds: float | None,
                      tunnel_argv: list[str]) -> int:
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    tunnel = asyncio.create_task(keep_tunnel_open(tunnel_argv, stop))
    connected = asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            # Windows default Ctrl+C yields KeyboardInterrupt; no private signal handlers.
            pass
    try:
        if seconds is None:
            return await run_agent(config, stop, connected=connected)
        async def deadline():
            await asyncio.sleep(seconds)
            stop.set()
        timer = asyncio.create_task(deadline())
        try:
            result = await run_agent(config, stop, reconnect_delay=0.2, connected=connected)
            if not connected.is_set():
                print('DEVICE_AGENT_HEARTBEAT=NOT_CONFIRMED', flush=True)
                return 2 if result == 0 else result
            print('DEVICE_AGENT_HEARTBEAT=PASS', flush=True)
            return result
        finally:
            timer.cancel()
    finally:
        stop.set()
        await tunnel
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.remove_signal_handler(sig)
            except NotImplementedError:
                pass


def main() -> None:
    parser = argparse.ArgumentParser(description="Hermes outbound device-presence-only agent")
    parser.add_argument("--config", required=True, type=Path)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--watch", action="store_true", help="reconnect whenever network returns")
    mode.add_argument("--once-seconds", type=float, help="connect briefly and then disconnect")
    parser.add_argument('--ssh-host', required=True)
    parser.add_argument('--ssh-user', required=True)
    parser.add_argument('--ssh-key', type=Path, required=True)
    parser.add_argument('--known-hosts', type=Path, required=True)
    parser.add_argument('--ssh-bin', default='ssh', choices=('ssh', 'ssh.exe'))
    args = parser.parse_args()
    if args.once_seconds is not None and not 0.5 <= args.once_seconds <= 120:
        parser.error("--once-seconds must be between 0.5 and 120")
    try:
        config = load_config(args.config)
        require_websockets()
        tunnel_argv = ssh_arguments(
            remote_host=args.ssh_host, remote_user=args.ssh_user,
            ssh_key=args.ssh_key, known_hosts=args.known_hosts,
            local_port=int(config['endpoint'].rsplit(':', 1)[1]), ssh_bin=args.ssh_bin)
        result = asyncio.run(_main_async(config, seconds=args.once_seconds,
                                        tunnel_argv=tunnel_argv))
    except AgentDependencyUnavailable:
        print("DEVICE_AGENT_DEPENDENCY=WEBSOCKETS_16_REQUIRED", file=sys.stderr)
        result = 5
    except (InvalidAgentConfig, ValueError) as exc:
        # Error code strings are sanitized, never interpolate config.
        print(f"DEVICE_AGENT_CONFIG={exc}", file=sys.stderr)
        result = 4
    except KeyboardInterrupt:
        result = 130
    raise SystemExit(result)


if __name__ == "__main__":
    main()
