"""Owner-invoked read-only WSS pilot checks. Never print the device token."""
from __future__ import annotations

import argparse
import asyncio
from pathlib import Path
import ssl

from device_fabric.presence import DeviceRegistry
from device_fabric.read_only_agent import observe


def provision(registry: DeviceRegistry, token_path: Path) -> None:
    # Explicit manual action, not service startup; token lives in 0600 state.
    registry.initialize()
    if token_path.exists():
        if token_path.is_symlink() or not token_path.is_file():
            raise ValueError("invalid_token_file")
        if not registry.authenticated("pilot-sim", token_path.read_text().strip()):
            raise ValueError("pilot_token_mismatch")
        print("PILOT_IDENTITY=already_prepared")
        return
    if any(d["device_id"] == "pilot-sim" for d in registry.list_devices()):
        raise ValueError("pilot_token_missing")
    code = registry.request_pair("pilot-sim", "Hermes local test simulator")
    token = registry.approve_pair(code)
    with token_path.open("x") as output:
        output.write(token + "\n")
    token_path.chmod(0o600)
    print("PILOT_IDENTITY=created")


async def probe(registry: DeviceRegistry, token_path: Path, cert: Path, port: int) -> None:
    token = token_path.read_text().strip()
    if not registry.authenticated("pilot-sim", token):
        raise ValueError("pilot_token_invalid")
    tls = ssl.create_default_context(cafile=str(cert))
    stop = asyncio.Event()
    task = asyncio.create_task(observe(
        f"wss://localhost:{port}", "pilot-sim", token,
        tls=tls, stop=stop, heartbeat_interval=0.15))
    try:
        # Observe live session, not merely an accepted TCP socket.
        for _ in range(30):
            await asyncio.sleep(0.05)
            if task.done():
                await task
            status = registry.get_device_status("pilot-sim")["status"]
            if status == "online":
                break
        else:
            raise RuntimeError("pilot_never_online")
    finally:
        stop.set()
        await asyncio.wait_for(task, timeout=4)
    status = registry.get_device_status("pilot-sim")
    if status["status"] != "offline" or status["last_seen"] is None:
        raise RuntimeError("pilot_did_not_disconnect")
    print("WSS_TLS_HANDSHAKE=PASS")
    print("PILOT_HEARTBEAT=PASS")
    print("PILOT_OFFLINE_AFTER_DISCONNECT=PASS")
    print("REMOTE_COMMAND_EXECUTION=NOT_IMPLEMENTED")


def main() -> None:
    parser = argparse.ArgumentParser(description="Hermes owner-scoped device pilot probe")
    parser.add_argument("action", choices=("provision", "probe", "status"))
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--cert", type=Path)
    parser.add_argument("--port", type=int, default=38177)
    args = parser.parse_args()
    registry = DeviceRegistry(args.db)
    if args.action == "provision":
        provision(registry, args.token_file)
    elif args.action == "probe":
        if args.cert is None:
            parser.error("--cert required for probe")
        asyncio.run(probe(registry, args.token_file, args.cert, args.port))
    else:
        for entry in registry.list_devices():
            print(f"DEVICE={entry['device_id']} STATUS={entry['status']} "
                  f"EXECUTION={entry['execution']}")
            

if __name__ == "__main__":
    main()
