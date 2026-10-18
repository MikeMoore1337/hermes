"""Explicitly activated, loopback-only TLS presence service (#297).

Does not create a registry, install certificates or run a device command.
"""
from __future__ import annotations

import argparse
import asyncio
import signal
import ssl
from pathlib import Path

from device_fabric.presence import DeviceRegistry, SecurePresenceRelay


async def run(*, database: Path, cert: Path, key: Path, port: int) -> None:
    if not (1024 <= port <= 65535):
        raise ValueError("invalid_port")
    if not database.is_file() or not cert.is_file() or not key.is_file():
        raise ValueError("pilot_not_prepared")
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(str(cert), str(key))

    relay = SecurePresenceRelay(DeviceRegistry(database), heartbeat_timeout=35)
    await relay.start(tls, host="127.0.0.1", port=port)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            pass
    try:
        await stop.wait()
    finally:
        await relay.stop()


def main() -> None:
    parser = argparse.ArgumentParser(description="Hermes device-presence pilot, loopback only")
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--cert", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--port", type=int, default=38177)
    args = parser.parse_args()
    asyncio.run(run(database=args.db, cert=args.cert, key=args.key, port=args.port))


if __name__ == "__main__":
    main()
