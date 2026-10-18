"""Optional outbound-only WSS presence client (Issue #297).

No startup service, CLI installer, filesystem handlers or remote shell. Caller
must explicitly supply a device credential and validating TLS context.
"""
from __future__ import annotations

import asyncio
import json
import ssl

try:
    from websockets.asyncio.client import connect
    from websockets.exceptions import ConnectionClosed
except ImportError:
    connect = None
    ConnectionClosed = Exception

from device_fabric.presence import NAME, AccessDenied, MAX_MSG


async def observe(url: str, device_id: str, token: str, *, tls: ssl.SSLContext,
                  stop: asyncio.Event, heartbeat_interval: float = 10,
                  connected: asyncio.Event | None = None) -> None:
    """Single outbound connection; disconnect on unknown server frame.

    A reconnect supervisor can call this again, but no work is ever buffered.
    """
    if connect is None:
        raise RuntimeError('websockets_dependency_missing')
    if not isinstance(url, str) or not url.startswith('wss://'):
        raise ValueError('wss_required')
    if not isinstance(tls, ssl.SSLContext) or tls.verify_mode != ssl.CERT_REQUIRED or not tls.check_hostname:
        raise ValueError('validating_tls_required')
    if not isinstance(device_id, str) or not NAME.fullmatch(device_id):
        raise ValueError('invalid_device')
    if not isinstance(token, str) or len(token) < 32:
        raise ValueError('invalid_token')
    if not 0.02 <= heartbeat_interval <= 60:
        raise ValueError('invalid_heartbeat')
    async with connect(url, ssl=tls, compression=None, max_size=MAX_MSG,
                       proxy=None, open_timeout=5) as socket:
        await socket.send(json.dumps({'type': 'hello', 'device_id': device_id, 'token': token}))
        response = json.loads(await asyncio.wait_for(socket.recv(), 5))
        if response != {'type': 'welcome'}:
            raise AccessDenied('pairing_denied')
        while not stop.is_set():
            await socket.send('{"type":"heartbeat"}')
            try:
                response = json.loads(await asyncio.wait_for(socket.recv(), 5))
            except (ConnectionClosed, asyncio.TimeoutError) as exc:
                raise AccessDenied('relay_unavailable') from exc
            if response != {'type': 'alive'}:
                # Do not interpret untrusted agent commands or arguments.
                raise AccessDenied('unexpected_server_message')
            if connected is not None:
                connected.set()
            try:
                await asyncio.wait_for(stop.wait(), heartbeat_interval)
            except asyncio.TimeoutError:
                continue
