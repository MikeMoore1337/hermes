"""Isolated WSS device-presence pilot for Hermes #297.

No file, process, shell, or remote MCP operations are implemented. Not deployed.
An approved owner action must provision the SQLite DB, TLS and per-device tokens.
"""
from __future__ import annotations

import asyncio
from contextlib import suppress, contextmanager
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import ssl
import time
from datetime import datetime, timezone
from typing import Any

try:
    from websockets.asyncio.server import serve
    from websockets.exceptions import ConnectionClosed
except ImportError:  # Dormant source can be present without optional runtime packages.
    serve = None
    ConnectionClosed = Exception

NAME = re.compile(r"^[a-z][a-z0-9_-]{1,39}$")
MAX_MSG = 4096


def _now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _age(stamp):
    if not stamp:
        return float('inf')
    try:
        return (datetime.now(timezone.utc) - datetime.fromisoformat(stamp.replace('Z', '+00:00'))).total_seconds()
    except ValueError:
        return float('inf')


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


class AccessDenied(ValueError):
    pass


class DeviceRegistry:
    """Local-only owner-provisioned SQLite database; no public pairing API."""

    def __init__(self, path: Path, *, stale_after: float = 45):
        self.path = Path(path)
        if not 1 <= stale_after <= 3600:
            raise ValueError('invalid_stale_after')
        self.stale_after = stale_after

    @contextmanager
    def _connect(self, *, readonly=False):
        if readonly:
            conn = sqlite3.connect(self.path.resolve().as_uri() + '?mode=ro', uri=True, timeout=3)
        else:
            conn = sqlite3.connect(self.path, timeout=3)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def initialize(self):
        # Owner-run explicit action. No implicit creation on module import or reads.
        if self.path.exists():
            if self.path.is_symlink() or not self.path.is_file():
                raise AccessDenied('invalid_registry')
        else:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self._connect() as conn:
            conn.execute('CREATE TABLE IF NOT EXISTS devices('
                         'device_id TEXT PRIMARY KEY, name TEXT NOT NULL, secret_hash TEXT NOT NULL,'
                         'revoked INTEGER NOT NULL DEFAULT 0, connected INTEGER NOT NULL DEFAULT 0,'
                         'last_seen TEXT)')
            conn.execute('CREATE TABLE IF NOT EXISTS pending('
                         'code_hash TEXT PRIMARY KEY, device_id TEXT UNIQUE NOT NULL,'
                         'name TEXT NOT NULL, expires REAL NOT NULL)')
            conn.execute('CREATE TABLE IF NOT EXISTS events('
                         'id INTEGER PRIMARY KEY, at TEXT NOT NULL, device_id TEXT NOT NULL,'
                         'event TEXT NOT NULL)')
        os.chmod(self.path, 0o600)

    def _event(self, conn, device_id, event):
        conn.execute('INSERT INTO events(at, device_id, event) VALUES (?,?,?)', (_now(), device_id, event))
        conn.execute('DELETE FROM events WHERE id NOT IN '
                     '(SELECT id FROM events ORDER BY id DESC LIMIT 1000)')

    def request_pair(self, device_id, name, *, lifetime=120):
        if not isinstance(device_id, str) or not NAME.fullmatch(device_id):
            raise AccessDenied('invalid_device')
        if not isinstance(name, str) or not 1 <= len(name) <= 60:
            raise AccessDenied('invalid_name')
        if not 1 <= lifetime <= 600:
            raise ValueError('invalid_lifetime')
        code = secrets.token_urlsafe(24)
        with self._connect() as conn:
            conn.execute('DELETE FROM pending WHERE expires < ?', (time.time(),))
            if conn.execute('SELECT 1 FROM devices WHERE device_id=?', (device_id,)).fetchone():
                raise AccessDenied('device_exists')
            if conn.execute('SELECT 1 FROM pending WHERE device_id=?', (device_id,)).fetchone():
                raise AccessDenied('pending_exists')
            conn.execute('INSERT INTO pending VALUES (?,?,?,?)',
                         (_token_hash(code), device_id, name, time.time() + lifetime))
        return code

    def approve_pair(self, code):
        if not isinstance(code, str) or len(code) > 200:
            raise AccessDenied('invalid_pairing')
        with self._connect() as conn:
            row = conn.execute('SELECT * FROM pending WHERE code_hash=?', (_token_hash(code),)).fetchone()
            if row is None or row['expires'] < time.time():
                raise AccessDenied('not_pending')
            token = secrets.token_urlsafe(32)
            conn.execute('DELETE FROM pending WHERE code_hash=?', (_token_hash(code),))
            conn.execute('INSERT INTO devices(device_id, name, secret_hash) VALUES (?,?,?)',
                         (row['device_id'], row['name'], _token_hash(token)))
            self._event(conn, row['device_id'], 'paired')
        return token

    def authenticated(self, device_id, token):
        if not isinstance(device_id, str) or not isinstance(token, str) or len(token) > 200:
            return False
        with self._connect(readonly=True) as conn:
            row = conn.execute('SELECT secret_hash, revoked FROM devices WHERE device_id=?',
                               (device_id,)).fetchone()
        return bool(row and not row['revoked'] and hmac.compare_digest(row['secret_hash'], _token_hash(token)))

    def touch(self, device_id, connected):
        with self._connect() as conn:
            cur = conn.execute('UPDATE devices SET connected=?,last_seen=? WHERE device_id=? AND revoked=0',
                               (int(connected), _now(), device_id))
            if cur.rowcount != 1:
                raise AccessDenied('device_revoked')
            self._event(conn, device_id, 'online' if connected else 'offline')

    def heartbeat(self, device_id):
        with self._connect() as conn:
            cur = conn.execute('UPDATE devices SET last_seen=? WHERE device_id=? AND revoked=0 AND connected=1',
                               (_now(), device_id))
            if cur.rowcount != 1:
                raise AccessDenied('device_revoked')

    def revoke(self, device_id):
        with self._connect() as conn:
            cur = conn.execute('UPDATE devices SET revoked=1,connected=0 WHERE device_id=? AND revoked=0',
                               (device_id,))
            if cur.rowcount != 1:
                raise AccessDenied('unknown_device')
            self._event(conn, device_id, 'revoked')

    def list_devices(self):
        with self._connect(readonly=True) as conn:
            rows = conn.execute('SELECT device_id,name,revoked,connected,last_seen '
                                'FROM devices ORDER BY device_id LIMIT 100').fetchall()
        return [dict(device_id=r['device_id'], name=r['name'],
                     status=('revoked' if r['revoked'] else 'online' if r['connected']
                             and _age(r['last_seen']) <= self.stale_after else 'offline'),
                     last_seen=r['last_seen'], capabilities=['device_status'], execution='disabled')
                for r in rows]

    def device_status(self, device_id):
        return self.get_device_status(device_id)

    def get_device_status(self, device_id):
        for entry in self.list_devices():
            if entry['device_id'] == device_id:
                return entry
        raise AccessDenied('unknown_device')


class SecurePresenceRelay:
    """WSS listener bound to loopback by default; no command relay or HTTP API."""

    def __init__(self, registry: DeviceRegistry, *, heartbeat_timeout: float = 3):
        if not 0.1 <= heartbeat_timeout <= 90:
            raise ValueError('invalid_heartbeat_timeout')
        self.registry = registry
        self.timeout = heartbeat_timeout
        self._server = None
        self._sessions: dict[str, Any] = {}
        self._lock = asyncio.Lock()
        self.port = None

    async def start(self, ssl_context: ssl.SSLContext, *, host='127.0.0.1', port=0):
        if serve is None:
            raise RuntimeError('websockets_dependency_missing')
        if not isinstance(ssl_context, ssl.SSLContext):
            raise ValueError('tls_required')
        if host not in ('127.0.0.1', '::1'):
            raise AccessDenied('public_listener_not_approved')
        self._server = await serve(self._handler, host, port, ssl=ssl_context,
                                   max_size=MAX_MSG, max_queue=4,
                                   compression=None, ping_interval=20, ping_timeout=10)
        self.port = self._server.sockets[0].getsockname()[1]

    async def stop(self):
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def _handler(self, socket):
        device = None
        try:
            raw = await asyncio.wait_for(socket.recv(), self.timeout)
            hello = json.loads(raw)
            if (not isinstance(hello, dict) or hello.get('type') != 'hello'
                    or set(hello) != {'type', 'device_id', 'token'}):
                raise AccessDenied('unauthorized')
            ident, token = hello['device_id'], hello['token']
            if not self.registry.authenticated(ident, token):
                raise AccessDenied('unauthorized')
            async with self._lock:
                if ident in self._sessions:
                    raise AccessDenied('already_online')
                self._sessions[ident] = socket
            device = ident
            self.registry.touch(device, True)
            await socket.send(json.dumps({'type': 'welcome'}))
            while True:
                raw = await asyncio.wait_for(socket.recv(), self.timeout)
                message = json.loads(raw)
                if isinstance(message, dict) and message.get('type') == 'heartbeat' and set(message) == {'type'}:
                    self.registry.heartbeat(device)
                    await socket.send(json.dumps({'type': 'alive'}))
                else:
                    await socket.send(json.dumps({'type': 'error', 'code': 'commands_disabled'}))
        except (asyncio.TimeoutError, ConnectionClosed):
            pass
        except (ValueError, json.JSONDecodeError):
            with suppress(ConnectionClosed):
                await socket.send(json.dumps({'type': 'error', 'code': 'unauthorized'}))
        finally:
            if device:
                async with self._lock:
                    if self._sessions.get(device) is socket:
                        self._sessions.pop(device, None)
                        with suppress(AccessDenied):
                            self.registry.touch(device, False)
            with suppress(ConnectionClosed):
                await socket.close()


class DeviceStatusMCP:
    """Read-only in-process RPC facade; no MCP network endpoint until owner gate."""

    def __init__(self, registry: DeviceRegistry):
        self.registry = registry

    def handle(self, packet):
        from device_fabric.offline_poc import ReadOnlyMCP
        return ReadOnlyMCP(self.registry).handle(packet)
