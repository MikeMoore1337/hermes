"""Hermes #297: real encrypted loopback WSS + disk registry, read-only only."""
import asyncio
import json
from pathlib import Path
import ssl
import subprocess
import tempfile
import unittest

try:
    from websockets.asyncio.client import connect
    from websockets.exceptions import ConnectionClosed
except ImportError:
    connect = None
    ConnectionClosed = Exception

from device_fabric.read_only_agent import observe
from device_fabric.owner_smoke import probe
from device_fabric.presence import (AccessDenied, DeviceRegistry, DeviceStatusMCP,
                                    SecurePresenceRelay, MAX_MSG)


# Integration tests run under the pinned, dedicated websockets CI job.
# Plain deployment Python does not ship this optional dependency; registering
# skipped unittest cases changes the success banner to 'OK (skipped=N)', which
# the installed exact-OK production gate intentionally rejects.
class PresenceWssTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        cert, key = base / 'cert.pem', base / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                        '-keyout', str(key), '-out', str(cert)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(str(cert), str(key))
        self.client_context = ssl.create_default_context(cafile=str(cert))
        self.registry = DeviceRegistry(base / 'db' / 'devices.sqlite3', stale_after=2)
        self.registry.initialize()
        self.hub = SecurePresenceRelay(self.registry, heartbeat_timeout=.22)
        await self.hub.start(ctx)
        self.url = f'wss://localhost:{self.hub.port}'
        self.clients = []

    async def asyncTearDown(self):
        for sock in self.clients:
            await sock.close()
        await self.hub.stop()

    def pair(self, name):
        code = self.registry.request_pair(name, f'Test {name}')
        return self.registry.approve_pair(code)

    async def open(self, device, token):
        sock = await connect(self.url, ssl=self.client_context, max_size=MAX_MSG)
        self.clients.append(sock)
        await sock.send(json.dumps({'type': 'hello', 'device_id': device, 'token': token}))
        return sock, json.loads(await asyncio.wait_for(sock.recv(), .6))

    async def test_two_outbound_presence_clients_without_command_handlers(self):
        pc, vps = self.pair('win-sim'), self.pair('linux-sim')
        stop = asyncio.Event()
        tasks = [asyncio.create_task(observe(self.url, device, token,
                     tls=self.client_context, stop=stop, heartbeat_interval=.04))
                 for device, token in [('win-sim', pc), ('linux-sim', vps)]]
        try:
            await asyncio.sleep(.15)
            self.assertEqual({x['status'] for x in self.registry.list_devices()}, {'online'})
            stop.set()
            await asyncio.wait_for(asyncio.gather(*tasks), .5)
            await asyncio.sleep(.05)
            self.assertEqual({x['status'] for x in self.registry.list_devices()}, {'offline'})
        finally:
            stop.set()
            for task in tasks:
                if not task.done():
                    task.cancel()

    async def test_presence_client_rejects_plaintext_and_weak_tls(self):
        stop = asyncio.Event()
        with self.assertRaises(ValueError):
            await observe('ws://localhost', 'some-pc', 'x' * 40,
                          tls=self.client_context, stop=stop)
        insecure = ssl._create_unverified_context()
        with self.assertRaises(ValueError):
            await observe(self.url, 'some-pc', 'x' * 40,
                          tls=insecure, stop=stop)

    async def test_two_devices_heartbeat_offline_and_reconnect(self):
        pc, vps = self.pair('pc-demo'), self.pair('vps-demo')
        s1, r1 = await self.open('pc-demo', pc)
        s2, r2 = await self.open('vps-demo', vps)
        self.assertEqual((r1['type'], r2['type']), ('welcome', 'welcome'))
        self.assertEqual({r['status'] for r in self.registry.list_devices()}, {'online'})
        await s1.send(json.dumps({'type': 'heartbeat'}))
        self.assertEqual(json.loads(await s1.recv())['type'], 'alive')
        await s1.close()
        await asyncio.sleep(.03)
        self.assertEqual(self.registry.get_device_status('pc-demo')['status'], 'offline')
        s3, r3 = await self.open('pc-demo', pc)
        self.assertEqual(r3['type'], 'welcome')
        self.assertEqual(self.registry.get_device_status('pc-demo')['status'], 'online')

    async def test_tls_required_and_bad_ca_refused(self):
        with self.assertRaises((ssl.SSLCertVerificationError, OSError)):
            await connect(self.url, ssl=ssl.create_default_context())
        with self.assertRaises(ValueError):
            await SecurePresenceRelay(self.registry).start(None)
        with self.assertRaises(AccessDenied):
            await SecurePresenceRelay(self.registry).start(ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER), host='0.0.0.0')

    async def test_unknown_identity_wrong_token_and_duplicate_connection(self):
        token = self.pair('owner-pc')
        for identity, credential in [('unpaired', token), ('owner-pc', 'bad')]:
            sock, error = await self.open(identity, credential)
            self.assertEqual(error['code'], 'unauthorized')
            self.assertEqual(self.registry.get_device_status('owner-pc')['status'], 'offline')
        _, result = await self.open('owner-pc', token)
        self.assertEqual(result['type'], 'welcome')
        _, rejected = await self.open('owner-pc', token)
        self.assertEqual(rejected['code'], 'unauthorized')
        self.assertEqual(self.registry.get_device_status('owner-pc')['status'], 'online')

    async def test_pairing_persists_one_time_revoke_and_stale(self):
        code = self.registry.request_pair('new-linux', 'New Linux')
        token = self.registry.approve_pair(code)
        with self.assertRaises(AccessDenied):
            self.registry.approve_pair(code)
        restarted = DeviceRegistry(self.registry.path, stale_after=2)
        self.assertTrue(restarted.authenticated('new-linux', token))
        sock, _ = await self.open('new-linux', token)
        self.registry.revoke('new-linux')
        await sock.send(json.dumps({'type': 'heartbeat'}))
        denial = json.loads(await sock.recv())
        self.assertEqual(denial['code'], 'unauthorized')
        _, denial2 = await self.open('new-linux', token)
        self.assertEqual(denial2['code'], 'unauthorized')
        self.assertEqual(restarted.get_device_status('new-linux')['status'], 'revoked')

    async def test_command_and_oversize_rejected_no_replay(self):
        token = self.pair('deny-me')
        sock, _ = await self.open('deny-me', token)
        await sock.send(json.dumps({'type': 'call', 'tool': 'start_process', 'command': 'do something'}))
        denial = json.loads(await sock.recv())
        self.assertEqual(denial['code'], 'commands_disabled')
        await sock.send('x' * (MAX_MSG + 5))
        with self.assertRaises(ConnectionClosed):
            await sock.recv()
        await asyncio.sleep(.03)
        other, result = await self.open('deny-me', token)
        self.assertEqual(result['type'], 'welcome')
        with self.assertRaises(asyncio.TimeoutError):
            await asyncio.wait_for(other.recv(), .04)

    async def test_owner_smoke_checks_real_handshake_heartbeat_and_offline(self):
        token = self.pair('pilot-sim')
        token_path = Path(self.temp.name) / 'pilot-token'
        token_path.write_text(token, encoding='utf-8')
        await probe(self.registry, token_path,
                    Path(self.temp.name) / 'cert.pem', self.hub.port)
        state = self.registry.get_device_status('pilot-sim')
        self.assertEqual(state['status'], 'offline')
        self.assertIsNotNone(state['last_seen'])

    async def test_idle_timeout_and_read_only_mcp(self):
        token = self.pair('timed-out')
        sock, result = await self.open('timed-out', token)
        self.assertEqual(result['type'], 'welcome')
        await asyncio.sleep(.31)
        self.assertEqual(self.registry.get_device_status('timed-out')['status'], 'offline')
        mcp = DeviceStatusMCP(self.registry)
        self.assertEqual(mcp.handle({'id': 1, 'method': 'initialize'})['result']['protocolVersion'], '2025-03-26')
        tools = mcp.handle({'id': 2, 'method': 'tools/list'})['result']['tools']
        self.assertEqual({t['name'] for t in tools}, {'list_devices', 'get_device_status'})
        self.assertEqual(mcp.handle({'id': 3, 'method': 'tools/call', 'params': {'name': 'start_process'}})['error']['code'], -32601)
        status = mcp.handle({'id': 4, 'method': 'tools/call', 'params': {'name': 'get_device_status', 'arguments': {'device_id': 'timed-out'}}})
        self.assertEqual(json.loads(status['result']['content'][0]['text'])['execution'], 'disabled')

if connect is None:
    # Do not register integration tests requiring an absent optional runtime
    # into general unittest discovery. Dedicated WSS workflow runs all cases.
    del PresenceWssTests

if __name__ == '__main__':
    unittest.main()
