"""YFC async transport bounds and cleanup without network services."""
import asyncio
import socket
import unittest

from device_fabric.linux_native_async_transport import sync_adapter


class AsyncTransportTests(unittest.TestCase):
    def test_roundtrip_timeout_and_thread_cleanup(self):
        local, remote = socket.socketpair()
        events = []

        class FakeSocket:
            async def send(self, data):
                events.append(data)

            async def recv(self):
                await asyncio.sleep(1)

            async def close(self):
                local.close()
                events.append('closed')

        async def connect(_uri, **_kwargs):
            return FakeSocket()

        try:
            transport = sync_adapter(connect)('wss://fixture', sock=local)
            with transport as ws:
                ws.send('synthetic')
                with self.assertRaises(TimeoutError):
                    ws.recv(0.01)
            self.assertFalse(transport._thread.is_alive())
            self.assertEqual(events, ['synthetic', 'closed'])
        finally:
            local.close()
            remote.close()

    def test_failed_connection_closes_socket(self):
        local, remote = socket.socketpair()

        async def denied(_uri, **_kwargs):
            raise ValueError('synthetic')

        try:
            with self.assertRaises(ValueError):
                sync_adapter(denied)('wss://fixture', sock=local)
            self.assertEqual(local.fileno(), -1)
        finally:
            local.close()
            remote.close()
