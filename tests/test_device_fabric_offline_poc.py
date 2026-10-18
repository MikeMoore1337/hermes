"""Real loopback-stream integration checks. No agent/runtime/remote device access."""
import asyncio
import json
import unittest

from device_fabric.offline_poc import Denied, LoopbackRelay, ReadOnlyMCP, MAX_FRAME


class DeviceFabricOfflineTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.relay = LoopbackRelay(heartbeat_timeout=0.25)
        await self.relay.start()
        self.open_clients = []

    async def asyncTearDown(self):
        for reader, writer in self.open_clients:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass
        await self.relay.stop()

    def pair(self, device_id):
        code = self.relay.request_pair(device_id, f"Emulator {device_id}")
        return self.relay.approve_pair(code)

    async def connect(self, device_id, token):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.relay.port)
        self.open_clients.append((reader, writer))
        await self.send(writer, {"type": "hello", "device_id": device_id, "token": token})
        return reader, writer, await self.recv(reader)

    @staticmethod
    async def send(writer, packet):
        writer.write(json.dumps(packet).encode() + b"\n")
        await writer.drain()

    @staticmethod
    async def recv(reader):
        return json.loads(await asyncio.wait_for(reader.readline(), 0.6))

    async def test_two_emulators_heartbeat_offline_and_reconnect(self):
        a, b = self.pair("pc-one"), self.pair("vps-two")
        r1, w1, ok1 = await self.connect("pc-one", a)
        r2, w2, ok2 = await self.connect("vps-two", b)
        self.assertEqual((ok1["type"], ok2["type"]), ("welcome", "welcome"))
        self.assertEqual([d["status"] for d in self.relay.list_devices()], ["online", "online"])
        await self.send(w1, {"type": "heartbeat"})
        self.assertEqual((await self.recv(r1))["type"], "alive")
        w1.close()
        await w1.wait_closed()
        await asyncio.sleep(0.03)
        self.assertEqual(self.relay.device_status("pc-one")["status"], "offline")
        self.assertIsNotNone(self.relay.device_status("pc-one")["last_seen"])
        self.assertEqual((await self.connect("pc-one", a))[2]["type"], "welcome")
        self.assertEqual(self.relay.device_status("pc-one")["status"], "online")

    async def test_unpaired_wrong_token_and_spoofed_id_fail_closed(self):
        token = self.pair("emulator-a")
        for ident, secret in (("emulator-a", "bad"), ("emulator-b", token)):
            _, _, result = await self.connect(ident, secret)
            self.assertEqual(result["code"], "unauthorized")
            self.assertEqual(self.relay.device_status("emulator-a")["status"], "offline")
        self.assertEqual((await self.connect("emulator-a", token))[2]["type"], "welcome")

    async def test_pairing_is_single_use_and_cannot_duplicate_id(self):
        code = self.relay.request_pair("one-device", "One")
        secret = self.relay.approve_pair(code)
        with self.assertRaises(Denied):
            self.relay.approve_pair(code)
        with self.assertRaises(Denied):
            self.relay.request_pair("one-device", "A clone")
        _, _, success = await self.connect("one-device", secret)
        self.assertEqual(success["type"], "welcome")
        _, _, failure = await self.connect("one-device", secret)
        self.assertEqual(failure["code"], "already_online")
        self.assertEqual(self.relay.device_status("one-device")["status"], "online")

    async def test_revoke_closes_connection_and_rejects_replay(self):
        token = self.pair("revoked")
        reader, writer, result = await self.connect("revoked", token)
        self.assertEqual(result["type"], "welcome")
        self.relay.revoke("revoked")
        with self.assertRaises(Denied):
            self.relay.device_status("revoked")
        self.assertEqual((await self.connect("revoked", token))[2]["code"], "unauthorized")
        self.assertEqual(await asyncio.wait_for(reader.read(1), 0.3), b"")

    async def test_disabled_commands_never_enqueued_or_executed(self):
        token = self.pair("safe-device")
        reader, writer, _ = await self.connect("safe-device", token)
        await self.send(writer, {"type": "request", "command": "start_process", "args": {"command": "echo x"}})
        self.assertEqual((await self.recv(reader))["code"], "commands_disabled")
        writer.close()
        await writer.wait_closed()
        await asyncio.sleep(0.02)
        reader2, writer2, result = await self.connect("safe-device", token)
        self.assertEqual(result["type"], "welcome")
        # No pending-task queue: rejected requests never replay on reconnect.
        with self.assertRaises(asyncio.TimeoutError):
            await asyncio.wait_for(reader2.readline(), 0.035)
        writer2.close()

    async def test_idle_timeout_disconnects_device(self):
        token = self.pair("sleepy")
        reader, _, result = await self.connect("sleepy", token)
        self.assertEqual(result["type"], "welcome")
        await asyncio.sleep(0.32)
        self.assertEqual(self.relay.device_status("sleepy")["status"], "offline")
        self.assertEqual((await self.recv(reader))["code"], "connection_closed")

    async def test_oversized_and_malformed_packets_rejected(self):
        token = self.pair("limits")
        reader, writer, result = await self.connect("limits", token)
        self.assertEqual(result["type"], "welcome")
        writer.write(b'x' * (MAX_FRAME + 500) + b"\n")
        await writer.drain()
        self.assertEqual((await self.recv(reader))["code"], "frame_too_large")
        await asyncio.sleep(0.02)
        self.assertEqual(self.relay.device_status("limits")["status"], "offline")
        reader2, writer2, _ = await self.connect("limits", token)
        writer2.write(b'{no-json}\n')
        await writer2.drain()
        self.assertEqual((await self.recv(reader2))["code"], "invalid_json")

    async def test_read_only_mcp_initialize_discovery_and_deny_calls(self):
        self.pair("registered")
        mcp = ReadOnlyMCP(self.relay)
        self.assertEqual(mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize"})["result"]["protocolVersion"], "2025-03-26")
        self.assertIsNone(mcp.handle({"method": "notifications/initialized"}))
        tools = mcp.handle({"id": 2, "method": "tools/list"})["result"]["tools"]
        self.assertEqual({t["name"] for t in tools}, {"list_devices", "get_device_status"})
        self.assertTrue(all(t["annotations"]["readOnlyHint"] for t in tools))
        result = mcp.handle({"id": 3, "method": "tools/call", "params": {"name": "list_devices", "arguments": {}}})
        self.assertEqual(json.loads(result["result"]["content"][0]["text"])[0]["status"], "offline")
        status = mcp.handle({"id": 4, "method": "tools/call", "params": {"name": "get_device_status", "arguments": {"device_id": "registered"}}})
        self.assertEqual(json.loads(status["result"]["content"][0]["text"])["execution"], "disabled")
        for tool in ("read_file", "start_process", "write_file", "get_config", "list_processes"):
            denial = mcp.handle({"id": 5, "method": "tools/call", "params": {"name": tool, "arguments": {}}})
            self.assertEqual(denial["error"]["code"], -32601)
        self.assertEqual(mcp.handle({"id": 6, "method": "tools/call", "params": {"name": "get_device_status", "arguments": {"device_id": "other"}}})["error"]["code"], -32602)


if __name__ == "__main__":
    unittest.main()
