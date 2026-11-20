"""Produce an actual native outbound read response over a synthetic socket."""
import json
from pathlib import Path
import tempfile

from device_fabric import linux_native_outbound as outbound
from device_fabric.linux_native_files import LinuxNativeFiles
from device_fabric.linux_native_read_dispatch import LinuxOriginalReadDispatcher


class Socket:
    def __init__(self):
        self.sent = []
        self.incoming = [
            {"type": "welcome", "protocol": 1, "relayVersion": "fixture", "serverTime": 1},
            {"type": "call", "id": "call-id-1", "tool": "native_file_read",
             "args": {"project": "hermes", "relative": "README.md"}},
        ]

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        pass

    def send(self, value):
        self.sent.append(json.loads(value))

    def recv(self, timeout=None):
        if not self.incoming:
            raise TimeoutError()
        return json.dumps(self.incoming.pop(0))


def main():
    identity = "h454-linux-hermes-" + "a" * 32
    token = "synthetic-fixture-token-" + "x" * 40
    config = outbound.local_config(target="hermes-vps", device_id=identity, token=token)
    with tempfile.TemporaryDirectory(prefix="h454-wire-contract-") as temp:
        root = Path(temp)
        (root / "README.md").write_bytes(b"abc")
        with LinuxNativeFiles(root=root, project="hermes") as files:
            dispatcher = LinuxOriginalReadDispatcher(device_id=identity, local_roots={"hermes": files},
                                                     is_device_revoked=lambda: False)
            sock = Socket()
            outbound.run_session(config, dispatcher, lambda *_args, **_kwargs: sock)
            result = sock.sent[-1]
            if result.get("type") != "result" or result.get("id") != "call-id-1":
                raise ValueError("synthetic_result_missing")
            print(json.dumps(result["result"], separators=(",", ":")))


if __name__ == "__main__":
    main()
