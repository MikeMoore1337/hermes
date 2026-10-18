"""Manual owner provisioning of independent read-only WSS device identities.

Never prints or logs a credential, certificate private key or pairing code.
Bundle is a 0600 JSON file to transfer over an owner-controlled secure channel.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from device_fabric.presence import AccessDenied, DeviceRegistry, NAME


def enroll(registry: DeviceRegistry, device_id: str, name: str, ca: Path,
           bundle_dir: Path, port: int) -> Path:
    if not isinstance(device_id, str) or not NAME.fullmatch(device_id):
        raise ValueError('invalid_device')
    if port not in (38178, 38179):
        raise ValueError("unapproved_local_forward_port")
    if ca.is_symlink() or not ca.is_file():
        raise ValueError("missing_ca_certificate")
    pem = ca.read_text(encoding="ascii")
    if not pem.startswith("-----BEGIN CERTIFICATE-----\n") or len(pem) > 6144:
        raise ValueError("invalid_ca_certificate")
    if bundle_dir.is_symlink() or (bundle_dir.exists() and not bundle_dir.is_dir()):
        raise ValueError("invalid_bundle_directory")
    bundle_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(bundle_dir, 0o700)
    # The token never crosses stdout. The temporary one-use code stays in RAM.
    filename = bundle_dir / f"{device_id}.json"
    if filename.exists() or filename.is_symlink():
        raise ValueError("bundle_already_exists")
    code = registry.request_pair(device_id, name)
    token = registry.approve_pair(code)
    payload = {
        "schema": 1, "device_id": device_id, "endpoint": f"wss://localhost:{port}",
        "token": token, "server_ca_pem": pem
    }
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(filename, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(payload, output, sort_keys=True)
            output.write("\n")
    except BaseException:
        # If bundle delivery fails, do not leave an enabled orphan credential.
        registry.revoke(device_id)
        raise
    return filename


def main() -> None:
    parser = argparse.ArgumentParser(description="Owner-only Hermes device enrollment")
    parser.add_argument("action", choices=("enroll", "list", "revoke"))
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--bundle-dir", type=Path)
    parser.add_argument("--ca", type=Path)
    parser.add_argument("--device-id")
    parser.add_argument("--name")
    parser.add_argument("--port", type=int)
    args = parser.parse_args()
    registry = DeviceRegistry(args.db)
    if args.action == "enroll":
        if any(v is None for v in (args.bundle_dir, args.ca, args.device_id, args.name, args.port)):
            parser.error("enroll requires --bundle-dir --ca --device-id --name --port")
        path = enroll(registry, args.device_id, args.name, args.ca, args.bundle_dir, args.port)
        print("DEVICE_ENROLLMENT=CREATED")
        print(f"DEVICE_ID={args.device_id}")
        print("BUNDLE=PRIVATE_0600")
        print("BUNDLE_LOCATION=OWNER_LOCAL_ONLY")
        print("EXECUTION=DISABLED")
    elif args.action == "revoke":
        if not args.device_id:
            parser.error("revoke requires --device-id")
        registry.revoke(args.device_id)
        print(f"DEVICE_REVOKED={args.device_id}")
    else:
        for device in registry.list_devices():
            print(f"DEVICE={device['device_id']} STATUS={device['status']} "
                  f"LAST_SEEN={device['last_seen'] or 'NEVER'} EXECUTION={device['execution']}")


if __name__ == "__main__":
    main()
