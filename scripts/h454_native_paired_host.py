"""Owner-host paired upgrade admission; no installer or service start in this module."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import socket
import stat
import subprocess

from device_fabric.native_private_tls import load_private_relay
from scripts.h454_native_linux_wheel import verify_bytes as verify_wheel
from scripts.h454_native_paired_rebind import RebindDenied, Transition, build_transition
from scripts.h454_native_private_versioned_upgrade import checked_file, owned_directory, raw_show

OLD = "30db4fbab46626985b078d574dbe0b839872840e"
NEW = "f95bc75678334233a5b6a5cb6136a048d1f5e299"
BUNDLE_SHA = "f655da2fde877f52f8bae8b709670de510f51280b66a706f1ed3b9c3c512e359"
WHEEL_SHA = "6aa59f0ef92e796b2db6f5f26550c4713c0e4036899fadf02f55e2ed4db0b7ae"
MANIFEST_SHA = "8af5e283ae473a3ef94a83908253a5bc47e64ef82a95be6cb38bf834cb0b9747"
TRUST_SHA = "7ed257d75ca61649fd139657466d95d8358eb5c295eeacd14ae991188ff2f595"
CA_SHA = "014868af3edc97e04c58099746964bde1d65d2f38c931360e27a8f309b8c0f7c"
UNIT_SHA = {
    "hermes-commander-native.service": "75a681a6c6157acc3356513483b886f81097f958ef94d5d816a6eaf9c7ac4390",
    "hermes-commander-native-preflight.service": "2478a19c69e807bb93c5f99e4958862403a920bf98dec04c558add390972ce68",
}
OLD_BLOBS = {
    "device_fabric/__init__.py": "b0a593a1351215ce4f3c05b805faeb34bef0161a",
    "device_fabric/linux_native_files.py": "898c57fbfcdc8f6102dc4d4ddb6f24a1c69bcca8",
    "device_fabric/linux_native_outbound.py": "fac78190b4cba0a8ff1d5bf12523ade7ea833564",
    "device_fabric/linux_native_read_dispatch.py": "91f918828820dad2ce9d862a459b7e9999458707",
    "device_fabric/linux_native_search.py": "21347322c0b278cd312f80e2c7cbf4dcc2c74d89",
    "device_fabric/native_brc_enrollment.py": "6f17835d5a67869e2fdc1dbcbcb2bc373b0372ec",
    "device_fabric/native_brc_status.py": "53576289893181f46b3b720dbd2e913de08caece",
    "device_fabric/native_effect_grants.py": "732470da527cfc07a2474486a8929752e76242dc",
    "device_fabric/native_install_preview.py": "72b1e8661bb170db81412203f29deea40fddf56e",
    "device_fabric/native_private_tls.py": "9d2fe1fd5d98b791a00cb57799b49d9582ae9849",
    "scripts/h454_native_install_preflight.py": "c0d7d7cc880ee39926cbcf92df818f22e7461598",
    "scripts/h454_native_linux_runtime.py": "b6e4383e8746d473fda745e351b02323c2bfb8b2",
    "scripts/h454_native_linux_service.py": "c375effa28aaa6721ef36597694d8bc829043453",
    "scripts/h454_native_linux_unit_candidate.py": "6cc64e431f580ed84c69d44d24ce5700daa7cdc1",
}


@dataclass(frozen=True, repr=False, slots=True)
class HostPlan:
    transition: Transition
    old_manifest: bytes
    old_device: bytes
    old_trust: bytes
    old_units: dict[str, bytes]
    bundle: bytes
    receipt: bytes
    wheel: bytes
    uid: int
    gid: int

    def __repr__(self) -> str:
        return "HostPlan([REDACTED])"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _blob(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def _check_unit(name: str, relay_ip: str) -> None:
    values = raw_show(name)
    expected = {
        "FragmentPath": "/etc/systemd/system/" + name,
        "LoadState": "loaded", "UnitFileState": "static" if "preflight" in name else "disabled",
        "User": "hermes-commander-native", "Group": "hermes-commander-native",
        "DropInPaths": "", "NeedDaemonReload": "no", "RestrictSUIDSGID": "no",
        "NoNewPrivileges": "yes", "ProtectSystem": "strict",
        "PrivateNetwork": "yes" if "preflight" in name else "no",
    }
    if any(values.get(key) != value for key, value in expected.items()):
        raise RebindDenied()
    if values.get("ActiveState") not in ({"inactive"} if "preflight" in name else {"inactive", "failed"}):
        raise RebindDenied()
    status = subprocess.run(["/usr/bin/systemctl", "show", name, "--no-pager",
                             "--property=MainPID,SubState"], stdin=subprocess.DEVNULL,
                            capture_output=True, timeout=5, check=False)
    if status.returncode != 0 or len(status.stdout) > 1024:
        raise RebindDenied()
    lines = status.stdout.decode("ascii").splitlines()
    properties = dict(line.split("=", 1) for line in lines if "=" in line)
    if (len(lines) != 2 or set(properties) != {"MainPID", "SubState"}
        or properties["MainPID"] != "0" or properties["SubState"] not in {"dead", "failed"}):
        raise RebindDenied()
    if "preflight" not in name:
        deny = values.get("IPAddressDeny", "").split()
        if (deny != ["any"] and not (len(deny) == 2 and set(deny) == {"0.0.0.0/0", "::/0"})):
            raise RebindDenied()
        if values.get("IPAddressAllow") != relay_ip + "/32":
            raise RebindDenied()


def inspect() -> HostPlan:
    """Read only: bind installed old files, staged source and paired identity.

    This admission does not stage, install, alter files, reload systemd, access
    the relay, or establish owner approval. It never returns data for logging.
    """
    try:
        if os.geteuid() != 0 or socket.gethostname() != "vps1777112993":
            raise RebindDenied()
        import pwd as passwd
        identity = passwd.getpwnam("hermes-commander-native")
        if (identity.pw_uid <= 0 or identity.pw_gid <= 0
            or identity.pw_shell not in ("/usr/sbin/nologin", "/sbin/nologin")):
            raise RebindDenied()
        state = Path("/var/lib/hermes-commander-native")
        meta = state.lstat()
        if (not stat.S_ISDIR(meta.st_mode) or (meta.st_uid, meta.st_gid) !=
            (identity.pw_uid, identity.pw_gid) or stat.S_IMODE(meta.st_mode) != 0o700):
            raise RebindDenied()
        owned_directory(state.parent)
        for name in (".h454-hermes-enrollment.pending", ".h454-paired-manifest.json.pending",
                     ".h454-paired-device.json.pending"):
            if (state / name).exists() or (state / name).is_symlink():
                raise RebindDenied()
        manifest = checked_file(state / "manifest.json", 8192, owner=identity.pw_uid,
                                private=True, modes={0o600})
        device = checked_file(state / "device.json", 8192, owner=identity.pw_uid,
                              private=True, modes={0o600})
        if any((state / name).lstat().st_gid != identity.pw_gid
               for name in ("manifest.json", "device.json")):
            raise RebindDenied()
        if _sha(manifest) != MANIFEST_SHA:
            raise RebindDenied()
        original = Path("/opt/hermes-commander-native/releases/main-" + OLD)
        base = Path("/opt/hermes-commander-native")
        for directory, mode in ((base, 0o755), (base / "releases", 0o755),
                                (base / "deps", 0o755), (base / "receipts", 0o700),
                                (base / "deps" / ("main-" + OLD), 0o755)):
            owned_directory(directory, mode=mode)
        upgrade_receipt = base / "receipts" / ("h454-paired-upgrade-" + NEW)
        if upgrade_receipt.exists() or upgrade_receipt.is_symlink():
            raise RebindDenied()
        owned_directory(original, mode=0o755)
        for name, expected in OLD_BLOBS.items():
            if _blob(checked_file(original / name, 262144, modes={0o444})) != expected:
                raise RebindDenied()
        trust_root = Path("/opt/hermes-commander-native/trust")
        owned_directory(trust_root, mode=0o755)
        trust = checked_file(trust_root / "private-relay.json", 2048, modes={0o444})
        ca = checked_file(trust_root / "ca.crt", 8192, modes={0o444})
        if _sha(trust) != TRUST_SHA or _sha(ca) != CA_SHA:
            raise RebindDenied()
        relay = load_private_relay("hermes-vps", OLD)
        units = {}
        unit_root = Path("/etc/systemd/system")
        owned_directory(unit_root)
        for name, expected in UNIT_SHA.items():
            units[name] = checked_file(unit_root / name, 16384, modes={0o644})
            if _sha(units[name]) != expected:
                raise RebindDenied()
            _check_unit(name, relay.relay_ipv4)
        procs = subprocess.run(["/usr/bin/pgrep", "-u", str(identity.pw_uid)],
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=5, check=False)
        if procs.returncode != 1:
            raise RebindDenied()
        stage = Path("/root/h454-native-stage/main-" + NEW + "/hermes-vps")
        owned_directory(stage, mode=0o700)
        bundle = checked_file(stage / "h454-native-linux-readonly.tar.gz", 2097152,
                              private=True, modes={0o600})
        receipt = checked_file(stage / "h454-native-bundle-receipt.json", 4096,
                               private=True, modes={0o600})
        wheel_path = Path("/root/h454-native-stage/main-e8887bfb7a04aaff9cbb91a1c46003fcd8d5347a/hermes-vps/wheel/websockets-17.2-py3-none-any.whl")
        owned_directory(wheel_path.parent, mode=0o700)
        wheel = checked_file(wheel_path, 400000, private=True, modes={0o600})
        if _sha(wheel) != WHEEL_SHA:
            raise RebindDenied()
        verify_wheel(wheel)
        for target in (Path("/opt/hermes-commander-native/releases/main-" + NEW),
                       Path("/opt/hermes-commander-native/deps/main-" + NEW)):
            if target.exists() or target.is_symlink():
                raise RebindDenied()
        transition = build_transition(manifest, device, trust, ca, bundle, receipt,
                                      old_release=OLD, new_release=NEW,
                                      expected_bundle_sha256=BUNDLE_SHA)
        return HostPlan(transition, manifest, device, trust, units, bundle, receipt, wheel,
                        identity.pw_uid, identity.pw_gid)
    except Exception:
        raise RebindDenied("native_paired_host_denied") from None
