"""Owner-host paired upgrade admission; no installer or service start in this module."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path, PurePosixPath
import socket
import stat
import subprocess

from device_fabric.native_private_tls import load_private_relay
from scripts.h454_native_linux_wheel import RECEIPT as WHEEL_RECEIPT, _receipt as wheel_receipt
from scripts.h454_native_linux_wheel import verify_bytes as verify_wheel
from scripts.h454_native_paired_rebind import RebindDenied, Transition, build_transition, verified_sources
from scripts.h454_native_private_versioned_upgrade import checked_file, owned_directory, raw_show

OLD = "9181c49b3095cca64c8f49b641e1689cc987e7ee"
NEW = "2ce60cc8a3fc1e33df36632bc671f737b0d50131"
BUNDLE_SHA = "4d5d1d8b9f9be3df9eb44b017dbf1658db9e32ab4e4380f744bc6ce7e12182cd"
WHEEL_SHA = "6aa59f0ef92e796b2db6f5f26550c4713c0e4036899fadf02f55e2ed4db0b7ae"
MANIFEST_SHA = "c8cd38694b79dd0319eb2ebd69200be449cb17b7038d5d016a0a1db2b81fa829"
TRUST_SHA = "cd605ea7193082c215d8273328e5a73e0c6b6468719b17b38fa91c243e056c47"
CA_SHA = "014868af3edc97e04c58099746964bde1d65d2f38c931360e27a8f309b8c0f7c"
UNIT_SHA = {
    "hermes-commander-native.service": "4f4f15bbe1a0bef6670f52d6c5ac65d743320248dbb54cd41d31ff90e9ce6084",
    "hermes-commander-native-preflight.service": "ee56e054350523aba05af781c7839c9c988bbddc3316f934e0d29a1914f09cbd",
}
OLD_BLOBS = {
    "device_fabric/__init__.py": "b0a593a1351215ce4f3c05b805faeb34bef0161a",
    "device_fabric/linux_native_files.py": "898c57fbfcdc8f6102dc4d4ddb6f24a1c69bcca8",
    "device_fabric/linux_native_outbound.py": "fac78190b4cba0a8ff1d5bf12523ade7ea833564",
    "device_fabric/linux_native_read_dispatch.py": "91f918828820dad2ce9d862a459b7e9999458707",
    "device_fabric/linux_native_search.py": "21347322c0b278cd312f80e2c7cbf4dcc2c74d89",
    "device_fabric/native_brc_enrollment.py": "6ceffd491306026360e3355c1939586cd61df88c",
    "device_fabric/native_brc_status.py": "53576289893181f46b3b720dbd2e913de08caece",
    "device_fabric/native_effect_grants.py": "732470da527cfc07a2474486a8929752e76242dc",
    "device_fabric/native_install_preview.py": "72b1e8661bb170db81412203f29deea40fddf56e",
    "device_fabric/native_private_tls.py": "9d2fe1fd5d98b791a00cb57799b49d9582ae9849",
    "scripts/h454_native_install_preflight.py": "c0d7d7cc880ee39926cbcf92df818f22e7461598",
    "scripts/h454_native_linux_runtime.py": "b6e4383e8746d473fda745e351b02323c2bfb8b2",
    "scripts/h454_native_linux_service.py": "bc64ca59689df24f9986086c978f901e5c206ba6",
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


def _exact_file(path: Path, before: os.stat_result, expected: bytes) -> bool:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(fd)
        data = os.read(fd, len(expected) + 1)
        after = os.fstat(fd)
        fields = ("st_dev", "st_ino", "st_size", "st_ctime_ns", "st_mode", "st_uid")
        return data == expected and all(
            getattr(before, key) == getattr(opened, key) == getattr(after, key)
            for key in fields
        )
    finally:
        os.close(fd)


def _verified_tree(root: Path, files: dict[str, bytes], *, trusted_uid: int = 0) -> None:
    if type(trusted_uid) is not int or trusted_uid != os.geteuid():
        raise RebindDenied()
    owned_directory(root, owner=trusted_uid, mode=0o755)
    expected_dirs = set()
    for name in files:
        path = PurePosixPath(name)
        if path.is_absolute() or any(p in ("", ".", "..") for p in path.parts):
            raise RebindDenied()
        for parent in path.parents:
            if str(parent) != ".":
                expected_dirs.add(parent.as_posix())
    actual_files, actual_dirs = set(), set()
    for path in root.rglob("*"):
        rel = path.relative_to(root).as_posix()
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode) and info.st_uid == trusted_uid and stat.S_IMODE(info.st_mode) == 0o755:
            actual_dirs.add(rel)
        elif (rel in files and stat.S_ISREG(info.st_mode) and info.st_uid == trusted_uid
              and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o444
              and _exact_file(path, info, files[rel])):
            actual_files.add(rel)
        else:
            raise RebindDenied()
        if len(actual_files) > len(files) or len(actual_dirs) > len(expected_dirs):
            raise RebindDenied()
    if actual_files != set(files) or actual_dirs != expected_dirs:
        raise RebindDenied()


def inspect(*, staged: bool = False) -> HostPlan:
    """Read only: bind installed old files, staged source and paired identity.

    This admission does not stage, install, alter files, reload systemd, access
    the relay, or establish owner approval. It never returns data for logging.
    """
    try:
        if type(staged) is not bool or os.geteuid() != 0 or socket.gethostname() != "vps1777112993":
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
        verified_wheel = verify_wheel(wheel)
        source_target = base / "releases" / ("main-" + NEW)
        deps_target = base / "deps" / ("main-" + NEW)
        if staged:
            sources = verified_sources(bundle, receipt, release=NEW, expected_bundle_sha256=BUNDLE_SHA)
            _verified_tree(source_target, sources)
            deps = dict(verified_wheel.files)
            deps[WHEEL_RECEIPT] = wheel_receipt("hermes-vps", NEW, verified_wheel)
            _verified_tree(deps_target, deps)
        elif any(target.exists() or target.is_symlink() for target in (source_target, deps_target)):
            raise RebindDenied()
        transition = build_transition(manifest, device, trust, ca, bundle, receipt,
                                      old_release=OLD, new_release=NEW,
                                      expected_bundle_sha256=BUNDLE_SHA)
        return HostPlan(transition, manifest, device, trust, units, bundle, receipt, wheel,
                        identity.pw_uid, identity.pw_gid)
    except Exception:
        raise RebindDenied("native_paired_host_denied") from None
