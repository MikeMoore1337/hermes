"""Staged offline-CA TLS leaf rotation for Hermes presence-only WSS (#346).

No CA signing key, new listener, credential enrollment or service activation.
The existing unit must be explicitly migrated to an atomic active pointer.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import datetime as dt
import fcntl
import grp
import hashlib
import os
from pathlib import Path
import secrets
import socket
import ssl
import stat
import subprocess
import time
from typing import Callable

from scripts.h15_presence_tls_preflight import PreflightError, check

TLS_HOME = Path("/var/lib/hermes-device-fabric/tls")
SERVICE = "hermes-device-fabric-pilot.service"
IDENTITY = "hermes-device-fabric"
PORT = 38177


class RotationError(ValueError):
    pass


def _directory(path: Path, *, owner: int = 0, group: int | None = None) -> None:
    try:
        s = path.lstat()
    except OSError as exc:
        raise RotationError("DIRECTORY_NOT_FOUND") from exc
    if not stat.S_ISDIR(s.st_mode) or s.st_uid != owner or (group is not None and s.st_gid != group):
        raise RotationError("DIRECTORY_UNTRUSTED")
    if stat.S_IMODE(s.st_mode) & 0o022:
        raise RotationError("DIRECTORY_WRITABLE_BY_OTHERS")


def _file(path: Path, *, max_size: int = 16384) -> bytes:
    try:
        s = path.lstat()
        if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or not 0 < s.st_size <= max_size:
            raise RotationError("SOURCE_FILE_UNTRUSTED")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            opened = os.fstat(fd)
            if opened.st_ino != s.st_ino or opened.st_dev != s.st_dev or opened.st_size != s.st_size:
                raise RotationError("SOURCE_FILE_CHANGED")
            data = os.read(fd, max_size + 1)
        finally:
            os.close(fd)
        if len(data) != s.st_size:
            raise RotationError("SOURCE_FILE_CHANGED")
        return data
    except OSError as exc:
        raise RotationError("SOURCE_FILE_UNAVAILABLE") from exc


def _write(path: Path, data: bytes, *, uid: int, gid: int, mode: int) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchown(fd, uid, gid)
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb", closefd=False) as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
    finally:
        os.close(fd)


def _sync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


@dataclass(frozen=True)
class RotationPaths:
    root: Path
    owner_uid: int = 0

    @property
    def ca(self) -> Path:
        return self.root / "ca-public.pem"

    @property
    def generations(self) -> Path:
        return self.root / "generations"

    @property
    def active(self) -> Path:
        return self.root / "active"


def _generation_name(data: bytes) -> str:
    return "leaf-" + hashlib.sha256(data).hexdigest()[:32]


def _validate_layout(paths: RotationPaths, *, gid: int) -> None:
    _directory(paths.root, owner=paths.owner_uid)
    _directory(paths.generations, owner=paths.owner_uid)
    if stat.S_IMODE(paths.root.stat().st_mode) != 0o750 or paths.root.stat().st_gid != gid:
        raise RotationError("ROOT_DIRECTORY_PERMISSIONS")
    if stat.S_IMODE(paths.generations.stat().st_mode) != 0o750 or paths.generations.stat().st_gid != gid:
        raise RotationError("GENERATIONS_DIRECTORY_PERMISSIONS")
    info = paths.ca.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != paths.owner_uid
            or info.st_gid != gid or stat.S_IMODE(info.st_mode) != 0o640):
        raise RotationError("UNTRUSTED_CA_PUBLIC_CERTIFICATE")
    _file(paths.ca)


def _validated_name(paths: RotationPaths, name: str, *, gid: int) -> Path:
    if not name.startswith("leaf-") or len(name) != 37 or any(c not in "0123456789abcdef" for c in name[5:]):
        raise RotationError("INVALID_GENERATION_NAME")
    generation = paths.generations / name
    _directory(generation, owner=paths.owner_uid, group=gid)
    if stat.S_IMODE(generation.stat().st_mode) != 0o750:
        raise RotationError("GENERATION_DIRECTORY_PERMISSIONS")
    for part in ("cert.pem", "key.pem"):
        s = (generation / part).lstat()
        if (not stat.S_ISREG(s.st_mode) or s.st_nlink != 1
                or s.st_uid != paths.owner_uid or s.st_gid != gid
                or stat.S_IMODE(s.st_mode) != 0o640):
            raise RotationError("GENERATION_FILE_PERMISSIONS")
    cert_bytes = _file(generation / "cert.pem")
    _file(generation / "key.pem")
    if _generation_name(cert_bytes) != name:
        raise RotationError("GENERATION_CONTENT_MISMATCH")
    return generation


def _pointer(paths: RotationPaths, pointer: Path, *, gid: int) -> str | None:
    try:
        s = pointer.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISLNK(s.st_mode) or s.st_uid != paths.owner_uid:
        raise RotationError("ACTIVE_POINTER_UNTRUSTED")
    target = os.readlink(pointer)
    if not target.startswith("generations/") or target.count("/") != 1:
        raise RotationError("ACTIVE_POINTER_UNTRUSTED")
    name = target.split("/")[1]
    _validated_name(paths, name, gid=gid)
    return name


def _pending_name(paths: RotationPaths, *, gid: int) -> str | None:
    return _pointer(paths, paths.root / "pending", gid=gid)


def _active_name(paths: RotationPaths, *, gid: int) -> str | None:
    return _pointer(paths, paths.active, gid=gid)


def _switch(paths: RotationPaths, name: str, pointer: str = "active") -> None:
    if pointer not in ("active", "pending"):
        raise RotationError("INVALID_POINTER")
    # Unique temp name: a power loss can strand an older uncommitted
    # symlink; that must not prevent a later recovery attempt.
    tmp = paths.root / ("." + pointer + "-" + name + "-" + secrets.token_hex(8))
    os.symlink("generations/" + name, tmp)
    try:
        os.replace(tmp, paths.root / pointer)
        _sync_dir(paths.root)
    finally:
        if tmp.is_symlink():
            tmp.unlink()


def _probe(*, ca: Path, leaf: Path, port: int = PORT, hostname: str = "localhost") -> bool:
    ctx = ssl.create_default_context(cafile=str(ca))
    ctx.check_hostname = True
    # systemctl can mark a simple process active before it binds the port.
    # Retry transport startup briefly, never a mismatched TLS identity.
    for attempt in range(3):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as channel:
                    actual = channel.getpeercert(binary_form=True)
                    expected = subprocess.run(
                        ["openssl", "x509", "-in", str(leaf), "-outform", "DER"],
                        capture_output=True, check=True, timeout=3,
                    ).stdout
                    return channel.version() in ("TLSv1.2", "TLSv1.3") and actual == expected
        except (OSError, ssl.SSLError, TimeoutError, subprocess.SubprocessError):
            if attempt == 2:
                return False
            time.sleep(0.4)
    return False


def _restart(unit: str) -> bool:
    if unit != SERVICE:
        raise RotationError("UNEXPECTED_SERVICE")
    try:
        p = subprocess.run(["/usr/bin/systemctl", "restart", unit],
                           timeout=20, capture_output=True)
        if p.returncode != 0:
            return False
        status = subprocess.run(["/usr/bin/systemctl", "is-active", "--quiet", unit], timeout=4)
        return status.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def stage(paths: RotationPaths, *, leaf: Path, key: Path, gid: int,
          now: dt.datetime | None = None) -> str:
    _validate_layout(paths, gid=gid)
    check(paths.ca, leaf, key, hostname="localhost",
          root_owned=paths.owner_uid == 0, min_valid_days=3, now=now)
    cert_data, key_data = _file(leaf), _file(key)
    name = _generation_name(cert_data)
    output = paths.generations / name
    if _pending_name(paths, gid=gid) is not None:
        raise RotationError("PENDING_CANDIDATE_ALREADY_EXISTS")
    if _active_name(paths, gid=gid) == name:
        raise RotationError("CANDIDATE_ALREADY_ACTIVE")
    if output.exists() or output.is_symlink():
        # Crash after atomic generation publish, but before pending pointer:
        # safely resume only for an identical, still-valid certificate/key.
        # Never replace an existing generation or silently trust its key.
        _validated_name(paths, name, gid=gid)
        if (_file(output / "cert.pem") != cert_data
                or _file(output / "key.pem") != key_data):
            raise RotationError("STAGED_GENERATION_SOURCE_MISMATCH")
        check(paths.ca, output / "cert.pem", output / "key.pem",
              hostname="localhost", min_valid_days=3, now=now,
              key_group_readable=True)
    else:
        # A killed process may strand a prior .incoming directory. Use a
        # unique private name so this does not block a future owner retry.
        # Leave stranded directories private for deliberate owner review.
        directory = paths.generations / (
            ".incoming-" + name + "-" + secrets.token_hex(8))
        os.mkdir(directory, mode=0o700)
        try:
            os.chown(directory, paths.owner_uid, gid)
            _write(directory / "cert.pem", cert_data, uid=paths.owner_uid, gid=gid, mode=0o640)
            _write(directory / "key.pem", key_data, uid=paths.owner_uid, gid=gid, mode=0o640)
            os.chmod(directory, 0o750)
            check(paths.ca, directory / "cert.pem", directory / "key.pem",
                  hostname="localhost", min_valid_days=3, now=now, key_group_readable=True)
            os.rename(directory, output)
            _sync_dir(paths.generations)
        finally:
            if directory.exists():
                for item in directory.iterdir():
                    item.unlink()
                directory.rmdir()
    if _pending_name(paths, gid=gid) is not None:
        raise RotationError("PENDING_CANDIDATE_ALREADY_EXISTS")
    _switch(paths, name, pointer="pending")
    return name


def _transaction(paths: RotationPaths, *, gid: int) -> str | None:
    marker = paths.root / ".rollback-target"
    if not marker.exists() and not marker.is_symlink():
        return None
    info = marker.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != paths.owner_uid
            or stat.S_IMODE(info.st_mode) != 0o600):
        raise RotationError("ROLLBACK_MARKER_UNTRUSTED")
    try:
        name = _file(marker, max_size=128).decode("ascii")
    except UnicodeError as exc:
        raise RotationError("ROLLBACK_MARKER_UNTRUSTED") from exc
    _validated_name(paths, name, gid=gid)
    return name


def _clear_transaction(paths: RotationPaths) -> None:
    (paths.root / ".rollback-target").unlink()
    _sync_dir(paths.root)


def recover(paths: RotationPaths, *, gid: int, unit: str = SERVICE,
            restart: Callable[[str], bool] = _restart,
            probe: Callable[..., bool] = _probe) -> str:
    _validate_layout(paths, gid=gid)
    old = _transaction(paths, gid=gid)
    if old is None:
        return "ROTATION=NO_PENDING_RECOVERY"
    _switch(paths, old)
    try:
        if not restart(unit) or not probe(ca=paths.ca, leaf=paths.generations / old / "cert.pem"):
            raise RotationError("RECOVERY_HEALTH_UNVERIFIED")
    except Exception as exc:
        raise RotationError("RECOVERY_HEALTH_UNVERIFIED") from exc
    _clear_transaction(paths)
    return "ROTATION=RECOVERED"


@contextmanager
def _exclusive(paths: RotationPaths):
    _directory(paths.root, owner=paths.owner_uid)
    marker = paths.root / ".rotation.lock"
    fd = os.open(marker, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != paths.owner_uid
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise RotationError("LOCK_FILE_UNTRUSTED")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RotationError("ROTATION_ALREADY_RUNNING") from exc
        yield
    finally:
        os.close(fd)


def activate(paths: RotationPaths, name: str, *, gid: int, unit: str = SERVICE,
             restart: Callable[[str], bool] = _restart,
             probe: Callable[..., bool] = _probe,
             now: dt.datetime | None = None) -> str:
    _validate_layout(paths, gid=gid)
    _validated_name(paths, name, gid=gid)
    check(paths.ca, paths.generations / name / "cert.pem",
          paths.generations / name / "key.pem",
          hostname="localhost", min_valid_days=3, now=now, key_group_readable=True)
    if _transaction(paths, gid=gid) is not None:
        raise RotationError("RECOVERY_REQUIRED")
    old = _active_name(paths, gid=gid)
    if old is None:
        raise RotationError("INITIAL_MIGRATION_REQUIRED")
    if old == name:
        return "ROTATION=ALREADY_ACTIVE"
    _write(paths.root / ".rollback-target", old.encode("ascii"),
           uid=paths.owner_uid, gid=gid, mode=0o600)
    _sync_dir(paths.root)
    _switch(paths, name)
    try:
        if restart(unit) and probe(ca=paths.ca, leaf=paths.generations / name / "cert.pem"):
            pending = _pending_name(paths, gid=gid)
            if pending == name:
                (paths.root / "pending").unlink()
                _sync_dir(paths.root)
            _clear_transaction(paths)
            return "ROTATION=PASS"
    except Exception:
        pass
    _switch(paths, old)
    recovered = False
    try:
        recovered = restart(unit) and probe(ca=paths.ca, leaf=paths.generations / old / "cert.pem")
    except Exception:
        pass
    if _pending_name(paths, gid=gid) == name:
        (paths.root / "pending").unlink()
        _sync_dir(paths.root)
    if recovered:
        _clear_transaction(paths)
    raise RotationError("ROTATION_ROLLED_BACK" if recovered else "ROLLBACK_HEALTH_UNVERIFIED")


def auto(paths: RotationPaths, *, gid: int,
         restart: Callable[[str], bool] = _restart,
         probe: Callable[..., bool] = _probe,
         now: dt.datetime | None = None) -> str:
    _validate_layout(paths, gid=gid)
    if _transaction(paths, gid=gid) is not None:
        return recover(paths, gid=gid, restart=restart, probe=probe)
    old = _active_name(paths, gid=gid)
    if old is None:
        raise RotationError("INITIAL_MIGRATION_REQUIRED")
    at = now or dt.datetime.now(dt.timezone.utc)
    existing = paths.generations / old
    try:
        check(paths.ca, existing / "cert.pem", existing / "key.pem",
              min_valid_days=3, now=at, key_group_readable=True)
        return "ROTATION=NOT_DUE"
    except PreflightError as exc:
        if str(exc) != "CERTIFICATE_EXPIRING_TOO_SOON":
            raise RotationError("ACTIVE_CERTIFICATE_INVALID") from exc
    pending = _pending_name(paths, gid=gid)
    if pending is None or pending == old:
        raise RotationError("NEED_STAGED_PENDING_CANDIDATE")
    return activate(paths, pending, gid=gid, restart=restart, probe=probe, now=at)


def _run_mode(args: argparse.Namespace, paths: RotationPaths, gid: int) -> int:
    try:
        if args.mode == "check":
            _validate_layout(paths, gid=gid)
            current = _active_name(paths, gid=gid)
            if current is None:
                raise RotationError("INITIAL_MIGRATION_REQUIRED")
            print("ROTATION=READY")
        elif args.mode == "stage":
            if args.leaf is None or args.key is None:
                raise RotationError("LEAF_AND_KEY_REQUIRED")
            stage(paths, leaf=args.leaf, key=args.key, gid=gid)
            print("ROTATION=STAGED")
        elif args.mode == "bootstrap":
            _validate_layout(paths, gid=gid)
            if _active_name(paths, gid=gid) is not None:
                raise RotationError("ALREADY_BOOTSTRAPPED")
            pending = _pending_name(paths, gid=gid)
            if pending is None:
                raise RotationError("NO_STAGED_CERTIFICATE")
            _switch(paths, pending)
            (paths.root / "pending").unlink()
            print("ROTATION=BOOTSTRAPPED_POINTER_ONLY")
        elif args.mode == "recover":
            print(recover(paths, gid=gid))
        elif args.mode == "activate":
            if not args.generation:
                raise RotationError("GENERATION_REQUIRED")
            print(activate(paths, args.generation, gid=gid))
        else:
            print(auto(paths, gid=gid))
        return 0
    except (RotationError, PreflightError, OSError, ValueError, KeyError) as exc:
        print("ROTATION=NO_GO")
        print("REASON=" + str(exc))
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["check", "stage", "bootstrap", "activate", "auto", "recover"])
    parser.add_argument("--leaf", type=Path)
    parser.add_argument("--key", type=Path)
    parser.add_argument("--generation")
    args = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise RotationError("ROOT_REQUIRED")
        gid = grp.getgrnam(IDENTITY).gr_gid
        paths = RotationPaths(TLS_HOME)
        with _exclusive(paths):
            return _run_mode(args, paths, gid)
    except (RotationError, PreflightError, OSError, ValueError, KeyError) as exc:
        print("ROTATION=NO_GO")
        print("REASON=" + str(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
