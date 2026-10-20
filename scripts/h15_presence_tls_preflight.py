"""Offline, read-only validation of a candidate private-CA WSS leaf (#346).

This checks a candidate before an operator may stage it. It NEVER installs,
rotates, signs or restarts anything, and needs only the CA public cert.
"""
from __future__ import annotations

import argparse
import datetime as dt
import os
import re
from pathlib import Path
import stat
import subprocess


class PreflightError(ValueError):
    pass


def _regular(path: Path, *, private: bool = False, root_owned: bool = False,
             key_group_readable: bool = False) -> None:
    try:
        item = path.lstat()
    except OSError as exc:
        raise PreflightError("MISSING_OR_UNREADABLE_INPUT") from exc
    if not stat.S_ISREG(item.st_mode) or item.st_nlink != 1:
        raise PreflightError("NONREGULAR_OR_LINKED_FILE")
    mode = stat.S_IMODE(item.st_mode)
    if private and (mode & 0o007 or (not key_group_readable and mode & 0o070)):
        raise PreflightError("PRIVATE_KEY_PERMISSIONS_UNSAFE")
    if root_owned and item.st_uid != 0:
        raise PreflightError("FILE_NOT_ROOT_OWNED")


def _openssl(*args: str) -> bytes:
    try:
        result = subprocess.run(["openssl", *args], capture_output=True, timeout=8, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PreflightError("OPENSSL_UNAVAILABLE_OR_TIMEOUT") from exc
    if result.returncode != 0:
        # Do not include stderr or key path contents in diagnostics.
        raise PreflightError("CERTIFICATE_OR_KEY_VERIFICATION_FAILED")
    return result.stdout.strip()


def check(
    ca: Path, leaf: Path, key: Path, *, hostname: str = "localhost",
    min_valid_days: int = 2, root_owned: bool = False,
    now: dt.datetime | None = None,
    key_group_readable: bool = False,
) -> str:
    if not hostname or any(ord(x) < 33 or ord(x) > 126 for x in hostname):
        raise PreflightError("INVALID_HOSTNAME")
    if not 0 <= min_valid_days <= 3650:
        raise PreflightError("INVALID_VALIDITY_THRESHOLD")
    if len({os.path.realpath(p) for p in (ca, leaf, key)}) != 3:
        raise PreflightError("INPUT_FILES_MUST_DIFFER")
    _regular(ca, root_owned=root_owned)
    _regular(leaf, root_owned=root_owned)
    _regular(key, private=True, root_owned=root_owned,
             key_group_readable=key_group_readable)

    at = now or dt.datetime.now(dt.timezone.utc)
    if at.tzinfo is None:
        raise PreflightError("NAIVE_CURRENT_TIME")
    _openssl("verify", "-CAfile", str(ca), "-no-CApath", "-purpose", "sslserver",
             "-verify_hostname", hostname, "-attime", str(int(at.timestamp())), str(leaf))
    san = _openssl("x509", "-in", str(leaf), "-ext", "subjectAltName", "-noout").decode("ascii")
    dns_names = re.findall(r"\bDNS:([^,\s]+)", san)
    if hostname.lower() not in {name.lower() for name in dns_names}:
        raise PreflightError("REQUIRED_DNS_SAN_MISSING")
    public_cert = _openssl("x509", "-in", str(leaf), "-pubkey", "-noout")
    public_key = _openssl("pkey", "-in", str(key), "-pubout")
    if public_cert != public_key:
        raise PreflightError("LEAF_PRIVATE_KEY_MISMATCH")

    end = _openssl("x509", "-in", str(leaf), "-enddate", "-noout").decode("ascii")
    if not end.startswith("notAfter="):
        raise PreflightError("MISSING_CERTIFICATE_EXPIRY")
    try:
        expires = dt.datetime.strptime(end[9:], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)
    except ValueError as exc:
        raise PreflightError("INVALID_CERTIFICATE_EXPIRY") from exc
    at = now or dt.datetime.now(dt.timezone.utc)
    if at.tzinfo is None:
        raise PreflightError("NAIVE_CURRENT_TIME")
    if expires - at < dt.timedelta(days=min_valid_days):
        raise PreflightError("CERTIFICATE_EXPIRING_TOO_SOON")
    return "CANDIDATE_CERTIFICATE_PREFLIGHT=PASS"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ca", required=True, type=Path)
    parser.add_argument("--leaf", required=True, type=Path)
    parser.add_argument("--key", required=True, type=Path)
    parser.add_argument("--hostname", default="localhost")
    parser.add_argument("--min-valid-days", type=int, default=2)
    parser.add_argument("--root-owned", action="store_true")
    args = parser.parse_args()
    try:
        print(check(args.ca, args.leaf, args.key, hostname=args.hostname,
                    min_valid_days=args.min_valid_days, root_owned=args.root_owned))
    except PreflightError as exc:
        print("CANDIDATE_CERTIFICATE_PREFLIGHT=NO_GO")
        print("REASON=" + str(exc))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
