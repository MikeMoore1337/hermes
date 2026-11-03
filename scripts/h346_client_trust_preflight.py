"""Read-only, owner-pinned client trust-overlap preflight for Hermes #346.

This never writes device bundles, touches the relay or reads CA private keys.
It is NOT evidence of a live Windows/YFC handshake or migration approval.
"""
from __future__ import annotations

import argparse
import binascii
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import ssl
import stat
import subprocess

from device_fabric.device_agent import load_config

MAX_BUNDLE_BYTES = 6144
_PEM = re.compile(r"-----BEGIN CERTIFICATE-----\n(?:[A-Za-z0-9+/=]{1,128}\n)+-----END CERTIFICATE-----\n?")
_SHA256 = re.compile(r"[a-f0-9]{64}")


class TrustError(ValueError):
    pass


@dataclass(frozen=True)
class TrustPreview:
    device: str
    ca_sha256: str
    existing_ca_count: int
    overlap_bytes: int
    already_trusted: bool


def _read_file(path: Path, *, max_bytes: int, private: bool = False) -> bytes:
    try:
        before = path.lstat()
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or not 0 < before.st_size <= max_bytes):
            raise TrustError("UNTRUSTED_INPUT_FILE")
        if private and os.name == "posix" and stat.S_IMODE(before.st_mode) & 0o077:
            raise TrustError("CLIENT_CONFIG_PERMISSIONS_UNSAFE")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(fd)
            if (opened.st_ino != before.st_ino or opened.st_dev != before.st_dev
                    or opened.st_size != before.st_size):
                raise TrustError("INPUT_CHANGED_DURING_READ")
            data = os.read(fd, max_bytes + 1)
        finally:
            os.close(fd)
        if len(data) != before.st_size:
            raise TrustError("INPUT_CHANGED_DURING_READ")
        return data
    except OSError as exc:
        raise TrustError("INPUT_UNAVAILABLE") from exc


def _certificates(pem: str) -> list[tuple[str, bytes]]:
    if len(pem.encode("ascii", errors="replace")) > MAX_BUNDLE_BYTES:
        raise TrustError("TRUST_BUNDLE_TOO_LARGE")
    at = 0
    blocks = []
    while at < len(pem):
        match = _PEM.match(pem, at)
        if match is None:
            raise TrustError("INVALID_PUBLIC_CERTIFICATE_PEM")
        block = match.group(0).rstrip("\n") + "\n"
        try:
            der = ssl.PEM_cert_to_DER_cert(block)
        except (ValueError, ssl.SSLError, binascii.Error) as exc:
            raise TrustError("INVALID_PUBLIC_CERTIFICATE_PEM") from exc
        blocks.append((block, der))
        if len(blocks) > 4:
            raise TrustError("TOO_MANY_TRUST_CERTIFICATES")
        at = match.end()
    if not blocks:
        raise TrustError("EMPTY_TRUST_BUNDLE")
    return blocks


def _openssl(*args: str) -> str:
    try:
        p = subprocess.run(["openssl", *args], check=False, capture_output=True,
                           text=True, timeout=8)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise TrustError("OPENSSL_UNAVAILABLE") from exc
    if p.returncode != 0 or len(p.stdout) > 32768:
        raise TrustError("PUBLIC_CERTIFICATE_VERIFICATION_FAILED")
    return p.stdout


def _public_ca(path: Path) -> tuple[str, bytes]:
    raw = _read_file(path, max_bytes=8192)
    try:
        pem = raw.decode("ascii")
    except UnicodeError as exc:
        raise TrustError("CA_NOT_ASCII_PEM") from exc
    blocks = _certificates(pem)
    if len(blocks) != 1:
        raise TrustError("CA_MUST_BE_ONE_CERTIFICATE")
    detail = _openssl("x509", "-in", str(path), "-noout", "-text")
    if "CA:TRUE" not in detail or "Certificate Sign" not in detail:
        raise TrustError("CA_BASIC_CONSTRAINTS_REQUIRED")
    _openssl("verify", "-CAfile", str(path), "-no-CApath",
             "-check_ss_sig", str(path))
    _openssl("x509", "-in", str(path), "-noout", "-checkend", "604800")
    return blocks[0]


def _leaf(path: Path, ca: Path) -> bytes:
    raw = _read_file(path, max_bytes=8192)
    try:
        blocks = _certificates(raw.decode("ascii"))
    except UnicodeError as exc:
        raise TrustError("LEAF_NOT_ASCII_PEM") from exc
    if len(blocks) != 1:
        raise TrustError("LEAF_MUST_BE_ONE_CERTIFICATE")
    _openssl("verify", "-CAfile", str(ca), "-no-CApath",
             "-purpose", "sslserver", "-verify_hostname", "localhost", str(path))
    _openssl("x509", "-in", str(path), "-noout", "-checkend", "259200")
    san = _openssl("x509", "-in", str(path), "-noout", "-ext", "subjectAltName")
    if "localhost" not in {
        item.lower() for item in re.findall(r"\bDNS:([^,\s]+)", san)
    }:
        raise TrustError("DNS_LOCALHOST_SAN_REQUIRED")
    eku = _openssl("x509", "-in", str(path), "-noout", "-ext", "extendedKeyUsage")
    if ("TLS Web Server Authentication" not in eku
            and "1.3.6.1.5.5.7.3.1" not in eku):
        raise TrustError("SERVER_AUTH_EKU_REQUIRED")
    return blocks[0][1]


def check(
    config: Path, ca: Path, primary: Path, fallback: Path,
    *, expected_device: str, expected_ca_sha256: str,
) -> TrustPreview:
    if expected_device not in ("windows-pc", "linux-vps"):
        raise TrustError("UNEXPECTED_DEVICE")
    pin = expected_ca_sha256.lower()
    if _SHA256.fullmatch(pin) is None:
        raise TrustError("CA_PIN_REQUIRED")
    baseline = _read_file(config, max_bytes=8192, private=True)
    try:
        current = load_config(config)
    except (OSError, ValueError, ssl.SSLError) as exc:
        raise TrustError("CLIENT_CONFIG_INVALID") from exc
    if _read_file(config, max_bytes=8192, private=True) != baseline:
        raise TrustError("CLIENT_CONFIG_CHANGED")
    if current["device_id"] != expected_device:
        raise TrustError("DEVICE_ID_MISMATCH")
    expected_port = "38178" if expected_device == "windows-pc" else "38179"
    if current["endpoint"] != "wss://localhost:" + expected_port:
        raise TrustError("UNEXPECTED_TUNNEL_PORT")
    new_pem, new_der = _public_ca(ca)
    ca_hash = hashlib.sha256(new_der).hexdigest()
    if ca_hash != pin:
        raise TrustError("OFFLINE_CA_FINGERPRINT_MISMATCH")
    primary_der = _leaf(primary, ca)
    fallback_der = _leaf(fallback, ca)
    if primary_der == fallback_der:
        raise TrustError("FALLBACK_CERTIFICATE_NOT_INDEPENDENT")
    old = _certificates(current["server_ca_pem"])
    old_hashes = {hashlib.sha256(der).hexdigest() for _, der in old}
    already_trusted = ca_hash in old_hashes
    bundle = "".join(pem for pem, _ in old) + ("" if already_trusted else new_pem)
    if len(bundle.encode("ascii")) > MAX_BUNDLE_BYTES:
        raise TrustError("TRUST_BUNDLE_TOO_LARGE")
    try:
        ctx = ssl.create_default_context(cadata=bundle)
    except (ssl.SSLError, ValueError) as exc:
        raise TrustError("TRUST_BUNDLE_UNUSABLE") from exc
    if not ctx.check_hostname or ctx.verify_mode != ssl.CERT_REQUIRED:
        raise TrustError("TLS_VERIFICATION_NOT_ENFORCED")
    return TrustPreview(expected_device, ca_hash, len(old),
                        len(bundle.encode("ascii")), already_trusted)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--ca-public", required=True, type=Path)
    parser.add_argument("--primary-leaf", required=True, type=Path)
    parser.add_argument("--fallback-leaf", required=True, type=Path)
    parser.add_argument("--device", required=True, choices=("windows-pc", "linux-vps"))
    parser.add_argument("--expected-ca-sha256", required=True)
    args = parser.parse_args()
    try:
        result = check(args.config, args.ca_public, args.primary_leaf,
                       args.fallback_leaf, expected_device=args.device,
                       expected_ca_sha256=args.expected_ca_sha256)
        print("H346_CLIENT_TRUST_PREFLIGHT=PASS")
        print("H346_CA_PIN_MATCH=PASS")
        print("H346_CLIENT_DEVICE=" + result.device)
        print("H346_OVERLAP_BYTES=" + str(result.overlap_bytes))
        print("H346_CA_ALREADY_PRESENT=" + str(result.already_trusted).upper())
        print("H346_PRIVATE_CONFIG_CHANGED=NO")
        print("H346_CLIENT_LIVE_HANDSHAKE=NOT_RUN")
        print("H346_NATIVE_WINDOWS_ACL=" + (
            "NOT_VERIFIED" if os.name == "nt" else "NOT_APPLICABLE"))
        return 0
    except TrustError as exc:
        print("H346_CLIENT_TRUST_PREFLIGHT=NO_GO")
        print("REASON=" + str(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
