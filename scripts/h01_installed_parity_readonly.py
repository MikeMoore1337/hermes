"""H-01 #33: read-only evidence for installed source and durable reservation.

Runs offline on the actual Hermes VPS; no subprocesses, network, API calls,
service changes or writes. Source matching is LOCAL release parity, not proof
of successful provider use or a completed incident analysis.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import stat

OWNER = Path("/opt/hermes-agent-owner")
DEPLOY_MARKER = Path("/var/lib/hermes-main-deploy/last-success.sha")
RESERVATION = Path("/var/lib/hermes-h01/state.json")
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
DATE = re.compile(r"\d{4}-\d{2}-\d{2}\Z")
REL_PATH = Path("scripts/h01_ops_agent_service.py")


class EvidenceUnavailable(ValueError):
    """A safe code that never embeds untrusted on-host content."""


def _read_regular(path: Path, limit: int) -> bytes:
    # A parent symlink check is required separately for the known release paths.
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise EvidenceUnavailable("not_a_bounded_regular_file")
        with path.open("rb") as handle:
            content = handle.read(limit + 1)
        if len(content) > limit:
            raise EvidenceUnavailable("file_too_large")
        return content
    except (OSError, ValueError) as exc:
        raise EvidenceUnavailable("file_unavailable") from None


def _source(owner: Path, marker: Path) -> tuple[str, str | None]:
    sha = _read_regular(marker, 128).decode("ascii", "strict").strip()
    if not HEX40.fullmatch(sha):
        raise EvidenceUnavailable("invalid_deployment_marker")
    release = owner / "releases" / ("main-" + sha)
    for part in (owner, owner / "scripts", owner / "releases",
                 release, release / "scripts"):
        if part.is_symlink() or not part.is_dir():
            raise EvidenceUnavailable("unsafe_release_root")
    receipt = _read_regular(release / ".deployment-receipt.txt", 4096)
    try:
        receipt_lines = receipt.decode("utf-8", "strict").splitlines()
    except UnicodeError:
        raise EvidenceUnavailable("invalid_release_receipt") from None
    if receipt_lines.count("SHA=" + sha) != 1:
        raise EvidenceUnavailable("release_receipt_mismatch")
    expected = _read_regular(release / REL_PATH, 128_000)
    installed = _read_regular(owner / REL_PATH, 128_000)
    # Fail closed if concurrent deployment changed the marker mid-snapshot.
    if _read_regular(marker, 128).decode("ascii", "strict").strip() != sha:
        raise EvidenceUnavailable("deployment_changed_during_probe")
    matching = hashlib.sha256(installed).digest() == hashlib.sha256(expected).digest()
    return ("MATCH" if matching else "DRIFT"), sha


def _reservation(path: Path) -> dict[str, object]:
    try:
        record = json.loads(_read_regular(path, 8192))
    except (ValueError, UnicodeError) as exc:
        raise EvidenceUnavailable("invalid_reservation_json") from None
    if (type(record) is not dict or
            set(record) != {"utc_date", "calls", "last_event_id", "last_status"} or
            type(record["utc_date"]) is not str or
            not (record["utc_date"] == "" or DATE.fullmatch(record["utc_date"])) or
            type(record["calls"]) is not int or not 0 <= record["calls"] <= 1 or
            type(record["last_event_id"]) is not int or record["last_event_id"] < 0 or
            type(record["last_status"]) is not str or len(record["last_status"]) > 80):
        raise EvidenceUnavailable("invalid_reservation_contract")
    # No raw status or untrusted payloads appear in the output.
    kind = ("PASS_RECORDED" if record["last_status"] == "PASS" else
            "RESERVED" if record["last_status"] == "RESERVED_NO_RETRY" else
            "OTHER")
    return {
        "utc_date": record["utc_date"], "reserved_calls": record["calls"],
        "last_event_id": record["last_event_id"], "last_status_kind": kind,
    }


def probe(
    owner: Path = OWNER,
    marker: Path = DEPLOY_MARKER,
    reservation: Path = RESERVATION,
) -> dict[str, object]:
    result: dict[str, object] = {
        "schema": "h01-installed-parity-v1",
        "source_parity": "NOT_VERIFIED",
        "source_release_sha": None,
        "reservation": "NOT_VERIFIED",
        "reservation_summary": None,
        "useful_incident_model_turn": "NOT_VERIFIED",
        "provider_side_usage": "NOT_MEASURED",
    }
    try:
        source_parity, sha = _source(owner, marker)
        result["source_parity"] = source_parity
        result["source_release_sha"] = sha
    except (EvidenceUnavailable, OSError, ValueError, UnicodeError):
        pass
    try:
        result["reservation_summary"] = _reservation(reservation)
        result["reservation"] = "VALID"
    except (EvidenceUnavailable, OSError, ValueError, UnicodeError):
        pass
    return result


def main() -> int:
    report = probe()
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if (report["source_parity"] == "MATCH" and
                 report["reservation"] == "VALID") else 2


if __name__ == "__main__":
    raise SystemExit(main())
