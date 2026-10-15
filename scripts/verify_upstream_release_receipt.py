"""H-01: fail-closed Docker Hub immutable release-receipt comparison.

Pure public manifest reads via Docker buildx; never image pull/build/run,
tag/write, credentials, Telegram, model, or service restart. No success result
can authorize a resident agent: official release receipt is unsigned.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
from typing import Any, Callable

REPOSITORY = "nousresearch/hermes-agent"
VERSION_TAG = REPOSITORY + ":v0.21.6"
RECEIPT_DIGEST = "sha256:9774f4f39a9bb8c2f68ce728ed5e99ddbad282163be56764afacf88ed952b784"
RECEIPT_REF = REPOSITORY + "@" + RECEIPT_DIGEST
RELEASE_TAG_OBJECT = "f27cdbce5ab63eafe8633b293a75151409da5769"
RELEASE_COMMIT = "818c13be1dc4fd28987e1e881a9408224afd4535"
RELEASE_CLAIM = "rc.4-v0.21.6"
CLAIM_SKIP_TESTS = True
EXPECTED_ARCHES = frozenset({"amd64", "arm64"})
MANIFEST_MEDIA_TYPE = "application/vnd.docker.distribution.manifest.list.v2+json"
SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
MAX_RESPONSE = 24_576


class ReceiptDenied(ValueError):
    """Only fixed codes; never copy untrusted command output."""


def commands() -> tuple[tuple[str, ...], ...]:
    """Exact allowlist: three read-only registry metadata commands."""
    return (
        ("docker", "buildx", "imagetools", "inspect", VERSION_TAG,
         "--format", "{{json .Manifest.Digest}}"),
        ("docker", "buildx", "imagetools", "inspect", VERSION_TAG, "--raw"),
        ("docker", "buildx", "imagetools", "inspect", RECEIPT_REF, "--raw"),
    )


def read_arches(raw: object) -> dict[str, str]:
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_RESPONSE:
        raise ReceiptDenied("manifest_response_invalid")
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        fields: dict[str, Any] = {}
        for name, value in pairs:
            if name in fields:
                raise ReceiptDenied("manifest_duplicate_json_key")
            fields[name] = value
        return fields
    try:
        data = json.loads(raw, object_pairs_hook=unique)
    except ReceiptDenied:
        raise
    except (ValueError, UnicodeError):
        raise ReceiptDenied("manifest_json_invalid") from None
    if (type(data) is not dict or
            data.get("mediaType") != MANIFEST_MEDIA_TYPE or
            type(data.get("schemaVersion")) is not int or
            data["schemaVersion"] != 2 or
            type(data.get("manifests")) is not list or
            len(data["manifests"]) != 2):
        raise ReceiptDenied("manifest_schema_invalid")
    result: dict[str, str] = {}
    for item in data["manifests"]:
        if type(item) is not dict or type(item.get("platform")) is not dict:
            raise ReceiptDenied("manifest_arch_schema_invalid")
        platform = item["platform"]
        arch, os_name, digest = (
            platform.get("architecture"), platform.get("os"), item.get("digest")
        )
        if (type(arch) is not str or arch not in EXPECTED_ARCHES
                or os_name != "linux" or type(digest) is not str
                or SHA.fullmatch(digest) is None or arch in result):
            raise ReceiptDenied("manifest_arch_invalid")
        result[arch] = digest
    if frozenset(result) != EXPECTED_ARCHES or len(set(result.values())) != 2:
        raise ReceiptDenied("manifest_arch_incomplete")
    return result


def classify(current_digest: str, current: dict[str, str],
             receipt: dict[str, str]) -> dict[str, object]:
    if type(current_digest) is not str or SHA.fullmatch(current_digest) is None:
        raise ReceiptDenied("registry_digest_invalid")
    for arches in (current, receipt):
        if (type(arches) is not dict or frozenset(arches) != EXPECTED_ARCHES
                or any(type(x) is not str or SHA.fullmatch(x) is None
                       for x in arches.values())):
            raise ReceiptDenied("registry_arch_map_invalid")
    manifest_equal = current_digest == RECEIPT_DIGEST
    arches_equal = current == receipt
    # A third party's unsigned release tag must never be treated as signed
    # source-to-image attestation even if all observed digests match.
    status = ("RELEASE_RECEIPT_MISMATCH"
              if not (manifest_equal and arches_equal)
              else "MATCHED_BUT_PROVENANCE_UNVERIFIED")
    return {
        "status": status,
        "version_tag": VERSION_TAG,
        "release_tag_object": RELEASE_TAG_OBJECT,
        "release_claim": RELEASE_CLAIM,
        "release_commit": RELEASE_COMMIT,
        "current_tag_manifest_digest": current_digest,
        "release_receipt_manifest_digest": RECEIPT_DIGEST,
        "manifest_digest_equal": manifest_equal,
        "architecture_manifests_equal": arches_equal,
        "current_architecture_digests": current,
        "receipt_architecture_digests": receipt,
        "claim_skip_tests": CLAIM_SKIP_TESTS,
        "supplier_signature_verified": False,
        "complete_sbom_verified": False,
        "reproducible_source_build_verified": False,
        "resident_agent_allowed": False,
    }


def check_once(runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
               ) -> dict[str, object]:
    outputs: list[bytes] = []
    for command in commands():
        try:
            completed = runner(
                command, check=False, capture_output=True, timeout=18,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise ReceiptDenied("public_registry_read_unavailable") from None
        if (completed.returncode != 0 or
                type(completed.stdout) is not bytes or
                not 1 <= len(completed.stdout) <= MAX_RESPONSE):
            raise ReceiptDenied("public_registry_read_unavailable")
        outputs.append(completed.stdout)
    try:
        digest = json.loads(outputs[0])
    except (ValueError, UnicodeError):
        raise ReceiptDenied("registry_digest_json_invalid") from None
    return classify(
        digest, read_arches(outputs[1]), read_arches(outputs[2])
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read only three exact public Docker release manifest facts"
    )
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"status": "NOT_EXECUTED"}))
        return 0
    try:
        result = check_once()
    except ReceiptDenied:
        print(json.dumps({
            "status": "UNKNOWN", "resident_agent_allowed": False,
            "reason": "release_receipt_verification_unavailable",
        }))
        return 2
    print(json.dumps(result, sort_keys=True))
    # An unsigned receipt never makes the agent safe to start.
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
