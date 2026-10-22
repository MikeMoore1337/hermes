"""H-27 #464: offline-only reviewed plugin manifest contract.

This is NOT a plugin registry, installer, discovery client, MCP bridge or
runtime loader. No third-party code, module, network, file or credentials run.
"""
from __future__ import annotations

import hashlib
import json
import re

SCHEMA = 1
MAX_MANIFEST_BYTES = 4096
FIELDS = frozenset({
    "id", "api_version", "capabilities", "data_scope", "side_effects",
    "owner_policy", "source_repo", "source_commit", "license",
    "optional_dependencies",
})
ID = "synthetic-research-reader"
REPO = "synthetic/hermes-fixture"
PIN = "0123456789abcdef0123456789abcdef01234567"  # deliberate non-real sample
LICENSE = "MIT"
CAPABILITY = "research.read"
SCOPE = "synthetic:public-metadata"
POLICY = "manual_review_readonly"
FIXTURE_RECORD = {
    "schema_version": 1, "fixture_id": "research-record-v1",
    "source_kind": "synthetic", "record_id": "study-demo-01",
}
REVIEW = {
    "schema_version": SCHEMA,
    "id": ID,
    "source_repo": REPO,
    "source_commit": PIN,
    "license": LICENSE,
    "capabilities": [CAPABILITY],
    "data_scope": SCOPE,
    "owner_policy": POLICY,
    "reviewed": True, "enabled": True,
}
_SHA = re.compile(r"^[0-9a-f]{40}$")
_IDENT = re.compile(r"^[a-z][a-z0-9-]{2,63}$")


class ReviewDenied(ValueError):
    """A sanitized static reason; never echo a manifest or a user path."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def sha256(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def _no_duplicate(pairs):
    item = {}
    for key, value in pairs:
        if key in item:
            raise ReviewDenied("DUPLICATE_KEY")
        item[key] = value
    return item


def _bad_number(_):
    raise ReviewDenied("INVALID_NUMBER")


def parse(raw):
    if type(raw) is not str:
        raise ReviewDenied("INVALID_JSON")
    try:
        if len(raw.encode("utf-8", errors="strict")) > MAX_MANIFEST_BYTES:
            raise ReviewDenied("INPUT_OVERSIZED")
        obj = json.loads(raw, object_pairs_hook=_no_duplicate,
                         parse_constant=_bad_number)
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise ReviewDenied("INVALID_JSON") from exc
    if type(obj) is not dict:
        raise ReviewDenied("MANIFEST_NOT_OBJECT")
    return obj


def validate(value, *, review=REVIEW):
    """Strict, local source-review consistency only, NOT ownership proof."""
    if type(value) is not dict or set(value) != FIELDS:
        raise ReviewDenied("MANIFEST_SCHEMA")
    if type(value["api_version"]) is not int or value["api_version"] != SCHEMA:
        raise ReviewDenied("UNSUPPORTED_VERSION")
    if type(value["id"]) is not str or not _IDENT.fullmatch(value["id"]):
        raise ReviewDenied("INVALID_ID")
    if value["id"] != ID:
        raise ReviewDenied("ALIAS_NOT_REVIEWED")
    if type(value["source_repo"]) is not str or value["source_repo"] != REPO:
        raise ReviewDenied("SOURCE_NOT_REVIEWED")
    commit = value["source_commit"]
    if type(commit) is not str or not _SHA.fullmatch(commit):
        raise ReviewDenied("INVALID_SOURCE_SHA")
    if type(value["license"]) is not str or not value["license"]:
        raise ReviewDenied("LICENSE_REQUIRED")
    if value["license"] not in ("MIT", "Apache-2.0"):
        raise ReviewDenied("LICENSE_NOT_ALLOWLISTED")
    if (type(value["capabilities"]) is not list or
            value["capabilities"] != [CAPABILITY]):
        raise ReviewDenied("CAPABILITY_NOT_ALLOWLISTED")
    if type(value["data_scope"]) is not str or value["data_scope"] != SCOPE:
        raise ReviewDenied("DATA_SCOPE_NOT_ALLOWLISTED")
    if type(value["side_effects"]) is not list or value["side_effects"] != []:
        raise ReviewDenied("SIDE_EFFECTS_DENIED")
    if type(value["owner_policy"]) is not str or value["owner_policy"] != POLICY:
        raise ReviewDenied("OWNER_POLICY_DENIED")
    if type(value["optional_dependencies"]) is not list or value["optional_dependencies"]:
        raise ReviewDenied("OPTIONAL_DEPENDENCIES_DENIED")
    if (type(review) is not dict or set(review) != {
            "schema_version", "id", "source_repo", "source_commit",
            "license", "capabilities", "data_scope", "owner_policy",
            "reviewed", "enabled"}):
        raise ReviewDenied("REVIEW_RECORD_SCHEMA")
    if type(review["schema_version"]) is not int or review["schema_version"] != SCHEMA:
        raise ReviewDenied("REVIEW_RECORD_SCHEMA")
    if type(review["reviewed"]) is not bool or not review["reviewed"]:
        raise ReviewDenied("NOT_REVIEWED")
    if type(review["enabled"]) is not bool or not review["enabled"]:
        raise ReviewDenied("REVIEW_DISABLED")
    for field in ("id", "source_repo", "source_commit", "license",
                  "capabilities", "data_scope", "owner_policy"):
        if type(value[field]) is not type(review[field]) or value[field] != review[field]:
            raise ReviewDenied("REVIEW_PIN_MISMATCH")
    return {
        "id": value["id"], "api_version": SCHEMA,
        "source_repo": value["source_repo"],
        "source_commit": value["source_commit"],
        "capabilities": [CAPABILITY],
        "data_scope": SCOPE, "status": "synthetic_review_match",
    }


def sample_manifest():
    return {
        "id": ID,
        "api_version": SCHEMA,
        "capabilities": [CAPABILITY],
        "data_scope": SCOPE,
        "side_effects": [],
        "owner_policy": POLICY,
        "source_repo": REPO,
        "source_commit": PIN,
        "license": LICENSE,
        "optional_dependencies": [],
    }


class SyntheticReader:
    """Single permitted in-memory fixture read; no effects or network."""

    def __init__(self, *, review=REVIEW):
        self.review = review
        self.calls = set()
        self.effects = []

    def read(self, raw_manifest, *, call_id, fixture_id):
        if type(call_id) is not str or not _IDENT.fullmatch(call_id):
            raise ReviewDenied("INVALID_CALL_ID")
        if call_id in self.calls:
            raise ReviewDenied("DUPLICATE_CALL")
        # No action is taken before both source review and read-only scope pass.
        validate(parse(raw_manifest), review=self.review)
        if type(fixture_id) is not str or fixture_id != "research-record-v1":
            raise ReviewDenied("FIXTURE_OUT_OF_SCOPE")
        self.calls.add(call_id)
        return dict(FIXTURE_RECORD)
