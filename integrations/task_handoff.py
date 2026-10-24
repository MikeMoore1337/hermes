"""Development-only, offline validation of cross-project handoff packets.

This is a strict *shape and scope* validator. It never verifies GitHub, BRC,
ToolKit, deployment, or approval claims and grants no execution permission.
"""
from __future__ import annotations

import json
import re
from urllib.parse import urlsplit

MAX_PACKET_BYTES = 8192
REPOSITORIES = {
    "hermes": "MikeMoore1337/hermes",
    "yfc": "MikeMoore1337/your-fitness-coach",
    "second-brain": "MikeMoore1337/second-brain",
    "toolkit": "MikeMoore1337/ai-development-toolkit",
}
SHA = re.compile(r"[0-9a-f]{40}\Z")
PROFILE = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")
LINK = re.compile(
    r"(?:pull|issues)/[1-9][0-9]*\Z|actions/runs/[1-9][0-9]*\Z|commit/[0-9a-f]{40}\Z"
)


class HandoffRefused(ValueError):
    """A fixed, sanitized refusal code; never contains submitted content."""


def _shape(obj: object, expected: set[str], code: str) -> dict:
    if type(obj) is not dict or set(obj) != expected:
        raise HandoffRefused(code)
    return obj


def _integer(value: object, code: str) -> int:
    if type(value) is not int or value < 1 or value > 2_147_483_647:
        raise HandoffRefused(code)
    return value


def _sha(value: object, code: str) -> str:
    if type(value) is not str or SHA.fullmatch(value) is None:
        raise HandoffRefused(code)
    return value


def _link(value: object, repository: str, code: str) -> str:
    if type(value) is not str or len(value) > 240:
        raise HandoffRefused(code)
    try:
        parsed = urlsplit(value)
    except ValueError:
        raise HandoffRefused(code) from None
    pieces = parsed.path.lstrip("/").split("/")
    if (parsed.scheme != "https" or parsed.netloc != "github.com"
            or parsed.query or parsed.fragment or parsed.username
            or len(pieces) < 4 or "/".join(pieces[:2]) != repository
            or LINK.fullmatch("/".join(pieces[2:])) is None):
        raise HandoffRefused(code)
    return value


def _pairs(items: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in items:
        if key in result:
            raise HandoffRefused("duplicate_json_key")
        result[key] = value
    return result


def _reported_result(obj: object, *, kind: str, repository: str) -> dict:
    expected = {"state", "ref"} if kind == "tests" else {"state", "ref", "sha"}
    result = _shape(obj, expected, kind + "_fields_invalid")
    allowed = {
        "tests": {"NOT_RUN", "REPORTED_PASS", "REPORTED_FAIL"},
        "ci": {"NOT_VERIFIED", "REPORTED_SUCCESS", "REPORTED_FAILURE"},
        "production": {"NOT_VERIFIED", "REPORTED_DEPLOYED"},
    }[kind]
    state = result["state"]
    if type(state) is not str or state not in allowed:
        raise HandoffRefused(kind + "_state_invalid")
    missing = state in {"NOT_RUN", "NOT_VERIFIED"}
    if missing:
        if result["ref"] is not None or (kind != "tests" and result["sha"] is not None):
            raise HandoffRefused(kind + "_unknown_claim_conflict")
    else:
        _link(result["ref"], repository, kind + "_ref_invalid")
        if kind != "tests":
            _sha(result["sha"], kind + "_sha_invalid")
    return result


def validate(packet: object) -> dict[str, object]:
    """Return a bounded handoff, never a verified/authorized outcome."""
    root = _shape(packet, {"schema_version", "task", "workspace", "toolkit", "evidence"},
                  "packet_fields_invalid")
    if type(root["schema_version"]) is not int or root["schema_version"] != 1:
        raise HandoffRefused("schema_unsupported")
    task = _shape(root["task"], {"repository", "issue"}, "task_fields_invalid")
    workspace = _shape(root["workspace"], {"alias", "scope", "git_verified"},
                       "workspace_fields_invalid")
    alias = workspace["alias"]
    if type(alias) is not str or alias not in REPOSITORIES:
        raise HandoffRefused("workspace_unknown")
    repository = REPOSITORIES[alias]
    if task["repository"] != repository:
        raise HandoffRefused("repository_workspace_mismatch")
    _integer(task["issue"], "issue_invalid")
    if workspace["scope"] != "sandbox" or workspace["git_verified"] is not False:
        raise HandoffRefused("workspace_proof_cannot_be_inferred")

    toolkit = _shape(root["toolkit"], {"profile", "selection"},
                     "toolkit_fields_invalid")
    if toolkit["selection"] not in ("NOT_VERIFIED", "REPORTED_SELECTED"):
        raise HandoffRefused("toolkit_selection_invalid")
    if toolkit["selection"] == "NOT_VERIFIED":
        if toolkit["profile"] is not None:
            raise HandoffRefused("toolkit_unknown_claim_conflict")
    elif (type(toolkit["profile"]) is not str
          or PROFILE.fullmatch(toolkit["profile"]) is None):
        raise HandoffRefused("toolkit_profile_invalid")

    evidence = _shape(root["evidence"],
                      {"pr", "tests", "ci", "production", "owner_acceptance"},
                      "evidence_fields_invalid")
    pr = evidence["pr"]
    if pr is not None:
        pr = _shape(pr, {"number", "head_sha", "ref"}, "pr_fields_invalid")
        number = _integer(pr["number"], "pr_number_invalid")
        _sha(pr["head_sha"], "pr_sha_invalid")
        link = _link(pr["ref"], repository, "pr_ref_invalid")
        if link != "https://github.com/" + repository + "/pull/" + str(number):
            raise HandoffRefused("pr_ref_mismatch")
    _reported_result(evidence["tests"], kind="tests", repository=repository)
    ci = _reported_result(evidence["ci"], kind="ci", repository=repository)
    _reported_result(evidence["production"], kind="production",
                     repository=repository)
    if evidence["owner_acceptance"] not in ("PENDING", "REPORTED_ACCEPTED"):
        raise HandoffRefused("owner_acceptance_invalid")
    if ci["state"] == "REPORTED_SUCCESS" and pr is not None:
        if ci["sha"] != pr["head_sha"]:
            raise HandoffRefused("ci_pr_head_mismatch")

    return {
        **root,
        "validation": {
            "status": "VALID_SHAPE_ONLY",
            "source_claims": "UNVERIFIED",
            "execution_authorized": False,
            "release_authorized": False,
            "ready_to_close": False,
            "next_step": "RECHECK_CANONICAL_GITHUB_AND_AUTHORIZED_RUNTIME",
        },
    }


def validate_json(raw: bytes) -> dict[str, object]:
    if type(raw) is not bytes or len(raw) > MAX_PACKET_BYTES:
        raise HandoffRefused("packet_oversize_or_invalid")
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except (ValueError, UnicodeError):
        raise HandoffRefused("json_invalid") from None
    return validate(data)
