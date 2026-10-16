"""Strict offline GitHub MCP request gate for QA Advisor experiments.

This is *not* an MCP client nor a resident agent tool. Transport is provided
by tests only. Production isolation and authorization are deliberately absent.
"""
from __future__ import annotations

import json
# No imports of networking packages or configurable execution backends.
from copy import deepcopy
from typing import Any

OWNER = "MikeMoore1337"
REPO = "hermes"
WORKFLOW_ID = "381262090"
ALLOWED_TOOLS = frozenset({"actions_list", "issue_read", "pull_request_read"})
MAX_PAYLOAD_BYTES = 65_536
MAX_ITEMS = 3
VALID_RUN_STATUS = frozenset({
    "completed", "in_progress", "queued", "pending", "waiting", "requested",
})
VALID_CONCLUSIONS = frozenset({
    None, "success", "failure", "cancelled", "timed_out", "action_required",
    "neutral", "skipped", "stale", "startup_failure",
})


class McpPreflightDenied(ValueError):
    """Fixed-code denial without revealing any raw untrusted text."""


class OfflineFixtureTransport:
    """Exact local fixture only; not a configurable network/MCP transport."""

    def __init__(self, responses: dict[str, object]) -> None:
        if type(responses) is not dict:
            raise McpPreflightDenied("invalid_mock_fixtures")
        self._responses = deepcopy(responses)
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def __call__(self, tool: str, args: dict[str, Any]) -> object:
        self.calls.append((tool, deepcopy(args)))
        if tool not in self._responses:
            raise McpPreflightDenied("missing_offline_fixture")
        return deepcopy(self._responses[tool])


def actions_ci_request() -> dict[str, object]:
    """One workflow, main only, at most 3 records."""
    return {
        "method": "list_workflow_runs", "owner": OWNER, "repo": REPO,
        "resource_id": WORKFLOW_ID, "page": 1, "perPage": MAX_ITEMS,
        "workflow_runs_filter": {"branch": "main"},
    }


def issue_request(number: int) -> dict[str, object]:
    if type(number) is not int or not 1 <= number <= 1_000_000:
        raise McpPreflightDenied("invalid_issue_number")
    return {"method": "get", "owner": OWNER, "repo": REPO,
            "issue_number": number}


def pr_status_request(number: int) -> dict[str, object]:
    if type(number) is not int or not 1 <= number <= 1_000_000:
        raise McpPreflightDenied("invalid_pr_number")
    return {"method": "get_status", "owner": OWNER, "repo": REPO,
            "pullNumber": number}


def _validate(tool: object, args: object) -> dict[str, Any]:
    if type(tool) is not str or tool not in ALLOWED_TOOLS:
        raise McpPreflightDenied("tool_denied")
    if type(args) is not dict:
        raise McpPreflightDenied("invalid_arguments")
    if tool == "actions_list":
        if args != actions_ci_request() or type(args.get("page")) is not int or (
            type(args.get("perPage")) is not int
        ) or type(args.get("workflow_runs_filter")) is not dict:
            raise McpPreflightDenied("arguments_denied")
    elif tool == "issue_read":
        if set(args) != {"method", "owner", "repo", "issue_number"}:
            raise McpPreflightDenied("arguments_denied")
        if args != issue_request(args["issue_number"]):
            raise McpPreflightDenied("arguments_denied")
    elif tool == "pull_request_read":
        if set(args) != {"method", "owner", "repo", "pullNumber"}:
            raise McpPreflightDenied("arguments_denied")
        if args != pr_status_request(args["pullNumber"]):
            raise McpPreflightDenied("arguments_denied")
    return deepcopy(args)


def _safe_positive_int(raw: object) -> int:
    if type(raw) is not int or raw <= 0:
        raise McpPreflightDenied("invalid_source_payload")
    return raw


def _normalize(tool: str, args: dict[str, Any], raw: object) -> dict[str, Any]:
    if type(raw) is not dict:
        raise McpPreflightDenied("invalid_source_payload")
    try:
        encoded = json.dumps(raw, ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, UnicodeError, OverflowError, RecursionError):
        raise McpPreflightDenied("invalid_source_payload") from None
    if len(encoded) > MAX_PAYLOAD_BYTES:
        raise McpPreflightDenied("oversized_source_payload")
    if tool == "actions_list":
        runs = raw.get("workflow_runs")
        if type(runs) is not list or len(runs) > MAX_ITEMS:
            raise McpPreflightDenied("invalid_source_payload")
        items = []
        for item in runs:
            if type(item) is not dict or item.get("workflow_id") != int(WORKFLOW_ID):
                raise McpPreflightDenied("unexpected_workflow")
            if item.get("head_branch") != "main":
                raise McpPreflightDenied("unexpected_branch")
            ident = _safe_positive_int(item.get("id"))
            status, conclusion = item.get("status"), item.get("conclusion")
            if (type(status) is not str or status not in VALID_RUN_STATUS or
                    (conclusion is not None and
                     (type(conclusion) is not str or conclusion not in VALID_CONCLUSIONS))):
                raise McpPreflightDenied("invalid_source_status")
            if status != "completed" and conclusion is not None:
                raise McpPreflightDenied("invalid_source_status")
            items.append({"run_id": ident, "status": status, "conclusion": conclusion})
        if len({item["run_id"] for item in items}) != len(items):
            raise McpPreflightDenied("duplicate_run")
        items.sort(key=lambda x: x["run_id"], reverse=True)
        return {"kind": "ci_snapshot", "runs": items}
    if tool == "issue_read":
        number, state = raw.get("number"), raw.get("state")
        if (type(number) is not int or number != args["issue_number"] or
                type(state) is not str or state not in {"open", "closed"}):
            raise McpPreflightDenied("unexpected_issue")
        return {"kind": "issue_state", "number": _safe_positive_int(number),
                "state": state}
    state = raw.get("state")
    if type(state) is not str or state not in {"success", "failure", "pending", "unknown"}:
        raise McpPreflightDenied("invalid_pr_status")
    return {"kind": "pr_status", "number": args["pullNumber"], "state": state}


def review_mock_call(
    tool: str, arguments: dict[str, Any],
    transport: OfflineFixtureTransport,
) -> dict[str, Any]:
    """Only accepts built-in fixture transport; never connects to MCP/network."""
    if type(transport) is not OfflineFixtureTransport:
        raise McpPreflightDenied("mock_transport_required")
    checked = _validate(tool, arguments)
    try:
        raw = transport(tool, checked)
    except Exception:
        raise McpPreflightDenied("mock_transport_failure") from None
    safe = _normalize(tool, checked, raw)
    return {
        "status": "MOCK_ONLY",
        "tool": tool,
        "result": safe,
        "remote_mcp_called": False,
        "credential_used": False,
        "live_authorization_verified": False,
        "production_enabled": False,
    }
