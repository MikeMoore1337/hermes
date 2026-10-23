"""Owner-approved native Windows folder policy (#454/#455).

Pure policy does not expose files, mount paths, approve commands or authorize
MCP requests. Native OS-enforced read transport is not yet activated.
"""
from __future__ import annotations

from dataclasses import dataclass
import ntpath
import re

# Exact owner-approved directories; no D: drive or parent workspace grant.
READ_ROOTS: dict[str, str] = {
    "ai-development-toolkit": r"D:\Pet-projects\ai-development-toolkit",
    "hermes": r"D:\Pet-projects\hermes",
    "second-brain": r"D:\Pet-projects\second-brain-workspace\second-brain",
    "your-fitness-coach": r"D:\Pet-projects\your-fitness-coach",
}
APPROVAL_ACTIONS = frozenset({"write", "create", "delete", "rename", "execute"})
READ_ACTIONS = frozenset({"read", "list", "stat"})
BLOCKED_PARTS = frozenset({
    ".ssh", ".aws", ".gnupg", ".kube", ".terraform",
    "vault", ".vault", "private-vault", ".secrets", "secrets",
    "credentials", ".env", ".env.local", ".env.production",
})
BLOCKED_SUFFIXES = (".pem", ".key", ".pfx", ".p12", ".kdbx")
_ROOT = re.compile(r"^[A-Za-z]:\\")


@dataclass(frozen=True)
class PermissionDecision:
    """Classification only, never a bearer grant or proof of host access."""
    status: str
    project: str | None
    action: str
    reason: str
    transport_ready: bool = False


def _valid_path(text: str) -> bool:
    if not isinstance(text, str) or len(text) > 1024 or not _ROOT.match(text):
        return False
    if "\x00" in text or "/" in text or any(ord(c) < 32 for c in text):
        return False
    components = text[3:].split("\\")
    if not components or any(
        not c or c in {".", ".."} or c.endswith((" ", "."))
        or ":" in c or c.lower() in {"con", "prn", "aux", "nul"}
        for c in components
    ):
        return False
    return True


def classify_native_request(path: str, action: str) -> PermissionDecision:
    """Owner-intent check, NOT an OS security boundary.

    Read policy approval does not imply a working native read transport.
    Write and execute remain approval-gated for every concrete action.
    No caller-supplied boolean can turn this policy into an authorization.
    """
    if not isinstance(action, str) or action not in READ_ACTIONS | APPROVAL_ACTIONS:
        return PermissionDecision("denied", None, str(action), "unknown_operation")
    if not _valid_path(path):
        return PermissionDecision("denied", None, action, "unsafe_windows_path")

    normalized = ntpath.normcase(path)
    project = next((key for key, root in READ_ROOTS.items()
                    if normalized == ntpath.normcase(root) or
                    normalized.startswith(ntpath.normcase(root) + "\\")), None)
    if project is None:
        return PermissionDecision("denied", None, action, "outside_approved_roots")
    relative = path[len(READ_ROOTS[project]):].lstrip("\\")
    if relative:
        components = tuple(p.casefold() for p in relative.split("\\"))
        last = components[-1]
        if any(p in BLOCKED_PARTS or p.startswith(".env.") for p in components) or (
                last.endswith(BLOCKED_SUFFIXES)):
            return PermissionDecision("denied", project, action, "private_path_excluded")
    if action in APPROVAL_ACTIONS:
        return PermissionDecision("owner_approval_required", project, action,
                                  "describe_exact_change_or_command_before_owner_approval")
    return PermissionDecision("read_policy_approved", project, action,
                              "host_read_broker_not_installed_or_verified")


def has_native_windows_access() -> bool:
    """No host bridge is activated by this source-only contract."""
    return False
