"""H-04: offline, lossy CI diagnostic signals for human review.

Raw job logs must never be returned, stored, interpolated into Telegram, or
used as proof of root cause. Only bounded fixed category identifiers escape.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

MAX_LOG_BYTES = 65_536

INDICATORS = (
    ("quota_or_rate_limit", re.compile(r"(?<![0-9])429(?![0-9])|rate.limit(?:ed|ing)?|quota.exceed(?:ed)?", re.I)),
    ("access_or_credential_failure", re.compile(r"(?<![0-9])(?:401|403)(?![0-9])|permission.denied|authenticat(?:ion|e).fail", re.I)),
    ("transient_network", re.compile(r"timed.out|timeout|connection.reset|name.or.service.not.known|dns.failure", re.I)),
    ("test_assertion", re.compile(r"\bAssertionError\b|\bFAILED\s+tests?/|\bpytest\b.{0,32}\bfailed\b", re.I)),
    ("deployment", re.compile(r"deployment.failed|deploy(?:ment)?\s+failed|rollback.failed", re.I)),
)
NO_LOGS = "logs_not_provided"
UNKNOWN = "insufficient_evidence"
UNTRUSTED = "untrusted_log_cannot_prove_root_cause"


class EvidenceRefused(ValueError):
    """All exception text is a fixed non-sensitive code."""


@dataclass(frozen=True)
class CIHypotheses:
    possible_causes: tuple[str, ...]
    evidence_strength: str
    source: str

    def public(self) -> dict[str, object]:
        return {
            "possible_causes": list(self.possible_causes),
            "evidence_strength": self.evidence_strength,
            "source": self.source,
            "verified_root_cause": False,
            "raw_log_retained": False,
            "requires_human_review": True,
        }


def summarize_log(log: object) -> dict[str, object]:
    """Map a single untrusted log fragment to fixed codes; never echo text.

    This function does not fetch logs, and processing them locally is not
    authorization to ingest private YFC logs or collect PII.
    """
    if log is None:
        return CIHypotheses((), NO_LOGS, "offline_only").public()
    if type(log) is not str:
        raise EvidenceRefused("log_type_invalid")
    if len(log.encode("utf-8")) > MAX_LOG_BYTES:
        raise EvidenceRefused("log_oversize")
    if "\x00" in log:
        raise EvidenceRefused("log_binary_denied")
    # Strip ANSI escape sequences before matching fixed indicators. No raw text
    # or matched groups are EVER exposed to caller.
    cleaned = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", log)
    codes = tuple(code for code, pattern in INDICATORS if pattern.search(cleaned))
    return CIHypotheses(codes, UNTRUSTED if codes else UNKNOWN, "offline_only").public()


def scenario_review(
    *,
    run_conclusion: str,
    sanitized_log: object = None,
    observed_provider_status: int | None = None,
    same_commit_other_run_success: bool = False,
) -> dict[str, object]:
    """Separate reproducible CI facts from hypotheses; do not assert flaky."""
    if run_conclusion not in ("success", "failure", "timed_out", "cancelled"):
        raise EvidenceRefused("conclusion_invalid")
    if (observed_provider_status is not None and
            (type(observed_provider_status) is not int or
             observed_provider_status not in (401, 402, 403, 408, 429, 500, 502, 503, 504))):
        raise EvidenceRefused("provider_status_invalid")
    if type(same_commit_other_run_success) is not bool:
        raise EvidenceRefused("repeatability_invalid")
    evidence = summarize_log(sanitized_log)
    causes = set(evidence["possible_causes"])
    if observed_provider_status == 429:
        causes.add("quota_or_rate_limit")
    elif observed_provider_status in (401, 402, 403):
        causes.add("access_or_credential_failure")
    elif observed_provider_status in (408, 500, 502, 503, 504):
        causes.add("transient_network")
    signals = tuple(sorted(causes))
    status = ("NO_INCIDENT_EVIDENCE" if run_conclusion == "success" else "REVIEW_REQUIRED")
    return {
        "status": status,
        "observed_run_conclusion": run_conclusion,
        "observed_provider_status": observed_provider_status,
        "diagnostic_hypotheses": list(signals) if status != "NO_INCIDENT_EVIDENCE" else [],
        "repeatability_signal": (
            "same_commit_success_and_failure_check_environment"
            if run_conclusion == "failure" and same_commit_other_run_success
            else "unknown"
        ),
        "verified_root_cause": False,
        "action": "inspect_sanitized_logs_manually" if status == "REVIEW_REQUIRED"
                  else "none",
        "raw_log_retained": False,
        "no_automatic_retry": True,
    }
