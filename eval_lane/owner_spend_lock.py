"""Owner-controlled hard stop for all billable Hermes Skill Evals execution.

Owner declined ANY incremental spending on 2026-10-18. This is a source-level
interlock, not a CLI flag, environment variable, grant, or job-field setting.
It intentionally requires a future reviewed code change AND separate explicit
owner permission before any real model process can be enabled.

Synthetic offline contract/replay tests do NOT use this function to invoke
anything: their mocked callbacks do not reach subprocess execution.
"""
from __future__ import annotations

from .protocol import AdmissionDenied


OWNER_REAL_AGENT_EXECUTION_LOCKED = True


def assert_owner_real_execution_allowed() -> None:
    """Fail closed before subprocess planning, process creation or spending."""
    if OWNER_REAL_AGENT_EXECUTION_LOCKED:
        raise AdmissionDenied("owner_zero_incremental_spend_execution_frozen")
