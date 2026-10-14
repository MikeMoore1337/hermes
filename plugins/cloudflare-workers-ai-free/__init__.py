"""Free-only Cloudflare Workers AI model provider for pinned Hermes Agent.

Adapted from AhmetArif0/hermes-cloudflare-workers-ai-provider,
commit f6821d058d504ee6324b0d3217564b93124c09f9 (MIT license).
This derivative intentionally exposes ONE free-plan model and no paid fallback.
"""

from __future__ import annotations

from typing import Any

from providers import register_provider
from providers.base import ProviderProfile

MODEL = "@cf/openai/gpt-oss-20b"
API_TOKEN_ENV = "CLOUDFLARE_WORKERS_AI_API_TOKEN"
BASE_URL_ENV = "CLOUDFLARE_WORKERS_AI_BASE_URL"
REASONING_LEVELS = ("low", "medium", "high")


def reasoning_effort_for(model: str | None, reasoning_config: Any) -> str | None:
    """Map only approved model reasoning levels; reject unapproved models."""
    if model != MODEL:
        raise ValueError("unapproved_cloudflare_model")
    if not isinstance(reasoning_config, dict):
        return None
    if reasoning_config.get("enabled") is False:
        return "low"
    requested = str(reasoning_config.get("effort") or "").strip().lower()
    if requested in ("none", "minimal"):
        return "low"
    if requested in REASONING_LEVELS:
        return requested
    if requested in ("xhigh", "max", "ultra"):
        return "high"
    return None


def classify_api_error(
    error: Any, *, status_code: Any = None, message: Any = "", **_: Any
) -> dict[str, Any]:
    """Fail closed for ANY provider failure, without another billable attempt.

    Cloudflare 3036 (daily free quota) and 3040 (out of capacity) both
    surface as HTTP 429. The error message is untrusted and never reflected.
    Without a verified Free-plan account, this profile alone cannot promise
    that a provider-side Paid billing configuration was not enabled.
    """
    if type(status_code) is int and status_code == 401:
        code = "cloudflare_auth_denied"
    elif type(status_code) is int and status_code in (402, 403):
        code = "cloudflare_access_or_billing_denied"
    elif type(status_code) is int and status_code == 429:
        code = "cloudflare_free_quota_or_capacity_exceeded"
    elif type(status_code) is int and status_code in (408, 500, 502, 503, 504):
        code = "cloudflare_temporary_unavailable"
    else:
        code = "cloudflare_provider_error"
    return {"reason": code, "retryable": False, "should_fallback": False}


class WorkersAIFreeProfile(ProviderProfile):
    """Strictly free-plan GPT-OSS 20B, with no third-party tools or subprocesses."""

    def build_api_kwargs_extras(
        self, *, reasoning_config: dict | None = None, **context: Any
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        effort = reasoning_effort_for(context.get("model"), reasoning_config)
        return {}, ({"reasoning_effort": effort} if effort else {})

    def get_model_context_length(self, model: str) -> int | None:
        return 128_000 if model == MODEL else None


workers_ai = WorkersAIFreeProfile(
    name="workers-ai",
    display_name="Cloudflare Workers AI (free only)",
    description="Only the free-plan Cloudflare GPT-OSS 20B; no paid fallbacks",
    signup_url="https://dash.cloudflare.com/?to=/:account/ai/workers-ai",
    env_vars=(API_TOKEN_ENV, BASE_URL_ENV),
    base_url="",
    auth_type="api_key",
    supports_model_listing=False,
    supports_health_check=False,
    default_aux_model=MODEL,
    fallback_models=(MODEL,),
    model_capabilities={
        MODEL: {
            "supports_tools": True,
            "supports_vision": False,
            "supports_reasoning": True,
            "context_window": 128_000,
        },
    },
    classify_api_error=classify_api_error,
)
register_provider(workers_ai)
