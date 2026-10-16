"""Yandex Wordstat via Search API v2: OFFLINE spec and cost estimate only.

No endpoint is contacted, no OAuth / API keys are read. This module MUST
NOT be used as a sending client. All access is blocked until the owner's
separate provider, billing and read-only egress admission is proven.
"""
from __future__ import annotations

import json
from decimal import Decimal
from types import MappingProxyType

API_HOST = "searchapi.api.cloud.yandex.net"
API_PREFIX = "https://" + API_HOST + "/v2/wordstat/"
DOCS_DATE = "2026-10-16"
PRICING_URL = "https://aistudio.yandex.ru/ru/docs/search-api/pricing"
AUTH_DOC_URL = "https://aistudio.yandex.ru/ru/docs/search-api/operations/wordstat-gettop"
PRICE_RUB_PER_1000 = MappingProxyType({
    "GetTop": Decimal("20"),
    "GetDynamics": Decimal("20"),
    "GetRegionsDistribution": Decimal("50"),
    "GetRegionsTree": Decimal("0"),
})
PATHS = MappingProxyType({
    "GetTop": "topRequests",
    "GetDynamics": "dynamics",
    "GetRegionsDistribution": "regions",
    "GetRegionsTree": "getRegionsTree",
})


class WordstatDenied(ValueError):
    """Stable error code, never echo keyword, OAuth or API key."""


def catalog() -> dict[str, object]:
    return {
        "schema": "hermes-h12-wordstat-v2-offline-v1",
        "status": "PROVIDER_ADMISSION_BLOCKED",
        "service": "Yandex AI Studio / Yandex Search API Wordstat v2",
        "docs_as_of": DOCS_DATE,
        "official_pricing_url": PRICING_URL,
        "official_auth_url": AUTH_DOC_URL,
        "api_host": API_HOST,
        "http_method": "POST",
        "methods": dict(sorted((name, {
            "path": API_PREFIX + PATHS[name],
            "reference_rub_per_1000": str(price),
            "charged_calls_authorized": False,
        }) for name, price in PRICE_RUB_PER_1000.items())),
        "requires_provider_role": "search-api.webSearch.user",
        "required_scope": "yc.search-api.execute",
        "provider_access_verified": False,
        "billing_hard_limit_verified": False,
        "daily_spend_cap_rub": "0",
        "automatic_retries": False,
        "paid_requests_enabled": False,
        "free_requests_enabled": False,
        "credentials_loaded": False,
        "any_request_executed": False,
        "yfc_write_enabled": False,
        "publication_enabled": False,
    }


def reference_estimate(method: str, calls: int) -> dict[str, object]:
    """Reference arithmetic only; NOT a verified account rate or budget."""
    if type(method) is not str or method not in PRICE_RUB_PER_1000:
        raise WordstatDenied("method_not_admitted")
    if type(calls) is not int or not 0 <= calls <= 100_000:
        raise WordstatDenied("call_count_invalid")
    estimate = PRICE_RUB_PER_1000[method] * Decimal(calls) / Decimal(1000)
    return {
        "status": "DRY_RUN_PRICE_REFERENCE_ONLY",
        "docs_as_of": DOCS_DATE,
        "method": method,
        "estimated_calls": calls,
        "reference_cost_rub": format(estimate, "f"),
        "provider_account_cost_confirmed": False,
        "provider_daily_quota_confirmed": False,
        "provider_billing_disabled_confirmed": False,
        "request_sent": False,
        "credentials_loaded": False,
        "billing_enabled": False,
        "daily_spend_cap_rub": "0",
    }


def main() -> int:
    """No CLI switches, secrets, phrase echoing, or network access."""
    print(json.dumps(catalog(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
