"""Owner-invoked one-shot Yandex -> existing H-12 in-memory handoff.

No cron, new OAuth, files, paid APIs or publication. The operator must
separately authorize each live run and verify pinned installed source/host.
Only a fixed sanitized receipt reaches stdout, never private query text.
"""
from __future__ import annotations

import argparse
import json
import re
from datetime import date
from typing import Any, Callable

from marketing.yandex_webmaster_direct import (
    YandexLiveDenied, YandexReadDiagnosticDenied, _safe_read_diagnostic_reason,
    collect, read_private_token, summarized_receipt,
)
from marketing.yandex_webmaster_h12 import (
    YandexH12Denied, build_h12_observed_batch, summarized_h12_batch,
)

RECEIPT_SCHEMA = "hermes-h397-yandex-h12-one-shot-receipt-v1"
H12_REFUSALS = frozenset({
    "H12_READ_EVIDENCE_INVALID", "H12_PROVENANCE_INVALID",
    "H12_SITE_GAP_INVALID", "H12_OBSERVATIONS_INVALID",
    "H12_QUERY_NOT_OBSERVED", "H12_PACKET_REJECTED",
    "H12_PRIVILEGE_PROMOTION_DENIED", "H12_NO_OBSERVED_QUERIES",
    "H12_BATCH_RECEIPT_INVALID", "H12_RECEIPT_INVALID",
})


def execute_one_shot(
    *, as_of: date, token: str,
    transport: Callable[[str, str], bytes] | None = None,
) -> dict[str, Any]:
    """The only network step is existing bounded collect (<=6 GET).

    Then build existing #64 packets from *observed* Yandex queries in memory,
    keeping site_gap=None as explicitly NOT_ASSESSED. No real page gap is
    invented, and no query or numerical metric is printed.
    """
    report = collect(
        as_of=as_of, token=token, transport=transport, diagnostic=True,
    )
    read = summarized_receipt(report)
    observations = report["data"]["seo_research_input_observations"]
    if (type(observations) is not list
            or len(observations) != read["query_rows"]):
        raise YandexH12Denied("H12_OBSERVATIONS_INVALID")

    if observations:
        batch = build_h12_observed_batch(report, as_of=as_of)
        receipt = summarized_h12_batch(batch)
        if receipt["h12_observation_count"] != len(observations):
            raise YandexH12Denied("H12_BATCH_RECEIPT_INVALID")
        count = receipt["h12_packet_count"]
        status = ("LIVE_H12_IN_MEMORY_UNATTESTED"
                  if report["status"] == "LIVE_GET_RESPONSE_UNATTESTED"
                  else "SYNTHETIC_H12_IN_MEMORY_UNATTESTED")
    else:
        # Zero returned rows means unavailable observations, NOT 0 impressions.
        count = 0
        status = ("LIVE_NO_OBSERVED_QUERIES"
                  if report["status"] == "LIVE_GET_RESPONSE_UNATTESTED"
                  else "SYNTHETIC_NO_OBSERVED_QUERIES")

    return {
        "schema": RECEIPT_SCHEMA,
        "status": status,
        "source_read_status": read["status"],
        "source_provenance": read["source_provenance"],
        "period_start": read["period_start"],
        "period_end": read["period_end"],
        "request_count": read["request_count"],
        "request_limit": 6,
        "observed_query_rows": len(observations),
        "h12_packet_schema": "hermes-h12-seo-research-packet-v1",
        "h12_packet_count": count,
        "h12_packet_status": "NO_DATA",
        "h12_evidence_kind": "NO_CONFIRMED_DEMAND",
        "site_gap_assessed": False,
        "indexing_available": read["indexing_available"],
        "sitemaps": read["sitemaps"],
        "independent_provider_attestation": False,
        "history_persisted": False,
        "publication_allowed": False,
        "yfc_write_allowed": False,
        "handoff_extra_gets": 0,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Owner-gated Yandex to H-12 in-memory, <=6 GET, no writes",
    )
    parser.add_argument("--date", required=True)
    parser.add_argument("--execute-read", action="store_true")
    parser.add_argument("--token-file")
    args = parser.parse_args(argv)
    try:
        if (type(args.date) is not str
                or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", args.date)):
            raise YandexH12Denied("DATE_INVALID")
        try:
            as_of = date.fromisoformat(args.date)
        except ValueError:
            raise YandexH12Denied("DATE_INVALID") from None
        if not args.execute_read:
            output = {
                "status": "NOT_EXECUTED", "request_limit": 6,
                "publication_allowed": False, "h12_handoff": "NOT_EXECUTED",
            }
        else:
            if args.token_file is None:
                raise YandexH12Denied("TOKEN_FILE_REQUIRED")
            token = read_private_token(args.token_file)
            output = execute_one_shot(as_of=as_of, token=token)
        code = 0
    except YandexReadDiagnosticDenied as exc:
        output = {
            "status": "REFUSED", "stage": (
                exc.stage if exc.stage in {
                    "USER", "HOSTS", "PLAN", "POPULAR", "POPULAR_DATA",
                    "ALL_HISTORY", "ALL_HISTORY_DATA", "INDEXING",
                    "INDEXING_DATA", "SITEMAPS", "SITEMAPS_DATA",
                    "NORMALIZE", "SEO_PACKET",
                } else "READ"
            ),
            "reason": _safe_read_diagnostic_reason(exc),
            "requests_attempted": exc.requests_attempted,
            "request_limit": 6, "publication_allowed": False,
        }
        code = 2
    except YandexLiveDenied as exc:
        output = {
            "status": "REFUSED", "stage": "PREFLIGHT",
            "reason": _safe_read_diagnostic_reason(exc),
            "requests_attempted": 0, "request_limit": 6,
            "publication_allowed": False,
        }
        code = 2
    except YandexH12Denied as exc:
        reason = exc.args[0] if len(exc.args) == 1 else None
        safe = (reason if type(reason) is str and
                reason in H12_REFUSALS | {"DATE_INVALID", "TOKEN_FILE_REQUIRED"}
                else "H12_HANDOFF_REFUSED")
        output = {
            "status": "REFUSED",
            "stage": ("PREFLIGHT" if safe in
                      {"DATE_INVALID", "TOKEN_FILE_REQUIRED"}
                      else "H12_HANDOFF"),
            "reason": safe,
            "requests_attempted": 0 if safe in
            {"DATE_INVALID", "TOKEN_FILE_REQUIRED"} else 6,
            "request_limit": 6,
            "publication_allowed": False,
        }
        code = 2
    except Exception:
        # Prevent traceback, provider body, query text, UID and token leaks.
        output = {
            "status": "REFUSED", "stage": "INTERNAL",
            "reason": "H12_INTERNAL_REFUSED", "request_limit": 6,
            "publication_allowed": False,
        }
        code = 2

    print(json.dumps(output, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
