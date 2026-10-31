"""Hermes #397 -> #64: bounded in-memory SEO packet handoff.

Does not read OAuth credentials, call an API, persist query strings, publish,
or promote a live HTTPS response into independent provider attestation.
The existing H-12 research packet remains the sole SEO packet contract.
"""
from __future__ import annotations

from datetime import date
from typing import Any

from marketing.seo_research import (
    INPUT_SCHEMA as H12_INPUT_SCHEMA,
    OUTPUT_SCHEMA as H12_OUTPUT_SCHEMA,
    SeoResearchDenied,
    build_packet,
)
from marketing.yandex_webmaster import HOST, OUTPUT_SCHEMA as YANDEX_OUTPUT_SCHEMA

HANDOFF_SCHEMA = "hermes-h24-yandex-h12-in-memory-handoff-v1"
READ_SCHEMA = "hermes-h24-yandex-read-probe-v1"
ALLOWED_READ_STATUSES = frozenset({
    "LIVE_GET_RESPONSE_UNATTESTED",
    "SYNTHETIC_TRANSPORT_CHECK",
})
CANONICAL_SITES = frozenset({
    "https://your-fitness-coach.ru",
    "https://your-fitness-coach.ru/",
})


class YandexH12Denied(ValueError):
    """Fixed error codes only: never include a query, token or source value."""


def build_h12_handoff(
    read_result: Any, *, as_of: date,
    selected_query: str, site_gap: dict[str, Any] | None,
) -> dict[str, Any]:
    """Build a #64 packet from an existing bounded H-24 report.

    None explicitly means no verified Statejnik gap is available.
    In that case the query MUST be present in the provider's observations;
    #64 returns NO_DATA (or HOLD), never invented coverage or editor READY.
    No HTTP, filesystem writes, owner/provider attestation, or publishing.
    """
    if (type(as_of) is not date or type(read_result) is not dict
            or read_result.get("schema") != READ_SCHEMA
            or read_result.get("status") not in ALLOWED_READ_STATUSES
            or read_result.get("source") != "yandex_webmaster"
            or read_result.get("host_id") != HOST
            or type(read_result.get("requests")) is not int
            or read_result["requests"] != 6
            or type(read_result.get("retries")) is not int
            or read_result["retries"] != 0
            or read_result.get("external_publication_allowed") is not False
            or read_result.get("paid_api_allowed") is not False
            or read_result.get("seo_changes_applied") != 0
            or read_result.get("sitemap_mutations") != 0):
        raise YandexH12Denied("H12_READ_EVIDENCE_INVALID")

    data = read_result.get("data")
    if (type(data) is not dict
            or data.get("schema") != YANDEX_OUTPUT_SCHEMA
            or data.get("status") != "OFFLINE_SOURCE_NOT_PROVIDER_VERIFIED"
            or data.get("source") != "yandex_webmaster"
            or data.get("source_type") != "owner_export"
            or data.get("owner_attested") is not False
            or data.get("authorization_verified") is not False
            or data.get("publication_allowed") is not False
            or data.get("mutations_allowed") is not False
            or data.get("paid_api_used") is not False
            or data.get("observed_at") != str(as_of)
            or data.get("requested_period") != [
                read_result.get("period_start"), read_result.get("period_end"),
            ]):
        raise YandexH12Denied("H12_PROVENANCE_INVALID")

    # A real Statejnik result is accepted as before. An explicit None means
    # no site coverage assessment was performed; never invent a gap.
    if site_gap is not None and (
        type(site_gap) is not dict
        or site_gap.get("site") not in CANONICAL_SITES
    ):
        raise YandexH12Denied("H12_SITE_GAP_INVALID")
    observations = data.get("seo_research_input_observations")
    digest = data.get("evidence_sha256")
    if (type(digest) is not str or len(digest) != 64
            or any(c not in "0123456789abcdef" for c in digest)
            or type(observations) is not list or len(observations) > 50):
        raise YandexH12Denied("H12_OBSERVATIONS_INVALID")
    for row in observations:
        if (type(row) is not dict
                or row.get("source") != "yandex_webmaster"
                or row.get("source_type") != "owner_export"
                or row.get("owner_attested") is not False
                or row.get("evidence_sha256") != digest):
            raise YandexH12Denied("H12_OBSERVATIONS_INVALID")

    if site_gap is None and (
        type(selected_query) is not str
        or not any(
            type(row.get("query")) is str
            and row["query"].casefold() == selected_query.casefold()
            for row in observations
        )
    ):
        raise YandexH12Denied("H12_QUERY_NOT_OBSERVED")

    try:
        packet = build_packet({
            "schema": H12_INPUT_SCHEMA,
            "theme": "market_research",
            "research_item": None,
            "site_gap": site_gap,
            "observations": observations,
            "selected_query": selected_query,
            "as_of": str(as_of),
        })
    except (SeoResearchDenied, ValueError, TypeError, KeyError):
        raise YandexH12Denied("H12_PACKET_REJECTED") from None

    if (packet.get("schema") != H12_OUTPUT_SCHEMA
            or packet.get("publication_allowed") is not False
            or packet.get("yfc_write_allowed") is not False
            or packet.get("outbound_messages_allowed") is not False
            or packet.get("paid_api_used") is not False
            or packet.get("evidence_kind") != "NO_CONFIRMED_DEMAND"
            or packet.get("status") not in {"HOLD", "NO_DATA"}):
        raise YandexH12Denied("H12_PRIVILEGE_PROMOTION_DENIED")
    if any(
        row.get("data_quality") != "OWNER_EXPORT_UNVERIFIED"
        for row in packet["observations"]
    ):
        raise YandexH12Denied("H12_PRIVILEGE_PROMOTION_DENIED")
    if site_gap is None and (
        packet.get("site_gap") is not None
        or "SITE_GAP_NOT_ASSESSED" not in packet.get("reasons", ())
        or packet["status"] not in {"HOLD", "NO_DATA"}
        or not packet["observations"]
    ):
        raise YandexH12Denied("H12_PRIVILEGE_PROMOTION_DENIED")

    return {
        "schema": HANDOFF_SCHEMA,
        "status": "IN_MEMORY_H12_PACKET_UNATTESTED",
        "source": "yandex_webmaster",
        "transport_status": read_result["status"],
        "source_provenance": data["status"],
        "packet": packet,
        "publication_allowed": False,
        "yfc_write_allowed": False,
        "provider_gets_during_handoff": 0,
        "filesystem_writes": 0,
    }


BATCH_SCHEMA = "hermes-h24-yandex-h12-in-memory-batch-v1"


def build_h12_observed_batch(
    read_result: Any, *, as_of: date,
) -> dict[str, Any]:
    """Deliver every *actually observed* popular query to existing H-12.

    Query selection is derived from the real normalized observations, never
    from an invented gap or text supplied by this adapter. All packets stay
    private in memory. Site coverage is explicitly NOT_ASSESSED.
    """
    data = read_result.get("data") if type(read_result) is dict else None
    rows = data.get("seo_research_input_observations") if type(data) is dict else None
    if type(rows) is not list or not 1 <= len(rows) <= 50:
        raise YandexH12Denied("H12_NO_OBSERVED_QUERIES")

    handoffs = []
    for row in rows:
        if type(row) is not dict or type(row.get("query")) is not str:
            raise YandexH12Denied("H12_OBSERVATIONS_INVALID")
        handoff = build_h12_handoff(
            read_result, as_of=as_of, selected_query=row["query"],
            site_gap=None,
        )
        packet = handoff["packet"]
        if (len(packet["observations"]) != 1
                or packet["observations"][0]["query"] != row["query"]
                or packet["site_gap"] is not None
                or packet["status"] != "NO_DATA"
                or packet["evidence_kind"] != "NO_CONFIRMED_DEMAND"):
            raise YandexH12Denied("H12_PRIVILEGE_PROMOTION_DENIED")
        handoffs.append(handoff)

    return {
        "schema": BATCH_SCHEMA,
        "status": "IN_MEMORY_H12_BATCH_UNATTESTED",
        "source_transport": read_result["status"],
        "source_provenance": data["status"],
        "handoffs": handoffs,
        "site_gap_assessed": False,
        "publication_allowed": False,
        "yfc_write_allowed": False,
        "provider_gets_during_handoff": 0,
        "filesystem_writes": 0,
    }


def summarized_h12_batch(batch: Any) -> dict[str, Any]:
    """Return only predefined metadata, never queries, numbers or packet text."""
    if (type(batch) is not dict
            or batch.get("schema") != BATCH_SCHEMA
            or batch.get("status") != "IN_MEMORY_H12_BATCH_UNATTESTED"
            or batch.get("source_transport") not in ALLOWED_READ_STATUSES
            or batch.get("source_provenance") != "OFFLINE_SOURCE_NOT_PROVIDER_VERIFIED"
            or batch.get("site_gap_assessed") is not False
            or batch.get("publication_allowed") is not False
            or batch.get("yfc_write_allowed") is not False
            or batch.get("provider_gets_during_handoff") != 0
            or batch.get("filesystem_writes") != 0):
        raise YandexH12Denied("H12_BATCH_RECEIPT_INVALID")

    handoffs = batch.get("handoffs")
    if type(handoffs) is not list or not 1 <= len(handoffs) <= 50:
        raise YandexH12Denied("H12_BATCH_RECEIPT_INVALID")
    for entry in handoffs:
        if (type(entry) is not dict
                or entry.get("transport_status") != batch["source_transport"]):
            raise YandexH12Denied("H12_BATCH_RECEIPT_INVALID")
        receipt = summarized_h12_handoff(entry)
        if (receipt["packet_status"] != "NO_DATA"
                or receipt["packet_evidence_kind"] != "NO_CONFIRMED_DEMAND"
                or receipt["matching_observation_count"] != 1):
            raise YandexH12Denied("H12_BATCH_RECEIPT_INVALID")
        if entry["packet"].get("site_gap") is not None:
            raise YandexH12Denied("H12_BATCH_RECEIPT_INVALID")

    return {
        "status": batch["status"],
        "source_transport": batch["source_transport"],
        "source_provenance": batch["source_provenance"],
        "h12_packet_schema": H12_OUTPUT_SCHEMA,
        "h12_packet_count": len(handoffs),
        "h12_observation_count": len(handoffs),
        "h12_evidence_kind": "NO_CONFIRMED_DEMAND",
        "h12_packet_status": "NO_DATA",
        "site_gap_assessed": False,
        "publication_allowed": False,
        "yfc_write_allowed": False,
        "provider_gets_during_handoff": 0,
        "filesystem_writes": 0,
    }


def summarized_h12_handoff(handoff: Any) -> dict[str, Any]:
    """Whitelisted, query-free receipt; full packet stays in caller memory."""
    if (type(handoff) is not dict
            or handoff.get("schema") != HANDOFF_SCHEMA
            or handoff.get("status") != "IN_MEMORY_H12_PACKET_UNATTESTED"
            or handoff.get("source") != "yandex_webmaster"
            or handoff.get("transport_status") not in ALLOWED_READ_STATUSES
            or handoff.get("source_provenance") != "OFFLINE_SOURCE_NOT_PROVIDER_VERIFIED"
            or handoff.get("publication_allowed") is not False
            or handoff.get("yfc_write_allowed") is not False
            or handoff.get("provider_gets_during_handoff") != 0
            or handoff.get("filesystem_writes") != 0):
        raise YandexH12Denied("H12_RECEIPT_INVALID")
    packet = handoff.get("packet")
    if (type(packet) is not dict or packet.get("schema") != H12_OUTPUT_SCHEMA
            or packet.get("evidence_kind") != "NO_CONFIRMED_DEMAND"
            or packet.get("status") not in {"HOLD", "NO_DATA"}
            or packet.get("publication_allowed") is not False
            or type(packet.get("observations")) is not list):
        raise YandexH12Denied("H12_RECEIPT_INVALID")
    return {
        "status": handoff["status"],
        "source_transport": handoff["transport_status"],
        "source_provenance": handoff["source_provenance"],
        "packet_schema": packet["schema"],
        "packet_status": packet["status"],
        "packet_evidence_kind": packet["evidence_kind"],
        "matching_observation_count": len(packet["observations"]),
        "publication_allowed": False,
        "provider_gets_during_handoff": 0,
        "filesystem_writes": 0,
    }
