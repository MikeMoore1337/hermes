"""H-30 FTS5 bounded synthetic CI benchmark, stdout-only.

Observations are environment-specific. No real user data, tokens or secrets.
No latency/RSS claim is inferred from Python-only tracemalloc.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import time
import tracemalloc
from .core import SyntheticIndex, sample, MAX_RECORDS, SCHEMA

NOW = 1792680000
ROW_COUNT = 160
SEARCH_COUNT = 64


def benchmark() -> dict:
    if ROW_COUNT > MAX_RECORDS:
        raise RuntimeError("bench_record_cap")
    tracemalloc.start()
    before = time.perf_counter_ns()
    with SyntheticIndex(now=NOW) as idx:
        for n in range(ROW_COUNT):
            title = (f"Проверка задачи фтс {n}" if n % 2 == 0
                     else f"Release checks synthetic event {n}")
            idx.upsert(sample(f"H-demo-{n+1000:04}", title,
                              now=NOW - n * 70))
        inserted_ns = time.perf_counter_ns() - before
        observed = []
        counts = []
        for n in range(SEARCH_COUNT):
            q = "Проверка задачи" if n % 2 == 0 else "Release checks"
            start = time.perf_counter_ns()
            results = idx.search(q, project_id="hermes", limit=8)
            observed.append(time.perf_counter_ns() - start)
            counts.append(len(results))
        budget = idx.limits()
        count = idx.count()
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    sorted_latency = sorted(observed)
    fingerprint = hashlib.sha256(
        "|".join(f"H-demo-{n+1000:04}" for n in range(ROW_COUNT)).encode()
    ).hexdigest()
    return {
        "schema": "hermes-h30-fts5-benchmark-v1",
        "synthetic_only": True, "records": count, "queries": SEARCH_COUNT,
        "dataset_ids_sha256": fingerprint,
        "insert_total_ms": round(inserted_ns / 1e6, 3),
        "query_p50_ms": round(statistics.median(sorted_latency) / 1e6, 3),
        "query_p95_ms": round(sorted_latency[int((len(sorted_latency)-1)*0.95)]/1e6, 3),
        "results_min": min(counts), "results_max": max(counts),
        "python_alloc_peak_bytes": peak,
        "sqlite_main_page_bytes": budget["sqlite_main_bytes"],
        "process_rss_bytes": None, "cpu_usage_percent": None,
        "real_vps_metrics": "NOT_MEASURED",
        "persistent_disk_bytes": 0,
        "no_model_calls": True, "no_background_service": True,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--format", choices=("short", "json"), default="short")
    args = parser.parse_args()
    try:
        result = benchmark()
    except Exception:
        print("H30_FTS5_BENCH_UNAVAILABLE")
        return 2
    if args.format == "json":
        print(json.dumps(result, sort_keys=True))
    else:
        print(f"H-30 synthetic SQLite FTS5: {result['records']} records; "
              f"{result['queries']} queries; "
              f"p50={result['query_p50_ms']}ms; "
              f"p95={result['query_p95_ms']}ms")
        print(f"SQLite in-memory pages: {result['sqlite_main_page_bytes']} bytes; "
              f"Python allocation peak: {result['python_alloc_peak_bytes']} bytes")
        print("NOT_MEASURED: real VPS CPU/RSS; index production use; source authenticity.")
    return 0 if result["records"] == ROW_COUNT and (
        result["results_min"] > 0 and result["results_max"] <= 8 and
        result["persistent_disk_bytes"] == 0
    ) else 1


if __name__ == "__main__":
    raise SystemExit(main())
