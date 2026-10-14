# Hermes Research Scout - offline evidence gate

Status: **offline core only**, no fetcher, no AI calls, no autonomous reports and
no production deployment. Partial progress for [Issue #4](https://github.com/MikeMoore1337/hermes/issues/4).

This deliberately does not copy code from VIBE-SERCH or other repositories
with unclear licences. Uses Python standard library.

Input consists of untrusted source metadata in a strict schema:
`url`, `title`, `published_at`, `claim_id`, `polarity`,
`summary`. Unknown keys, credentials, redirect targets or opaque data are
rejected. URL allowlist is exact HTTPS host-based and does **not** authorize
fetching: redirects/DNS and effective egress would require a separate hardened
connector with SSRF proof.

What this stage actually does:
- mark secondary vs primary domain (never proof of publication authenticity);
- quarantine stale/future items, suspicious instruction-like content and
  contradictory claim metadata;
- reject duplicate URLs and require independent primary **domains** before
  a claim can reach human review (domain independence is only a heuristic);
- emit bounded link/title/provenance metadata, not source summaries or secrets;
- return `NO_DATA`, `HOLD` or `READY_FOR_REVIEW`, never `verified=true`.

This stage does **not** verify the truth or factual independence of studies.
Even `READY_FOR_REVIEW` is NOT permission to publish to Telegram/YFC,
change a fitness recommendation, send a message or store in Second Brain.

Next gate: owner-approved public source registry, hardened time/size-bounded
fetch, real DOI/PMID/license evidence, direct evidence citations, link checks
and rate limits, at least 20 negative cases, operational budgets and a
bounded approved delivery mechanism. Keep #4 OPEN.


## Матрица негативных случаев (14.10.2026)

[Набор сквозных синтетических проверок](../tests/test_research_safety_matrix.py) покрывает 29 отдельно названных отклонений URL/SSRF, схемы, контрольных символов, дат, правдивости заявлений и внедрённых команд. Дополнительно проверяются многоязычные инструкции, приоритет причины при stale+injection, ложная независимость доменов и противоречия.

CI подтверждает только офлайн-защиту. Актуальность реальных исследований, NCBI registration, общая квота IP и live API остаются в статусе OPEN в [#4](https://github.com/MikeMoore1337/hermes/issues/4). `READY_FOR_REVIEW` и `MANUAL_REVIEW` не означают доказанный научный вывод и не дают разрешения публиковать материалы.
