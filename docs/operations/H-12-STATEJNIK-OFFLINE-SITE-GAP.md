# H-12 / #64 — проверяемый офлайн-аудит SEO-покрытия Statejnik

Дата: 16 октября 2026. Режим **только операторский синтетический offline**.
Statejnik v1.2.0 полностью сохранён в `third_party/statejnik`; изменения
не внесены ни в один upstream-файл или `SKILL.md`.

## Что доступно теперь

Оригинальный `site.py` содержит разные подкоманды: `scan` ходит в
сеть, `gap` сверяет **два готовых локальных JSON** с семантикой и
помечает уже покрытые/сомнительные статьи, коммерческие темы и пробелы.
Ранее runner запрещал **весь** `site.py`, поэтому даже офлайн `gap`
не работал.

Hermes добавил только **отдельную операторскую команду `site-gap`**.
Она вызывает тот же неизменённый `site.py gap`, но не допускает
любых переданных CLI-аргументов. Внутри pinned nonroot/no-network Docker
используется фиксированная последовательность:
`gap site.json keywords.json --out gap.json --plan plan.md --top 25`.
Нельзя переключиться на `scan`, `--allow-private`, альтернативный
`--config`, путь вне выбранной рабочей директории или сетевой клиент.
Оригинальный инструмент `site` остаётся `NETWORK_REQUIRES_SEPARATE_GO`.

## Как воспроизвести без сетевого доступа

На **отдельном тестовом Docker-хосте**, где pinned образ уже в кеше:

```bash
mkdir -m 0700 /path/to/empty-hermes-site-gap
python3 -m statejnik_integration.runner --init-workspace --workspace /path/to/empty-hermes-site-gap
```

После этого в директории создать только `site.json` и
`keywords.json` (два локальных UTF-8 JSON). **Важно:** контейнер
исполняется от UID/GID `65534:65534`, поэтому оператор должен
предоставить этому sandbox-пользователю строго ограниченные ACL
на чтение входов и запись только в выделенную рабочую папку.
На Windows/NTFS `chmod` не эквивалентен Linux ACL: без подходящего
разрешения команда безопасно завершится `offline_sandbox_unavailable`.
В одном воспроизводимом Docker Desktop smoke использовалась широкая
ACL *исключительно на автоматически удаляемую папку с синтетическими
данными*; такой доступ **недопустим для личных файлов** или реального
SEO-корпуса. Не открывать доступ к домашнему каталогу/vault.
Синтетический пример:

```json
{
  "url": "https://example.org",
  "pages": [
    {
      "url": "https://example.org/blog/running",
      "kind": "article",
      "title": "Как выбрать беговые кроссовки",
      "h1": "Выбор беговой обуви"
    }
  ],
  "article_sections": [{"path": "/blog"}],
  "article_urls": ["https://example.org/blog/running"],
  "urls": []
}
```

`keywords.json`:

```json
[
  {
    "phrase": "как выбрать беговые кроссовки",
    "cluster": "беговые кроссовки",
    "count": 0,
    "sources": []
  },
  {
    "phrase": "обувь для первого марафона",
    "sources": []
  }
]
```

Затем только явно:

```bash
python3 -m statejnik_integration.runner --execute --tool site-gap --workspace /path/to/empty-hermes-site-gap
```

Результаты останутся **только** в файлах `gap.json` и
`plan.md` этой директории; в ответе Hermes лишь код успеха/отказа,
без текста статей и пользовательских тем. Это не публикация.
**Повторный запуск без ручного удаления/пересмотра результатов
запрещён**, чтобы не перезаписывать аналитические артефакты.

Границы: ровно marker и два JSON до запуска, нет скрытого
`statejnik.yaml` или `.env`; только обычные файлы без symlink/hardlink,
каждый до 256 KiB, максимум 250 страниц и 300 фраз.
Запрещаются произвольные числа спроса, внешние источники частот и
опасные строки, влияющие на Markdown. Никакой Wordstat/Google Search Console
не вызывался: источники и реальные частоты **NO_DATA**.
Формулировка upstream-шаблона «частота — Вордстат» не подтверждает
реальные данные; тире и нули обозначают отсутствие верифицированной
частоты.

## Проверки и права

- Windows unit tests: строгая маршрутизация в `site.py gap`, запрет
  scan/network/flags/path traversal, неизвестных YAML/.env, крупных и
  подменённых файлов, чисел без provenance и перезаписи.
- Изолированный pinned Docker v0.22.2:
  `--network none --read-only --cap-drop ALL --user 65534:65534`,
  CPU/RAM/PID, host vendor read-only bind и ровно одна operator workspace.
- Отдельный E2E на синтетическом наборе проверяет реально созданные
  `gap.json` и `plan.md`, не только код возврата.
- Нет разрешения на `site scan`, `keywords`, `fetch-source`,
  `publish`, Wordstat v2, CMS, YFC writes или модель.

**Итог:** `OFFLINE_SITE_GAP_ENABLED`,
`SEARCH_METRICS_NO_DATA`, `NETWORK_NO_GO`,
`PUBLISH_NO_GO`, `RESIDENT_NO_GO`.
