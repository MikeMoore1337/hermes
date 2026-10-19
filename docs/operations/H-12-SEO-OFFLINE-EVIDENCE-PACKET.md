# H-12 / #64 - безопасный офлайн-пакет SEO-исследования

Дата: 2026-10-19. Контракт: `hermes-h12-seo-research-packet-v1`.
Операторский CLI - `python -m scripts.hermes_seo_research`.
**Нет сетевых запросов, моделей, subprocess, записи на диск/YFC и публикации.**

## Собраны существующие компоненты (без второго SEO-движка)

1. **Research Scout #4**: ровно одна уже собранная публичная
   `latest-citations.json.items[]` через
   `marketing.seo_brief.from_daily_item` с сохранением статуса
   `HOLD/MANUAL_REVIEW`, DOI/PMID, corrections и запрета научных утверждений.
   Это *не* научная экспертиза #317.
2. **Statejnik 1.2.0**: заранее произведённый в строго offline runner
   `site.py gap` JSON. Здесь **только читаем** `clusters`,
   `covered_by` и `maybe_covered`.
   Vendor heuristic не доказывает отсутствия статьи, поискового спроса
   или необходимости нового материала. Vendor `volume`
   **должен быть null**. Существующие `gap.json` и `plan.md`
   не заменяются и не переписываются.
3. **Поисковые наблюдения**: только явный операторский JSON из
   `synthetic_fixture` либо `owner_export`.
   Поддержаны GSC, Yandex Webmaster и Wordstat как *раздельные*
   категории измерений. Данные не извлекаются из API.
   `evidence_sha256` обязателен для owner export,
   но сам по себе подтверждает лишь идентификатор набора, **не**
   аутентичность источника. `owner_attested=true` также не
   является проверкой API со стороны Google/Yandex.
4. **Выход**: один JSON с сохранёнными source/period/query/page/country/
   intent/metric/limitations, источником #4, ближайшей страницей,
   H1/H2 и вопросом редактору; то же содержимое в поле `markdown`
   либо в Markdown CLI. Никакого генератора статей нет.

## Контракт ввода

JSON объект *строго* содержит поля:
`schema, theme, research_item, site_gap, observations, selected_query, as_of`.

- `schema`: `hermes-h12-seo-offline-input-v1`.
- `theme`: один из уже предусмотренных в `marketing.seo_brief.THEMES`.
- `research_item`: **ровно существующая публичная** запись Research Scout,
  без придуманного исследования и новых статусов.
- `site_gap`: offline output `site.py gap`, не HTML и не текст конкурентов.
- `observations`: 0..50 source-typed records; каждый содержит
  `source, source_type, observed_at, period_start, period_end, query, search_intent, limitations`
  и хотя бы одну допустимую метрику.
  `country, language, page` необязательны, если недоступны.
- `as_of`: фиксированная дата в тестах, не текущее время машины.
- `selected_query`: один кластер существующего offline gap.

Источник и допустимые метрики:

| Источник | Показатели |
|---|---|
| `google_search_console` | `impressions, clicks, ctr, average_position` |
| `yandex_webmaster` | `impressions, clicks, ctr, average_position` |
| `yandex_wordstat` | `search_volume` |

**GSC показы не равны Wordstat частотам**, показатели не складываются
между инструментами. Дата конца периода старше 90 дней помечается
`stale` и не участвует в решении. Уровень этого окна -
предварительное консервативное правило *для офлайн-брифа*, а не
универсальное SEO-правило. Нулевые реальные показатели допустимы,
`NO_DATA` остаётся отсутствием наблюдения, а не числом 0.
Внешние неизвестные поставщики и недокументированные метрики отклоняются.

## Решение редактору

- `READY_FOR_REVIEW`: найдено соответствующее свежее синтетическое
  наблюдение либо отдельно помеченный owner-attested export с
  ненулевыми показами/частотой; научный статус не HOLD, а gap не
  указывает на занятую страницу. **Это только очередь ручной проверки.**
  Синтетика всегда имеет `SYNTHETIC_ONLY` и никогда не объявляется
  настоящей статистикой.
- `HOLD`: научный HOLD, похожая/уже занятая страница либо конфликт интента.
- `NO_DATA`: нет свежего допустимого свидетельства спроса.
  В этом случае бриф по теме всё равно возможен.

Всегда:
`publication_allowed=false`,
`yfc_write_allowed=false`,
`live_api_used=false`,
`paid_api_used=false`.
Черновик не обходят YFC #320/#322, YFC owner READY или Research Scout #317.

## Воспроизведение

Для синтетического контракта и сквозного JSON → Markdown сценария:

```bash
python -m unittest tests.test_marketing_seo_brief tests.test_marketing_seo_research -v

# input.json - ограниченный операторский файл со схемой выше:
python -m scripts.hermes_seo_research --format json < input.json > packet.json
python -m scripts.hermes_seo_research --format markdown < input.json > packet.md
```

Результат CLI детерминирован, stdout не содержит секретов.
Ограничение stdin: 256 KiB. CLI не читает произвольные пути из JSON,
не сохраняет файл сам и не делает даже разрешённые внешние GET.
Offline E2E покрывает композицию **существующих выходных контрактов**,
не является новым live-прогоном Wordstat, HTML crawler или YFC production.

## Provenance, права и внешние блокировки

Исходники Statejnik от Artemii Millier сохранены в pinned upstream
`4de2944a31eaffdba4463cdbea115191cb551300`
(`third_party/statejnik/HERMES_SOURCE_MANIFEST.json`, 62 файла).
Владелец подтвердил полное личное разрешение для его проектов.
Публичный `LICENSE` остаётся `All rights reserved`;
отдельная частная лицензия публично не размещается.
Настоящее изменение не копирует и не меняет upstream, не даёт
прав на Wordstat, CMS, конкурентные статьи и сторонние API.

Контент конкурентов - только публичная структура/метаданные и ручной
анализ при соблюдении правил доступа, **без копирования текста**.
Неиспользуемые publisher/keyword/fetch CLI у vendor сохранены как
неактивные, не означают runtime GO. Сетевая граница selective egress
не принята для live (#64, H-12 egress NO-GO).
GSC OAuth - отдельно Hermes #191, поисковое наблюдение и
редакционный Growth Operator - YFC #320/#322.

Ни один новый таймер, разрешение сети, ключ, платный маршрут, CMS,
обработчик production или публикация этим PR не создаётся.

## Приёмка существующих SEO-исследований YFC - 19.10.2026

Источники уже существуют в YFC, повторного сбора статистики не требуется:

- YFC Task 241A: [semantic core CSV](https://github.com/MikeMoore1337/your-fitness-coach/blob/master/docs/seo/semantic-core-ru-cis.csv), [owner Wordstat export](https://github.com/MikeMoore1337/your-fitness-coach/blob/master/docs/seo/manual-wordstat-input.md), [SERP/конкуренты Google и Яндекс](https://github.com/MikeMoore1337/your-fitness-coach/blob/master/docs/seo/serp-competitor-matrix-ru-cis.md).
- YFC #264: поисковая foundation и Яндекс Метрика уже доставлены.
- YFC #502/#608/#612: технические SEO-проблемы исправлены; не повторять.
- YFC #320: GSC 12 показов / 0 кликов за 03-14.10.2026, выборка недостаточна; внешняя реальная статистика Яндекса за октябрь пока NO_DATA.

Модуль marketing.yfc_wordstat_import и CLI scripts.hermes_import_yfc_wordstat
принимают **только фиксированный Git-blob snapshot** исторического
YFC semantic-core-ru-cis.csv, зафиксированный в tests/fixtures/
yfc_241a_semantic_core_20260916.csv с исходным SHA-1
da88488e780b187afcfc5f70cb001ef4f4eb3a72.
Оригинал остался в YFC; копия нужна исключительно для воспроизводимой
офлайн-проверки существующей статистики, а не как ещё одна SEO-база.

Воспроизведение:

    python -m scripts.hermes_import_yfc_wordstat --query "калькулятор кбжу" --as-of 2026-10-19 < tests/fixtures/yfc_241a_semantic_core_20260916.csv

Результат - JSON с observations, пригодными для H-12 build_packet. Одна
выгрузка Wordstat дублируется в исходном semantic CSV в строках
search_engine=Google и search_engine=Yandex из-за сравнения SERP; importer
исключает двойной подсчёт и маркирует ВСЁ как yandex_wordstat.
Типы частотности сохраняются раздельно: broad и quoted_fixed_word_count,
с регионами, устройствами, period, SHA-256 исходных байтов и provenance.
Отсутствующие owner frequency остаются NO_DATA, реальный ноль не подменяется.
При обновлении YFC CSV исторический pin не изменяется незаметно - нужна
явная новая ревизия и проверки. Snapshot не подтверждает свежие live API
цифры.

Для темы без действительно подходящей статьи Research Scout можно подать
theme=market_research и research_item=null. Такой бриф НЕ делает научных
утверждений: research_brief=null, научный статус NOT_PROVIDED, экспертная
и owner READY проверки обязательны, никакой публикации.
Не следует привязывать случайный DOI к коммерческому SEO-запросу.

Source-specific yandex_wordstat наблюдение требует поля wordstat_operator,
wordstat_region, wordstat_device. В остальных источниках Wordstat-поля
запрещены. Показатели разных режимов и поисковых систем не суммируются.

Текущий завершённый объём Hermes #64 - офлайн-пакет с реальными ранее
предоставленными owner observations и безопасный маркетинговый handoff.
Свежие GSC API - Hermes #191; Яндекс Вебмастер API - Hermes #397;
эффективность/индексация на YFC - #320; изменение страниц/публикация -
YFC #322. Их самостоятельное завершение не требуется для офлайн-приёмки #64.
