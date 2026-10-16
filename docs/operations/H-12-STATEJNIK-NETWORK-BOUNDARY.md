# H-12 / #64 — защищённый сетевой транспорт Statejnik: offline-кандидат

Акт 16.10.2026. Режим **NETWORK_AND_PUBLISH_NO_GO**. Это код
отдельного Hermes-owned транспортного модуля и синтетические сетевые
тесты, **не** включение real network tools, Wordstat, CMS, YFC или
автоматической публикации. Все 62 оригинальных upstream-файла
`third_party/statejnik` сохранены без правок с теми же SHA256.

## Зафиксированный upstream риск

Оригинальный `skills/statejnik/scripts/_net.py` предоставляет
`request(..., allow_private=True)` и `request_json()` вызывает его
без запрета приватных адресов. `is_private_host()` при DNS lookup failure
возвращает `False` (fail-open), а предварительное DNS-разрешение
не закрепляет IP фактического HTTPS-соединения (DNS rebinding / TOCTOU).
Редиректы проверяют только имя, затем urllib снова разрешает DNS;
публичный разрешённый DNS-хост может перескочить на внутренний IP.
`request` использует неограниченное `resp.read()` и возвращает
фрагменты тела ошибок, которые могут включать чувствительные данные.
Это потенциальные уязвимости при разрешении внешней сети;
сеть и публикация текущего Hermes runner **всё ещё отключены**.

## Независимый код-кандидат

`statejnik_integration.network_boundary` по умолчанию бросает
`NetworkDenied("network_not_enabled")` ещё **до DNS**.
При явном `authorized=True` и непустом exact-host
`frozenset` из HTTPS-доменов работает **ограниченный транспорт-кандидат**:

- Только `https://host` или `https://host:443` для 1–8 канонических
  ASCII/IDNA-hostnames. Без IP literal, userinfo, control characters,
  backslash, non-HTTPS, нестандартного порта, wildcard, `.local`,
  `.internal`, `localhost`, некорректного authority и второго slash.
- DNS — максимум 16 ответов; **все** адреса должны быть глобально
  маршрутизируемыми, никакие private/shared/link-local/loopback/reserved/
  multicast/IP-mapped IPv6 не принимаются. DNS error = DENY.
- TLS-сокет открывается **на выбранный проверенный IP**, без нового DNS
  в `connect()`; SNI и проверка сертификата сохраняют исходный hostname.
  Никакой системной HTTP proxy / DNS после admission или plain HTTP.
- Redirect вручную, максимум 3, каждый URL вновь проверяется против
  exact allowlist и DNS. Перескок на `localhost`, cloud metadata,
  чужой домен, несогласованный порт или частный DNS = DENY.
- Только GET, без cookies, credential headers, POST, публикации и
  произвольного пользовательского Host. Клиент явно запрашивает
  `Accept-Encoding: identity` и `Connection: close`. **До чтения тела**
  обязательный Content-Type `text/html` либо `application/xhtml+xml`,
  отклонение gzip/br/другого сжатия, attachment, неизвестных и
  неоднозначных Transfer-Encoding, одновременно заданных
  Content-Length + Transfer-Encoding, некорректного либо превышающего
  1 MiB Content-Length. Чтение ограничено 1 MiB+1 даже при отсутствии
  заголовка длины или при chunked. Ответ только HTTP 200; ошибка не
  включает URL, токен или тело ответа.
- Ни одна existing `runner` / native Hermes service / timer
  **не импортирует и не вызывает** этот транспорт. Вендорские 12 CLI
  сохранены, а `site`, `keywords`, `fetch-source`, `publish`
  всё ещё отклоняются до Docker.

## Дополнительный лимит общего времени (16.10.2026)

Перед любым реально авторизованным `fetch_public_html` transport-кандидат
устанавливает отдельный **15-секундный процессный POSIX SIGALRM** вокруг
всего цикла DNS → TLS → HTTP headers → redirects → body. В отличие от
отдельного socket timeout, это прерывает синтетическую бесконечную
передачу данных по одному фрагменту; негативный тест на Linux подтверждает
`wall_budget_exceeded`, освобождение connection и восстановление исходного
обработчика таймера. По умолчанию `authorized=false` блокирует всё ещё до
установки таймера и DNS. На Windows, в многопоточном процессе, не-main
thread, при существующем `SIGALRM`-обработчике/таймере или отсутствии
POSIX `setitimer` запрос **не допускается**, а не выполняется без защиты.

**Граница доказательства:** POSIX сигнал обрабатывается интерпретатором
Python, а некоторые долгие блокирующие C-библиотечные вызовы (особенно
системное DNS-разрешение) могут задерживать выполнение Python handler.
Гарантированный независимый wall-time для ВСЕХ стадий требует будущего
изолированного child-процесса с внешним watchdog и принудительным kill,
плюс kernel egress firewall. Этот дополнительный timer — defense-in-depth,
**не** эксплуатационный GO и не разрешение использовать его внутри
многопоточного Hermes Control Center.

Проверка transport-кандидата не доказывает:
реальный egress firewall, TLS с реальными серверами, полный лимит
wall-time при медленной передаче, отсутствие DNS/SSRF обходов
в других функциях upstream, полное антибот/robots согласование,
доступность/стоимость Wordstat, согласие владельца CMS/YFC,
авторизацию на публикацию.

## Следующие gate до активации

1. [Read-only аудит фактических ограничений сети на VPS](../audits/H-12-EGRESS-PRODUCTION-NO-GO-2026-10-16.md):
   `PrivateNetwork=no`, нет `NetworkNamespacePath` и `IPAddressDeny`
   для отключённого resident service; **OS egress GO отсутствует**.
   Выделенная egress-сеть с allowlist **на уровне firewall/proxy**, без
   возможности обхода или приватного/metadata egress, ограниченные
   DNS и TLS, доказанные live negative tests. Один Python URL validator
   сам по себе недостаточен для full P0 GO.
2. Ревью complete network calls в `site.py`, `keywords.py`,
   `fetch-source.py`, `publish.py` и зависимостей `_net.py`.
   Подключить исправленный Hermes transport к конкретным read-only
   функциям в отдельном PR, не подменяя SHA оригинального исходника.
3. Серверные квоты API и отдельное owner GO на tokens/Wordstat/платные
   запросы; только после этого — controlled outbound trial.
4. CMS draft и manual publication review/YFC ownership,
   без обхода acceptance gate `--force-without-acceptance`.

**Disposition:** `OFFLINE_TRANSPORT_CANDIDATE_TESTED`,
`NETWORK_NOT_CONNECTED`, `PUBLISH_NO_GO`,
`RESIDENT_AGENT_NO_GO`.
