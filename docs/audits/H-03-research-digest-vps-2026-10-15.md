# H-03 #4 - реальная установка Research Scout (публичные научные метаданные)

Проверка на VPS `vps1777112993`, 15 октября 2026 года, 04:38 UTC. Явное владельческое указание продолжать реализацию задач; никаких внешних сообщений/публикаций и изменения YFC не выполнялось.

## Источники и код

- [PR #81](https://github.com/MikeMoore1337/hermes/pull/81) - первый реальный Europe PMC API без регистрации/карты/ключа, опубликованный main.
- [PR #90](https://github.com/MikeMoore1337/hermes/pull/90), [CI #38681831416](https://github.com/MikeMoore1337/hermes/actions/runs/38681831416) green: один DOI Crossref с pinned public DNS TLS, без redirects/retries. Реальный Crossref CLI DOI_METADATA_MATCH 15.10.2026.
- [PR #91](https://github.com/MikeMoore1337/hermes/pull/91), [CI #38682396395](https://github.com/MikeMoore1337/hermes/actions/runs/38682396395) green: ограниченный независимый daily public metadata report, максимум 3 Europe PMC + 1 Crossref GET, 3 фиксированные темы, без LLM/автопубликации/закрытых данных.

Код `research_scout/europe_pmc.py`, `crossref.py`, `daily_digest.py` и новый systemd service/timer/installer скопированы как проверенные Git blobs в `/opt/hermes-agent-owner`. Проверки `bash -n`, `systemd-analyze verify` и запуск без `--execute` прошли. Предупреждения о `RuntimeMaxSec` относятся к старым news oneshot units, не к Research Scout.

## Первый реальный отчёт

- Установка `install-research-scout.sh` проверила активность четырёх уже работающих таймеров и выполнила один публичный сбор. `hermes-research-scout.service` завершился с `Result=success, ExecMainStatus=0`.
- Journal выдал только счётчики: `{"automatic_publication":false,"candidate_count":4,"errors":0,"requests_attempted":4,"scientific_claims_verified":false,"status":"MANUAL_REVIEW","topics":3}`.
- Строгая чтение сохранённого JSON с VPS: `schema=hermes-research-metadata-v1`, `observed_at=2026-10-15T04:38:26.143783+00:00`, 4 кандидата из трёх фиксированных запросов, 1 `crossref_doi_status=MATCHED_METADATA_ONLY`, 0 HOLD, 0 ошибок источников. Не означает, что четыре разные статьи доказали какой-либо научный факт.
- `/var/lib/hermes-research-scout` 0700 root:root, `latest-citations.json` 0600 root:root. Никакого токена и raw provider body в journald. Исходные библиографические названия/ссылки доступны только в защищённом файле для ручной проверки.
- `hermes-research-scout.timer` active/enabled. Первое отдельное автоматическое срабатывание планировалось в `07:44:17 MSK` (со случайной задержкой). Факт его выполнения должен быть проверен отдельно, не путать с первым явным `systemctl start`.

## Безопасность и ограничения

Независимый `hermes-research-scout.service` работает с запретом доступа к файлам YFC news / Hermes Agent / QA watcher / Ops Telegram / конфигам с токенами, `CapabilityBoundingSet=` пуст, `ProtectSystem=strict`, CPU/RAM/time лимиты; новости, QA и Ops таймеры при первом проходе остались active. nft guard подтвердил `verified,changed=null`.

**Сбор открытых научных метаданных - не научная экспертиза.** Результаты `MANUAL_REVIEW` ждут проверки оригиналов, методологии, популяции, effect size, возможного двойного учёта и лицензии. Не публиковать в YFC и Telegram без отдельного утверждения владельцем; автоматический AI Agent не запускать только потому, что публичный metadata collector уже работает.

Откат только нового standalone таймера:

```bash
sudo systemctl disable --now hermes-research-scout.timer
```

Не запускать `disable` для связаного `hermes-discovery.timer` YFC. [Issue #4](https://github.com/MikeMoore1337/hermes/issues/4) остаётся PARTIAL до утверждения реального пользовательского канала выдачи и содержания научного обзора.
