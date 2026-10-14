# H-01 - проверка фактического Docker-образа Hermes Agent

Дата: 2026-10-14. Задача: [H-01-LIVE #33](https://github.com/MikeMoore1337/hermes/issues/33).

## Факты, проверенные на текущем VPS

- Протестированные два настоящих agent-turn применяют pinned reference `nousresearch/hermes-agent@sha256:32d095e84190ae7266afbb361579e6921f2c633e899f5eacfb88111b9c851a22`.
- Команда `docker image inspect` вернула фактический image ID `sha256:32d095e84190ae7266afbb361579e6921f2c633e899f5eacfb88111b9c851a22`, архитектуру `amd64` и время создания `2026-10-08T06:14:28.921848602Z`.
- Рабочий образ в предыдущем аудите сообщил исходный commit `a28a5d03a9fa60418db5f44f3436fa2aa029c8f2`. При этом реальный release tag `v0.21.6` в upstream указывает на commit `818c13be1dc4fd28987e1e881a9408224afd4535`.
- `https://github.com/NousResearch/hermes-agent/compare/a28a5d03a9fa60418db5f44f3436fa2aa029c8f2...818c13be1dc4fd28987e1e881a9408224afd4535`: релизный commit на **39 коммитов впереди образа** (ahead=39, behind=0), 54 изменённых файла.
- Изменения включают централизацию `/yolo` approval/restore в `tools/approval_yolo.py`, фиксацию восстановления этого режима после restart, обновление Docker/release pipeline, TUI/CLI gateway и другие изменения, не только косметические каталоги.
- **Дополнительная проверка 14.10.2026:** на самом VPS `docker manifest inspect nousresearch/hermes-agent:v0.21.6` вернул опубликованный многоархитектурный OCI-манифест, в котором запись **linux/amd64** содержит digest `sha256:32d095e84190ae7266afbb361579e6921f2c633e899f5eacfb88111b9c851a22`. Он точно совпадает с закреплённым образом на VPS. Следовательно, соответствие официально опубликованному Docker-тегу **доказано**. Отличие исходной ревизии от Git-тега остаётся отдельным вопросом сборки и разрешений. Это не означает, что все инструменты Hermes безопасны.
- Рабочая система Hermes news/YFC от этой разницы не зависит; их сервисы менять нельзя.

## Решение для владельца

**GO:** оставить текущий immutable digest только для уже проверенных ручных, bounded операций с разрешённым todo-list и Cloudflare Free. Принятие этой категории проверено через PR #27/#28 и VPS audit.

**NO-GO:** автоматическое распространение на shell, браузер, сторонние плагины, YFC/Second Brain, 24/7 автономный режим с `-z` (auto approve) до аудита обновлений policy и однозначной проверенной цепочки provenance.

## Условия снятия блокировки

1. **Выполнено:** подтверждено соответствие published `v0.21.6` Linux/AMD64 registry digest установленному pin. **Не выполнено:** воспроизводимость/source revision относительно Git release tag, подпись/SBOM, цепочка CI издателя, base dependencies и содержимое release workflow. Не смешивать digest образа для конкретной архитектуры с digest многоархитектурного OCI index.
2. Нельзя автоматически заменять официальный работающий pinned образ на пересобранный. При необходимости исправления исходной ревизии - подготовить отдельно проверенный immutable candidate и независимый rollback с SBOM/scan и exact SHA. Без необходимости обновлять image нельзя.
3. Провести diff и negative permission tests for session `/yolo` и `-z`, restart, remote tool scopes, sandbox and no paid fallback. Сам факт добавления `approval_yolo.py` не означает уязвимость; это изменение границы прав и требует проверки.
4. Протестировать baseline и candidate offline; подтвердить минимальный agent tool-turn с CPU/RAM/age limits, Cloudflare Free, news guard. Только после этого обновлять production pin отдельным PR/CI/rollback.
5. До того запрещено включать постоянные или широко привилегированные agent units. Реального reboot VPS в этом аудите не было.

## Доказанные проверки на день отчёта

- [H-01 full agent tool-turn](H-01-full-agent-tool-turn-2026-10-14.md).
- [H-01 network guard VPS test](H-01-network-guard-vps-2026-10-14.md).
- [Repo Compare](https://github.com/NousResearch/hermes-agent/compare/a28a5d03a9fa60418db5f44f3436fa2aa029c8f2...818c13be1dc4fd28987e1e881a9408224afd4535).

Статус задачи #33: **PARTIAL / official v0.21.6 AMD64 registry artifact verified; Git-tag source parity not verified**. Режим 24/7 ещё не разрешён - остаются reboot/нагрузка/квоты/права.

## Точная проверка опубликованного OCI-тега 14.10.2026

Read-only команда `docker manifest inspect nousresearch/hermes-agent:v0.21.6`
на Hermes VPS (без `docker pull` и изменения локального образа) вернула
многоархитектурный манифест с единственной выявленной записью linux/amd64
`sha256:32d095e84190ae7266afbb361579e6921f2c633e899f5eacfb88111b9c851a22`.
Результат проверен против `docker image inspect` на том же VPS.
**Это доказывает совпадение опубликованного AMD64 артефакта, но не доказывает
source parity или криптографическую подпись разработчика.**


## Дополнение по правам после сравнения GitHub API

[Свежая матрица риска и точных путей](H-01-upstream-security-diff-2026-10-14.md) фиксирует сравнение `a28a5d03...818c13be`: 39 commit ahead, 54 изменённых файла, в том числе новая централизация сессионного `/yolo`, перенос/восстановление live approval после смены идентификатора сессии, изменения gateway и release workflow. Это **не доказательство уязвимости** и не доказательство Git release source parity. Постоянный сервис остаётся запрещённым до source/SBOM/negative permissions/burn-in gate.
