# H-01 - проверка фактического Docker-образа Hermes Agent

Дата: 2026-10-14. Задача: [H-01-LIVE #33](https://github.com/MikeMoore1337/hermes/issues/33).

## Факты, проверенные на текущем VPS

- Протестированные два настоящих agent-turn применяют pinned reference `nousresearch/hermes-agent@sha256:32d095e84190ae7266afbb361579e6921f2c633e899f5eacfb88111b9c851a22`.
- Команда `docker image inspect` вернула фактический image ID `sha256:32d095e84190ae7266afbb361579e6921f2c633e899f5eacfb88111b9c851a22`, архитектуру `amd64` и время создания `2026-10-08T06:14:28.921848602Z`.
- Рабочий образ в предыдущем аудите сообщил исходный commit `a28a5d03a9fa60418db5f44f3436fa2aa029c8f2`. При этом реальный release tag `v0.21.6` в upstream указывает на commit `818c13be1dc4fd28987e1e881a9408224afd4535`.
- `https://github.com/NousResearch/hermes-agent/compare/a28a5d03a9fa60418db5f44f3436fa2aa029c8f2...818c13be1dc4fd28987e1e881a9408224afd4535`: релизный commit на **39 коммитов впереди образа** (ahead=39, behind=0), 54 изменённых файла.
- Изменения включают централизацию `/yolo` approval/restore в `tools/approval_yolo.py`, фиксацию восстановления этого режима после restart, обновление Docker/release pipeline, TUI/CLI gateway и другие изменения, не только косметические каталоги.
- Значит, **pin образа доказан**, но точное соответствие Docker build tagged release **не доказано**. Фактическое успешное выполнение инструмента todo_list само по себе не означает безопасную работу других инструментов, особенно shell/MCP.
- Рабочая система Hermes news/YFC от этой разницы не зависит; их сервисы менять нельзя.

## Решение для владельца

**GO:** оставить текущий immutable digest только для уже проверенных ручных, bounded операций с разрешённым todo-list и Cloudflare Free. Принятие этой категории проверено через PR #27/#28 и VPS audit.

**NO-GO:** автоматическое распространение на shell, браузер, сторонние плагины, YFC/Second Brain, 24/7 автономный режим с `-z` (auto approve) до аудита обновлений policy и однозначной проверенной цепочки provenance.

## Условия снятия блокировки

1. Проверить upstream Docker image provenance: точный registry manifest digest vs source commit, издателя и build workflow, происхождение base dependencies и release contents. Нельзя утверждать, что `v0.21.6` tag идентичен текущему image ID.
2. Выбрать release commit по обоснованию и создать **отдельный immutable image**, желательно с OCI revision metadata, воспроизводимой сборкой, SBOM/scan и сохранённым SHA.
3. Провести diff и negative permission tests for session `/yolo` и `-z`, restart, remote tool scopes, sandbox and no paid fallback. Сам факт добавления `approval_yolo.py` не означает уязвимость; это изменение границы прав и требует проверки.
4. Протестировать baseline и candidate offline; подтвердить минимальный agent tool-turn с CPU/RAM/age limits, Cloudflare Free, news guard. Только после этого обновлять production pin отдельным PR/CI/rollback.
5. До того запрещено включать постоянные или широко привилегированные agent units. Реального reboot VPS в этом аудите не было.

## Доказанные проверки на день отчёта

- [H-01 full agent tool-turn](H-01-full-agent-tool-turn-2026-10-14.md).
- [H-01 network guard VPS test](H-01-network-guard-vps-2026-10-14.md).
- [Repo Compare](https://github.com/NousResearch/hermes-agent/compare/a28a5d03a9fa60418db5f44f3436fa2aa029c8f2...818c13be1dc4fd28987e1e881a9408224afd4535).

Статус задачи #33: **PARTIAL / image origin mismatch known**, автоматический резидентный runtime не разрешён одним фактом успешных smoke-тестов.
