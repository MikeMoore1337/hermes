# H-01 #33 - повторная независимая сверка исходного кода и прав Hermes Agent

Дата анализа: 14.10.2026. **Только GitHub API и локальный анализ**, без перезапуска VPS, скачивания нового Docker-образа, включения AI Agent и изменений в YFC.

## Известный проверенный образ

- Установленный образ `nousresearch/hermes-agent@sha256:32d095e84190ae7266afbb361579e6921f2c633e899f5eacfb88111b9c851a22` точно соответствует *опубликованной* linux/amd64 записи манифеста `nousresearch/hermes-agent:v0.21.6`. Это подтверждено предыдущей проверкой на VPS, а не повторным Docker pull.
- Встроенная информация об исходниках образа: `a28a5d03a9fa60418db5f44f3436fa2aa029c8f2`; официальный GitHub tag `v0.21.6`: `818c13be1dc4fd28987e1e881a9408224afd4535`.
- **Повторный Github compare API:** `ahead_by=39`, `behind_by=0`, **54 изменённых файла** между этими ревизиями. Это изменения в направлении от встроенного SHA к более позднему tagged SHA, а не наоборот. [Фактический diff](https://github.com/NousResearch/hermes-agent/compare/a28a5d03a9fa60418db5f44f3436fa2aa029c8f2...818c13be1dc4fd28987e1e881a9408224afd4535).
- **Registry digest equality ≠ Git tag source parity.** Нельзя выводить исходный commit всех файлов бинарного образа или наличие проверенной подписи/SBOM только из совпадения digest.

## Что менялось в trust boundary

| Слой | Изменённые пути | Почему нужен отдельный review |
| --- | --- | --- |
| Approvals | `tools/approval_yolo.py` (новый, 72 строки), `tests/tools/test_approval_yolo.py` (новый) | В tagged-коде появилась единая функция `toggle_session_yolo`, `restore_session_yolo`, `transfer_session_yolo`; восстановление `yolo_mode` после рестарта и перенос при смене session key теперь отдельный источник риска сохранения привилегий |
| CLI / gateway | `gateway/slash_commands.py`, `gateway/run_turn.py`, `gateway/run_agent_cache.py`, `hermes_cli/cli_session_mixin.py`, `hermes_cli/cli_commands_mixin.py` | Согласовать persisted/live approval режимы после restart/compression/branch, отсутствие самопроизвольного расширения `-t todo` до shell/browser/MCP |
| TUI | `tui_gateway/methods_session.py`, `tui_gateway/methods_session_model_guard.py`, `tui_gateway/methods_config_set.py` | Не доверять состоянию UI как политике разрешений на хосте |
| Release | `.github/workflows/docker.yml`, `.github/workflows/stable-release.yml` | Проверить publisher, builder, provenance attestations, SHA source lock и digest/SBOM у релизного артефакта |
| Плагины | `plugin-catalog/commandcode-oauth.yaml` (новый) | Не допускать случайного включения новых OAuth/модельных шлюзов вместо только явно одобренного бесплатного контура |

Исходник `tools/approval_yolo.py` на tagged SHA утверждает, что approval-блокировка хранится как in-memory session flag, а выбранные поверхности самостоятельно сохраняют `model_config.yolo_mode`/маршрут и восстанавливают состояние после рестарта. Это **наблюдение реализации**, не утверждение о наличии уязвимости. Опасность появляется при наличии опасных инструментов в toolset, ошибках изоляции/восстановления scope или невидимом распространении уже одобренного режима. Текущий одноразовый smoke использует `-z` **только с `-t todo`**, но это не основание переносить `-z` в долговременную службу.

## Негативные проверки, обязательные перед снятием блокировки

1. Источник образа и подписи: проверить attestations/SBOM от издателя или доказанную цепочку CI->commit->digest для именно проверенной архитектуры. При отсутствии проверяемого доказательства - NO-GO.
2. Сессия после restart, compression/rotation/branch: `/yolo` не может получить shell/browser/HTTP/Git/MCP/write, если эти инструменты отсутствуют на уровне ОС и реального toolset. Отсутствие `-z` в конфигурации не эквивалентно запрету persisted bypass.
3. Принудительный отказ при 401/402/403/429, quota, DNS/private IP drift, превышении load 1.10/1.30; никаких платных fallback или автоматических ретраев.
4. Отдельный rollback, изолированный кандидат, сверенный хеш всех source/plugin файлов, воспроизводимый bill of materials и resource burn-in на VPS без конкуренции с новостями.
5. Resident systemd service и новые tools не включать до успешных проверок и явного изменения текущей политики владельца.

## Статус

**PROVEN:** official linux/amd64 registry digest и направление 39-коммитного диффа; изменение поверхности `/yolo` зафиксировано с точными путями. **NOT PROVEN:** source parity, SBOM, approval-state security под постоянным агентом, peak-load burn-in, cost/account guarantee.

Аудит и [машиночитаемая матрица](../../deploy/hermes-upstream-security-diff.json) предназначены для проверки, а не для запуска обновлённого агента. H-01 #33 остаётся OPEN; `permanent_agent_runtime_approved=false`.
