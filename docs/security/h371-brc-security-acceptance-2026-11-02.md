# H-15 #371 - проверка границ безопасности BRC (2026-11-02)

## Границы и источники

- Исходный upstream: `shahidx0x/better-remote-commander@cbe511702dd0147650353c29ac6ab1decd8afda1`; MIT LICENSE + NOTICE, `pnpm@11.24.0`, точная ревизия и `pnpm-lock.yaml` проверяются `scripts/h15_remote_commander_candidate_audit.py` и `.github/workflows/h15-remote-commander-candidate.yml`. Автоматическое обновление upstream отсутствует.
- CI проверяет **временный** patched relay/agent, а не целостность установленного на VPS/Windows образа. Кандидат запускается с `--read-only --cap-drop ALL --security-opt no-new-privileges`, ограничениями сети, CPU, RAM и PID; `scripts/h15_brc_sandbox_linux_e2e.mjs` исполняет настоящий `start_process` и Node-дочерний процесс.
- Реальная ранее зафиксированная приёмка: [#371, Linux OS-проверка и gateway](https://github.com/MikeMoore1337/hermes/issues/371#issuecomment-6255652360), [#371, Windows ACL](https://github.com/MikeMoore1337/hermes/issues/371#issuecomment-6259628205), [#371, reconnect](https://github.com/MikeMoore1337/hermes/issues/371#issuecomment-6262745787), [#371, OAuth revoke](https://github.com/MikeMoore1337/hermes/issues/371#issuecomment-6282852977), [#371, ChatGPT sandbox](https://github.com/MikeMoore1337/hermes/issues/371#issuecomment-6302424704), [#371, device revoke](https://github.com/MikeMoore1337/hermes/issues/371#issuecomment-6302483503).
- Статусы: `VERIFIED` = проверено на названном реальном клиенте/контуре; `SYNTHETIC_PASS` = пройдено в одноразовой CI-среде; `SOURCE_ONLY` = анализ кода без запуска; `NOT_VERIFIED` = не хватает доказательств; `BLOCKED` = необходимы отдельно разрешённые живые операции. Статус **не** переносится с CI на production.

## Матрица по действующей реализации

| Механизм | Доказательство | Статус | Остаточный риск / обязательный следующий тест |
| --- | --- | --- | --- |
| Filesystem isolation | `h15_brc_sandbox_linux_e2e.mjs`; контейнер UID 65534, read-only source, отдельный writable workspace; прежние клиентские file E2E | SYNTHETIC_PASS + VERIFIED (sandbox MCP) | OS-гарантии конкретного текущего production-образа и native Windows mounts не перепроверены |
| Shell isolation | Реальный `start_process` → Node в network-none Docker; /root и host-private недоступны в disposable CI | SYNTHETIC_PASS | Изоляция на ОС, а не `allowedDirectories`; проверить образ каждого реального устройства без host-доступа |
| Process execution | Настоящий shell в CI и ChatGPT/Codex; `force_terminate` для известной сессии | VERIFIED (sandbox) | Полная остановка дерева потомков при timeout/аварии **NOT_VERIFIED**; отслеживается в #454 |
| OAuth / PKCE | Zero-device OAuth S256 и отрицательные PKCE-тесты, owner-reported VPS пилот, отдельный реальный ChatGPT MCP | SYNTHETIC_PASS + VERIFIED (MCP-клиент) | Повторить auth с текущим образом и отдельными клиентскими identities после нового релиза |
| Token revocation | Прежние OAuth access/refresh revoke в CI; закрытие временного Windows пилота с отзывом токена | SYNTHETIC_PASS + VERIFIED (пилот) | Новый отказ для **уже открытого WSS после rekey/delete** требует CI и live приемки; код в этом PR |
| Device ACL | `mcp/invoke.ts`: owner, paused, revoked + socket token-hash; реальная маршрутизация трёх sandbox-устройств | SOURCE_ONLY (новое усиление), VERIFIED (базовая маршрутизация) | Проверить отказ чужого ID, чужого owner и восстановление после rekey; CI-регрессия в этом PR |
| Path traversal | Файловый MCP вне `/workspace` отклонялся у реального клиента | VERIFIED (file API) | Обход через shell нельзя исключить строковой нормализацией; требуется граница контейнера |
| Symlink escape | OS-only unmounted/protected paths в CI | NOT_VERIFIED (все варианты) | Отдельные отрицательные POSIX symlink и Windows junction/reparse/TOCTOU тесты при owner-approved runtime |
| Configuration tampering | `set_config_value` удалён из агентского dispatcher и запрещён relay allowlist | SYNTHETIC_PASS | Файлы конфигурации не должны быть доступны для записи непривилегированному shell вне собственной disposable области |
| Replay protection | `h15_brc_reconnect_socket_e2e.mjs`: socket+device binding, старые/чужие ответы отброшены | SYNTHETIC_PASS | Ответ-replay заблокирован; эффекты уже **выполненной** команды не откатываются автоматически |
| Reconnect handling | Disconnect/reconnect, duplicate hello, heartbeat expiry в тесте настоящего DeviceHub | SYNTHETIC_PASS | Физический reboot/login Windows, SSH outage и reconnect настоящего сервиса - #454, NOT_VERIFIED |
| Resource limits | GitHub CI Docker `--pids-limit`, `--memory`, `--cpus`; частичные caps вывода в dispatcher | SYNTHETIC_PASS | Полное дерево потомков, общий срок жизни и runtime quota на production требует независимой проверки |
| Audit logging | `mcp/invoke.ts` пишет `store.audit` на принятые/завершившиеся вызовы; mock-счётчик | SOURCE_ONLY + SYNTHETIC_PASS | Отказ до `hub.call` не всегда имеет отдельную audit-квитанцию; проверить журнал production без утечки arguments |
| Secret isolation | CI не монтирует owner secrets, реальные sandbox-отказы на host-private; токены в SQLite как hash | SYNTHETIC_PASS + VERIFIED (частично) | Текущие production secrets, env, дескрипторы и журналы при активном shell независимо NOT_VERIFIED |

## Новые проверки этого PR (до первого точного CI - NOT_VERIFIED)

1. Отказ в `/device/poll` при попытке другого владельца занять существующий `device_id`: HTTP 409, владелец и hash сохранены.
2. Привязка принятого WebSocket к неизменяемому `token_hash` без сохранения raw bearer на socket и отключение старого socket при ротации.
3. Отказ `tools/call` при удалённой записи устройства, смене владельца, несовпадении token hash или паузе, даже если старый socket остаётся подключён.
4. Отрицательные unit фикстуры для дрейфа upstream: патчеры не должны менять частично незнакомый код.
5. Реальный loopback HTTP/WSS и скомпилированный gateway, существующие полный upstream/patch тесты, Docker OS denial и 2-agent OAuth MCP CI без host-полномочий.

## Не пересекаться с #454 / решение о закрытии

Draft [#692](https://github.com/MikeMoore1337/hermes/pull/692) реализует WSS/SSH/tunnel/recovery, draft [#693](https://github.com/MikeMoore1337/hermes/pull/693) - UI onboarding. Настоящий PR не меняет их файлы или запущенный runtime. `main` source merge не равен активному обновлению BRC образа.

**#371 закрывать только после:** точного CI текущего PR + независимого review + независимой проверки текущего runtime под фактическим профилем безопасности, включая device rekey/revoke и shell/OS denial, с подтверждением отсутствия доступа к host production. Если реальный runtime/Windows сценарий требует отдельного одобрения, оставить #371 OPEN с этим конкретным gate. Подтверждённые упрощённые тесты не считать заменой полномасштабного penetration test.
