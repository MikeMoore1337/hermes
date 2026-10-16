# H-01 #33 — fail-closed native tool policy для Hermes v0.22.1

Дата: 15.10.2026. Работа продолжена в [PR #135](https://github.com/MikeMoore1337/hermes/pull/135) по [Issue #33](https://github.com/MikeMoore1337/hermes/issues/33).

Статус этого этапа: `PATCHED_NATIVE_TOOL_POLICY_BOUNDED_PASS`. Это не разрешение
на merge, deploy или постоянный запуск Hermes: `resident_agent_allowed=false`,
production не проверялся.

## Граница и исходные артефакты

Проверялся ровно upstream Hermes v0.22.1:

- source commit: `297552a9d646119871391d202509822cd86330df`;
- pinned AMD64 image: `nousresearch/hermes-agent@sha256:cd9cb455576d27c9b6311de1104494ad7e221b6e68dc77e9ac2a8af661a4dc21`;
- актуальный upstream `main` не использовался и на pinned source не подменялся;
- локальный patched image — только derivative test image
  `hermes-agent-v0221-native-tool-policy:20261015`, digest
  `sha256:d7ee205f86f3b8562663f333eb3c850b6824959b7c70f8b52d3102dbea3d849d`,
  не официальный релиз.

Проверочный контур находится в [verify_v0221_native_tool_policy.py](../../scripts/verify_v0221_native_tool_policy.py),
регресс — в [test_v0221_native_tool_policy.py](../../tests/test_v0221_native_tool_policy.py),
а минимальный upstream-кандидат — в
[hermes-v0.22.1-native-tool-policy.patch](../../patches/upstream/hermes-v0.22.1-native-tool-policy.patch).

## Что подтверждено на исходном образе

Фильтрация `_select_tool_names(enabled_toolsets, disabled_toolsets)` скрывала
`terminal`, но не была границей исполнения. В исходном pinned runtime безопасная
заглушка `_execute_tool` была достигнута в следующих сценариях:

- прямой native `terminal` при `enabled_toolsets=["safe"]`,
  `disabled_toolsets=["terminal"]`;
- legacy alias `process`, который канонизируется в `process_manage` после
  отсутствия проверки native scope;
- stale `AIAgent` policy при изменении `disabled_toolsets` после построения
  `valid_tool_names`;
- полный `AIAgent.run_conversation` с детерминированным OpenAI-style ответом
  модели и намеренно permissive `valid_tool_names`;
- `execute_code` с намеренно stale inner sandbox list: на исходном образе
  вложенный `terminal` проходил в registry dispatch, patched scope оставляет
  разрешённый `web_search`, но удаляет `terminal`;
- неизвестное native имя и ошибки policy/middleware в низкоуровневом пути.

Это подтверждает общий дефект: список доступных model tools и authorization
перед фактическим dispatch были разными механизмами. Сам по себе provider-level
`valid_tool_names` не защищал прямой executor path.

Первоначальное подозрение о Tool Search bridge в этом pinned коде не
подтвердилось: `tool_call` для запрещённого `terminal` уже не достигал
заглушки. Connector batch, однако, обязан сохранять ту же проверку, поэтому он
включён в patched regression.

## Исправление

Patch намеренно узкий и предназначен для передачи upstream, а не для изменения
официального Docker image:

1. текущая policy передаётся из `AIAgent` в native `handle_function_call` и
   повторно проверяется непосредственно перед registry/connector dispatch;
2. aliases проверяются после канонизации имени;
3. connector names проверяются как `manage_connections`, а batch остаётся
   внутри того же bridge scope;
4. изменённые execution-middleware аргументы повторно проходят approval guard;
5. ошибки tool-request middleware, pre-tool hooks, approval hooks,
   execution middleware и registry policy дают фиксированный отказ и не
   продолжают выполнение;
6. отсутствие ограниченной policy сохраняет только существующий явно
   unrestricted внутренний вызов (`enabled_toolsets is None` и
   `disabled_toolsets in (None, [])`). Некорректная форма policy — отказ;
7. `execute_code` передаёт во внутренний RPC sandbox пересечение
   `enabled_tools` с текущим session scope, поэтому stale sandbox cache не
   расширяет права;
8. subagent по-прежнему получает пересечение разрешённых toolsets родителя,
   а конечная проверка не позволяет расширить их через stale cache.

Фиксированные сообщения отказа не содержат аргументы, имена секретов или
   внутреннюю конфигурацию. Ранняя проверка оставлена для model/bridge пути,
   а конечная — для защиты от прямого вызова, TOCTOU между middleware и
   dispatch, alias/connector обхода и изменений registry policy.

## Детерминированное доказательство

Один и тот же инспектор запускается на оригинальном pinned образе и на его
локальном patched derivative. Используются реальные `AIAgent`,
`handle_function_call`, Tool Search/connector/delegate модули и execution
middleware; фактический executor и registry dispatch заменены наблюдаемыми
synthetic stubs. Full-loop case подаёт заранее созданный response object через
заменённый `_interruptible_api_call`, поэтому внешний AI API, shell, сеть,
платные запросы, production и реальные secrets не используются.

Набор проверок включает native allow/deny, legacy alias, fresh/stale agent
policy, полный AIAgent loop, Tool Search, неизвестное имя, некорректную policy,
request/pre/approval/execution hook errors, изменённые аргументы,
registry error, повтор после отказа, connector batch, subagent scope и
`execute_code` nested scope, parallel calls with different live policies,
subagent scope и secret-free diagnostics.

Результат фактического Docker-прогона:

```json
{
  "status": "PATCHED_NATIVE_TOOL_POLICY_BOUNDED_PASS",
  "original_low_level_gap_reproduced": true,
  "patched_checked_paths_blocked": true,
  "allowed_synthetic_paths_work": true,
  "full_agent_surface_verified": true,
  "model_executed": false,
  "real_tool_executed": false,
  "production_verified": false,
  "resident_agent_allowed": false
}
```

В original image запрещённые native и full-loop вызовы достигали только
synthetic executor; в patched image все проверенные запрещённые пути дали
контролируемый отказ до executor. Разрешённый synthetic `web_search` и
изменённый `write_file` прошли только после повторной approval-проверки; в
последнем случае approval увидел `SYNTHETIC_MODIFIED`.
В параллельной паре original пропускал restricted `terminal`, а patched
пропустил только разрешённый `web_search`.

## Docker и регресс

Derivative собран из pinned base через
[Dockerfile](../../docker/v0221-native-tool-policy-test/Dockerfile) с
`--pull=false`, `--network none`; patch сначала проходит `git apply --check`.
Оба runtime-прогона используют `--pull=never`, `--network none`,
`--read-only`, `--cap-drop ALL`, `no-new-privileges`, UID `65534:65534`,
CPU `0.5`, RAM/swap `768m`, PID limit `64` и `/tmp` tmpfs с `noexec`.
Монтирования, Docker socket, production credentials и секреты отсутствуют.
Три изменённых Python-файла в derivative image дополнительно прошли
`py_compile` с output только в ephemeral `/tmp`.

Локальные контрактные тесты проверяют:

- default `NOT_EXECUTED` не запускает Docker;
- positive evidence требует одновременно воспроизведённого исходного gap,
  заблокированных patched paths и работающих разрешённых synthetic paths;
- malformed, duplicate-key и secret-bearing evidence fail-closed;
- обе image identity checks выполняются до принятия результата;
- Docker command сохраняет pinned/isolation flags и не содержит mounts,
  `--env-file`, privileged mode или Docker socket.

## Что остаётся вне доказательства

Этот результат не является полной оценкой безопасности Hermes. Не проверялись
production network/host policy, Cloudflare billing, зависимости, нагрузка,
реальные iPhone/Telegram/VoiceOver сценарии, внешний provider, настоящие
credentials, deployment или merge. Также не утверждается, что новые upstream
версии безопасны: patch привязан к exact v0.22.1 source и требует отдельного
review/upstream disclosure.

Для Hermes repository зафиксированы patch, изолированный verifier, Docker
derivative и тесты. Официальный pinned image не изменён. Upstream-изменения
требуются в `model_tools.py`, `agent/tool_executor.py` и
`hermes_cli/middleware.py`; до их принятия upstream runtime нельзя считать
исправленным только по этому локальному derivative.

У upstream MCP server есть отдельный статический `EXPOSED_TOOLS` allowlist и
нет AIAgent session policy: это отдельный out-of-session API-контракт, который
не смешан с доказательством ограниченного AIAgent. Если MCP server будет
подключён как transport ограниченного агента, требуется отдельный upstream
патч, передающий и проверяющий session scope; текущий результат это не
утверждает.

Постоянный Hermes Agent остаётся `NO-GO`, пока не закрыты остальные P0-блокеры
родительской задачи, включая billing, supply-chain/dependencies, нагрузку,
эксплуатационный допуск и отдельные owner approvals.
