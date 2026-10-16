# H-01 #33 - ограничение native tool scope: реальная offline проверка

Дата: 15.10.2026. Отдельный Windows Docker Desktop, закреплённый Linux/AMD64 Hermes v0.22.1:
`sha256:cd9cb455576d27c9b6311de1104494ad7e221b6e68dc77e9ac2a8af661a4dc21`.

## Проверенный вопрос

Существует ли технический запрет на прямую передачу `terminal` в низкоуровневый
`model_tools.handle_function_call`, если сеансовый каталог инструментов его исключает?

- Для `enabled_toolsets=["safe"]`, `disabled_toolsets=["terminal"]` исходный
  `_select_tool_names` **не содержит** `terminal`.
- Прямой вызов `handle_function_call("terminal", ...)` с теми же ограничениями
  доходит до `_execute_tool`, что наблюдается через `unittest.mock.patch.object`.
- Замещённый `_execute_tool` возвращает синтетическую строку; ни `terminal`,
  ни другая команда реально не исполняются.
- `pre_tool_call` и `tool_request` middleware не отключались тестом.
- Результат: `DIRECT_NATIVE_SCOPE_GAP_OBSERVED`, `terminal_listed=false`,
  `native_dispatch_reached=true`, `real_tool_executed=false`.

Это **доказанный пробел в проверке ограничения набора инструментов в исследованном
низкоуровневом вызове**. Пока **НЕ** доказано, что полный Hermes Agent сможет
получить неожиданный native tool call от реального провайдера, обойти другие
runtime-политики или выполнить shell через интерфейс модели.

## Воспроизведение

На отдельном компьютере с заранее загруженным pinned образом:

```sh
python -m scripts.verify_v0221_native_tool_scope
# NOT_EXECUTED
python -m scripts.verify_v0221_native_tool_scope --execute
# DIRECT_NATIVE_SCOPE_GAP_OBSERVED, намеренный exit 2
```

Используются только `docker image inspect` и один `docker run`: `--pull=never`,
`--network none`, `--read-only`, `--cap-drop ALL`, nonroot, лимиты CPU/RAM/PID,
временная отдельная `/tmp` (tmpfs), нулевые credentials и запрет доступа к
host mounts. Реальная функция исполнения инструмента замещена до вызова.

## Что не проверялось

- Реальная отправка native tool call из ответа провайдера через полный `AIAgent`.
- Политика shell/hooks/plugins при выполнении настоящего инструмента.
- Production network policy, write permissions, Cloudflare billing и нагрузка.
- Source-to-image attestation и исправление upstream-политики.

Для допуска постоянного агента требуется end-to-end fail-closed тест
для **native и tool_search bridge** с фактическим отказом без вызова executor.
Не интерпретировать фильтрацию списка инструментов как достаточную защиту.

**Режим: NO-GO.** Код проверки всегда возвращает `resident_agent_allowed=false`
и exit 2 даже при успешном измерении. Новые модельные запросы и production
операции не выполнялись.
