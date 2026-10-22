# Hermes H-495: минимальный read-only каталог возможностей агентов

**Issue:** [#495](https://github.com/MikeMoore1337/hermes/issues/495). Связанные: [H-09 #61](https://github.com/MikeMoore1337/hermes/issues/61), Toolkit [#199](https://github.com/MikeMoore1337/ai-development-toolkit/issues/199) и [#200](https://github.com/MikeMoore1337/ai-development-toolkit/issues/200).

## Зачем и чем отличается от H-09

- H-09 `integrations/candidates.json` + `integrations/registry.py` уже фиксирует допуск внешних API/MCP/CLI по стоимости, эффектам, доступам и подтверждённым фактам. **Это канонический источник. Не добавлять новый список провайдеров.**
- H-495 `agent_capabilities/catalog.json` связывает агентную специализацию с отдельной *операцией* и с конкретным `integration_id` H-09. Наличие записи **не означает**, что агент, сервис или внешний клиент сейчас работает.
- `agent_capabilities/registry.py` предоставляет `preview(...)` только для offline-планирования. Он не вызывает инструменты, не загружает навыки, не меняет сервисы, не запускает модели и не выдаёт разрешения.

Сейчас все `availability=NOT_VERIFIED`; `source_revision=NOT_VERIFIED` отражает отсутствие подтверждённого runtime SHA. `CANDIDATE_ONLY` означает лишь отсутствие очевидного конфликта с текущей H-09 политикой при **переданных непроверенных** разрешениях. Результат всегда содержит `runtime_activation=NOT_AUTHORIZED` и `action_executed=false`.

## Отрицательные правила

- Неизвестное действие, интеграция или неверный JSON -> `REFUSED`.
- Требуемых прав нет, область данных расходится с H-09, неизвестна стоимость, интеграция DEFER/REJECT -> `REFUSED`.
- `owner_notification` и другие побочные действия -> `REFUSED`, отдельный допуск через утверждённый рабочий контур.
- Произвольное объявление `availability=RUNNING` в JSON -> ошибка схемы, не «самоподтверждение».
- Никаких write actions, OS/network permissions, secret scopes, вызовов Cloudflare/платных API или доступа к Second Brain vault.

## Проверка

```bash
python3 -m unittest tests.test_agent_capabilities -v
python3 -m integrations.registry --validate
python3 scripts/validate_repo.py
python3 -m unittest discover -s tests -v
```

Запуск проверок в CI и получение зелёного exact HEAD - отдельное фактическое подтверждение, не следствие появления этого документа. Работающий Hermes BRC и production не проверяются данным PR.

## Дальнейшая приёмка

Для перехода от кандидата к разрешённому действию нужна отдельная задача: конкретный живой endpoint и его версия, проверенные возможности runtime, подтверждённые права и quotas, policy enforcement на границе реального исполнительного процесса, негативные E2E на отказ и действующий owner gate. По умолчанию никаких resident skills, переноса Toolkit внутрь агента и новых контроллеров.
