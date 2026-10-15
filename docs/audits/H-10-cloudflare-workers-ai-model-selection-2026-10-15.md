# H-10 — выбор модели Cloudflare Workers AI для ограниченного пилота

**Дата проверки документации:** 15.10.2026. Проверены официальные страницы Cloudflare Pricing, Limits, Errors, OpenAI compatibility, JSON Mode и страниц моделей. Это проверка публичных условий, а не подтверждение тарифа конкретного аккаунта.

## Решение

Основной кандидат пилота — `@cf/openai/gpt-oss-20b`. Он уже закреплён в существующем Hermes-плагине, доступен через OpenAI-compatible Chat Completions, имеет function calling, reasoning и контекст 128k. Для Hermes это минимальное изменение: используется текущий провайдер и один фиксированный model ID.

Официальная страница JSON Mode не перечисляет GPT-OSS 20B в текущем списке моделей с гарантируемым JSON Mode. Поэтому пилот не считает ответ модели структурированным автоматически: используется строгий prompt-контракт, локальный JSON-парсер и локальный валидатор. Ошибка схемы — отказ, а не повтор или fallback.

| Модель | Что подтверждено документацией | Решение |
| --- | --- | --- |
| `@cf/openai/gpt-oss-20b` | Chat Completions, function calling, reasoning, контекст 128k; JSON Mode не следует считать подтверждённым для этого model ID | Основной кандидат |
| `@cf/meta/llama-3.3-70b-instruct-fp8-fast` | Chat Completions/function calling, контекст 24k; перечислена в документации JSON Mode | Альтернатива для отдельного последующего сравнения, сейчас не включена |
| `@cf/qwen/qwen3-30b-a3b-fp8` | Мультиязычность, function calling, контекст 32k; JSON Mode для этого ID не подтверждён в списке документации | Не включена в текущий пилот |
| `@cf/meta/llama-3.2-3b-instruct` | Мультиязычный диалог, контекст 80k; требуемый tool/function contract здесь не подтверждён | Не включена в текущий пилот |

Источники: [GPT-OSS 20B](https://developers.cloudflare.com/workers-ai/models/gpt-oss-20b/), [OpenAI-compatible API](https://developers.cloudflare.com/workers-ai/configuration/open-ai-compatibility/), [JSON Mode](https://developers.cloudflare.com/workers-ai/features/json-mode/), [Llama 3.3 70B](https://developers.cloudflare.com/workers-ai/models/llama-3.3-70b-instruct-fp8-fast/), [Qwen3 30B](https://developers.cloudflare.com/workers-ai/models/qwen3-30b-a3b-fp8/), [Llama 3.2 3B](https://developers.cloudflare.com/workers-ai/models/llama-3.2-3b-instruct/).

## Free, Paid и измерение квоты

Публичная документация указывает для Workers Free 10 000 Neurons в сутки, со сбросом в 00:00 UTC. Превышение бесплатной квоты требует Workers Paid; цена на странице Neurons не является подтверждением нулевого бюджета конкретного аккаунта. Лимит текстовых запросов и модельные ограничения могут меняться, поэтому пилот дополнительно ограничивает число случаев локально.

Модели, для которых документация требует Workers Paid, не могут стать fallback этого пилота. В частности, ответ Cloudflare с кодом 5035/HTTP 403 означает требование платного тарифа. Код 3036/HTTP 429 означает исчерпание дневной бесплатной квоты; код 3040/HTTP 429 — временное превышение capacity. Все такие ответы прекращают пилот без повторов.

Использование Neurons фиксируется только из фактического ответа провайдера, если поле присутствует. При отсутствии фактической стоимости результат содержит `COST_NOT_VERIFIED` на уровне отчёта, а не рассчитанную оценку.

См. [официальные цены](https://developers.cloudflare.com/workers-ai/platform/pricing/), [лимиты](https://developers.cloudflare.com/workers-ai/platform/limits/) и [коды ошибок](https://developers.cloudflare.com/workers-ai/platform/errors/).

## Статус конкретного аккаунта

`ACCOUNT_FREE_UNVERIFIED`. В текущей работе не выполнялись запросы к Cloudflare, не читались секреты и не менялись настройки оплаты. Наличие API-токена, model ID или исторического однократного HTTP-ответа не подтверждает Workers Free и отсутствие платного Unified Billing.

До отдельного owner approval владелец должен самостоятельно проверить в Dashboard тот же Account ID: Workers Free, отсутствие AI Gateway Unified Billing/кредитов, остаток дневной квоты и разрешённость именно `@cf/openai/gpt-oss-20b`. Для локального запуска передаётся только внешний JSON-attestation с SHA-256 Account ID; токен в чат, Git и отчёты не попадает.

## Граница этой проверки

Здесь не выполнялись реальные model calls, не включался постоянный агент, не добавлялся второй провайдер и не утверждается качество настоящей LLM. Модельный выбор — технический кандидат для строго ограниченного ручного пилота, а не решение о production-развёртывании.
