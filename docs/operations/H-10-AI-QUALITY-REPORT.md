# H-10: отчёт о качестве AI без подмены MOCK и финансовых фактов

Задача #62: анализ результата уже существующего offline или отдельно
разрешённого live пилота. Отчёт не делает вызов модели и не читает
секреты, счёт или API Cloudflare. Вход: JSON-массив из действующего
scripts.hermes_ai_pilot compare --json либо run --json.

python3 -m scripts.hermes_ai_pilot compare --json > pilot-results.json
python3 -m scripts.hermes_ai_quality_report --stdin < pilot-results.json

Значения:
- mock_cases: локальные подставные ответы, НЕ доказательство LLM.
- live_observed_cases: реально сообщённые пилотом вызовы, если есть.
- live_schema_accepted_cases: прохождение JSON/инвариантов, НЕ экспертная
  научная оценка.
- reported_provider_cost_usd: только если в КАЖДОМ live наблюдении
  есть числовое поле стоимости провайдера; иначе NOT_VERIFIED.
  Даже если API сообщил 0, это не гарантия отсутствия расходов.
- provider_neurons: только фактически предоставленные числовые
  Neurons для всех live наблюдений, иначе NOT_VERIFIED/NOT_RUN.
- scientific_quality_verified=false и billing_guaranteed_free=false
  не заменяются успехом тестов или пустыми значениями.

Сводка не изменяет баланс Cloudflare, файл бюджета, VPS, systemd,
YFC/Second Brain, Telegram, не выполняет инструментов/публикаций.
Это P2 функциональная отчётность, а не разрешение на resident Agent:
#33 остаётся OPEN/NO-GO. Нельзя считать вручную исправленный JSON
доказательством качества неотредактированного ответа модели.
