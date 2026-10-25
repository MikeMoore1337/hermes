# OmniRoute: изолированная проверка маршрутизации без расходов (#572)

**Статус:** OFFLINE_ORACLE_ONLY / ORIGINAL_RUNTIME_NOT_TESTED / LIVE_DISPATCH_DENY. Это **не** установка OmniRoute, интеграция с Hermes, подтверждение бесплатного тарифа или проверка реального биллинга. Production Hermes и BRC не затрагиваются.

## Точные источники

- Original: [cheaper-inference/OmniRoute](https://github.com/cheaper-inference/OmniRoute), [commit 5b3be70ba82ce70b59d02e2893afa3d81b6ee88b](https://github.com/cheaper-inference/OmniRoute/tree/5b3be70ba82ce70b59d02e2893afa3d81b6ee88b), package version 3.8.53, MIT license (Git blob b5c9f58d06b1cef61ebf96f580d90c3dba5e1dac).
- [docs/security/GUARDRAILS.md](https://github.com/cheaper-inference/OmniRoute/blob/5b3be70ba82ce70b59d02e2893afa3d81b6ee88b/docs/security/GUARDRAILS.md), Git blob 796c42362325b383bba985bc5c2845bea0c4baa0: upstream прямо описывает *fail-open* при исключении guardrail и неполное покрытие маршрутов/ответов. Это не самостоятельная граница «$0 гарантированно».
- [comboQuotaOnlyFallback.ts](https://github.com/cheaper-inference/OmniRoute/blob/5b3be70ba82ce70b59d02e2893afa3d81b6ee88b/src/app/%28dashboard%29/dashboard/combos/comboQuotaOnlyFallback.ts), Git blob 8f879b3160a441ffa6738660e5252dc59562a447: fallbackOnlyOnQuotaExhaustion настраивает fallback, но не проверяет цену модели/тариф. На закреплённом upstream оригинальный helper уже был исполнен с синтетической записью costUsd:10; цена сохраняется. Это **не** доказательство отсутствия других возможных защит в upstream.
- README сообщает, что prompts отправляются выбранному upstream поставщику. «Локальный gateway» не означает «данные никогда не выходят с хоста».

## Существующие границы Hermes

Hermes #62: только утверждённый Cloudflare Workers AI Free и конкретная разрешённая модель, без платного fallback. Историческая owner attestation сохранена; её нельзя подменять свежей гарантией отсутствия счетов. Hermes #295 владеет quota monitoring, #271 — очередью, #33/#291 — эксплуатационными gates. **Не добавляем второй прокси, монитор или scheduler**.

## Independent negative oracle

Файл tests/test_omniroute_free_only_policy.py — **только** независимая Python unittest-матрица на вымышленных поставщике/модели/домене .invalid. В ней нет imports OmniRoute, network I/O, ключей, runtime adapters или производственных решений. Она задаёт условия, которые будущая реальная интеграция обязана удовлетворить сама, прежде чем рассматривать live:

- unknown/поддельный provider или model, неразрешённый egress, неподтверждённый отдельный free/nonbillable account — DENY;
- неизвестные/нулевые/отрицательные quotas, snapshot старше **условного** тестового SLA 300 секунд — DENY;
- HTTP 401/402/403/429 и серверные ошибки, retries, fallback в paid/unknown, cycles и граф свыше лимита — DENY;
- любые raw chat/secret fields в synthetic trace и несинтетический payload — DENY;
- один безопасный вымышленный hop — SYNTHETIC_ORACLE_ACCEPTS_SHAPE_ONLY, не ALLOW_LIVE.

Запуск без зависимостей: python3 -m unittest tests.test_omniroute_free_only_policy -v

Эти тесты **не выполняют код OmniRoute**. Зелёный тест означает только полноту локального списка отрицательных условий, не реальную защиту gateway от списаний/утечки и не фактическую интеграцию.

## Решение и следующий допуск

**Текущий вердикт — NO_GO_FOR_DIRECT_ADOPTION:** upstream fail-open / ограниченное покрытие guardrails и quota-only fallback без подтверждения $0 несовместимы с требованиями Hermes. Не ставить/запускать оригинальный сервер, не передавать реальные secrets/prompts, не включать hooks или provider calls.

Вариант FORK рассматривать лишь после проверки на реальном upstream *каждого* сетевого/provider/fallback пути с независимой fail-closed границей, без второй системы квот, и доказательства необходимости относительно существующего Cloudflare Free. Настоящий live trial потребует отдельного no-cost/account/egress разрешения владельца. Пока это BLOCKED, BRC не нужен для данного offline отчёта.

Rollback: отдельным PR убрать только source-only тест и документ. Никаких runtime действий или записей в иные проекты не было.
