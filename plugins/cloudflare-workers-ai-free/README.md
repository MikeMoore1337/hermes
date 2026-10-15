# Hermes Cloudflare Workers AI Free - проверяемое подключение

**Статус: `ACCOUNT_FREE_UNVERIFIED`; подготовлено для изолированной установки, реальные запросы в текущем пилоте не выполнялись. Никаких оплачиваемых действий.**

## Зачем собственный вариант

Основа: MIT-плагин [AhmetArif0/hermes-cloudflare-workers-ai-provider](https://github.com/AhmetArif0/hermes-cloudflare-workers-ai-provider) на подтверждённом SHA `f6821d058d504ee6324b0d3217564b93124c09f9`.

Исходный плагин рекламирует также семь **платных** моделей и возвращает `should_fallback=True` на Free-entitlement 403. Для проекта Hermes с жёстким запретом платных моделей это неприемлемо. Поэтому локальная производная версия сознательно **разрешает только** `@cf/openai/gpt-oss-20b`, удаляет платные и дополнительные fallback-модели и запрещает автопереключение при 402/403/429. Сохраняются MIT-уведомления об авторстве.

Если конкретный аккаунт действительно остаётся на **Workers Free**, то по официальному [прайсу](https://developers.cloudflare.com/workers-ai/platform/pricing/) для него действует 10 000 Neurons/сутки; текущий аккаунт Hermes этим документом не подтверждён. На Workers Paid автоматическое сверхлимитное списание возможно: **не переходить на Paid**.

## Необходимый доступ

- [Cloudflare Dashboard / Workers AI](https://dash.cloudflare.com/?to=/:account/ai/workers-ai) -> Use REST API -> Create Workers AI API Token -> Account ID.
- Профиль должен оставаться **Workers Free**, без платных AI Gateway credits, без Unified Billing.
- `CLOUDFLARE_WORKERS_AI_API_TOKEN` и `CLOUDFLARE_WORKERS_AI_BASE_URL=https://api.cloudflare.com/client/v4/accounts/<ACCOUNT_ID>/ai/v1` предназначены только для отдельного хранилища `/var/lib/hermes-agent/.env` с режимом 0600 и владельцем `hermes-agent`.
- **Никогда не помещать ключ в GitHub, чат, команды CI или системный журнал.** Код не пытается находить токены YFC.

## Изолированное локальное развёртывание

После объединения PR и проверки CI доставить `plugins/cloudflare-workers-ai-free` и `deploy/install-cloudflare-free.sh` на текущий Hermes VPS под `/opt/hermes-agent-owner/`, сверить git blob SHA и выполнить:

```bash
bash /opt/hermes-agent-owner/deploy/install-cloudflare-free.sh
```

Скрипт создаёт каталог плагина с правами 0700 и `config.yaml` с одним бесплатным вариантом, **не записывает и не запрашивает ключ**, не подключает сеть, не включает systemd или gateway. Если каталог уже присутствует - отклоняет перезапись.

Для проверочного запуска можно передать **синтетический** токен и несуществующий Account ID через переменные окружения контейнера с `--network none` и проверить обнаружение плагина: это проверка структуры, не реальный ответ модели.

## Перед разрешённым реальным запросом

Понадобится отдельный утверждённый сетевой контур, позволяющий только `api.cloudflare.com:443` и запрещающий private IP, Docker socket, внутреннюю сеть, а также реальная проверка ответов и измерение Neurons/сутки. Обычный unrestricted Docker bridge не подходит. До подключения credentials модельное взаимодействие не заявлять как работающее.

Важный предел: даже при небольшом расходе Neurons стандартный Hermes может посылать много инструментов, и размер запроса/качество функции вызова требуют **живого** испытания. Не включать автоматические публикации или write-инструменты после первого удачного текстового запроса.


## Завершённая проверка, 2026-10-14

[Протокол](../../docs/audits/H-01-cloudflare-free-preflight-2026-10-14.md): в текущем защищённом Hermes runtime провайдер обнаружен, платные модели отклонены без API-запросов; отдельного Cloudflare token пока нет. Для безопасного получения ключа предусмотрен `deploy/set-cloudflare-free-credentials.sh`, запускаемый владельцем лично через SSH. Не передавать секрет в чат и не активировать systemd до проверки сетевых ограничений.
