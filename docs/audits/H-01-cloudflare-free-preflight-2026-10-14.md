# Рабочая подготовка Cloudflare Workers AI Free для Hermes

Дата проверки: **2026-10-14**. Согласовано: отдельный Cloudflare Workers AI Free, без платных API, без использования ключа редакционного Hermes/YFC.

## Что действительно сделано

1. **Исследован** официальный бесплатный лимит Workers AI: 10 000 Neurons/сутки, без автоматического счёта на **Workers Free**, и официальный GPT-OSS 20B (128K контекст, поддержка вызова инструментов).
2. Проанализирован Community MIT-плагин [AhmetArif0](https://github.com/AhmetArif0/hermes-cloudflare-workers-ai-provider) на точном SHA `f6821d058d504ee6324b0d3217564b93124c09f9`.
3. Создана и протестирована ограниченная [собственная производная](../../plugins/cloudflare-workers-ai-free/): только `@cf/openai/gpt-oss-20b`, без платных и иных fallback-моделей, и `should_fallback=False` для 402/403/429. Сохранена MIT-лицензия и авторство.
4. Установка на действующем Hermes VPS: файлы проверены по Git blob SHA, размещены в `/var/lib/hermes-agent/plugins/cloudflare-workers-ai-free` с доступом только `hermes-agent`, `config.yaml` 0600, model=workers-ai/default=GPT-OSS 20B. Не подключена сеть.
5. **Офлайн-проверка на реальном Docker-образе v0.21.6** (pinned `sha256:32d095e8...`) с fake credentials, `--network none`, отдельный UID/GID, read-only каталог данных: вывод `PROVIDER_DISCOVERY_AND_FREE_ONLY_GATE_PASS`. Plugin loader реально обнаружил `workers-ai`; вызов с платной моделью отказал до API.
6. При этом Hermes предупредил, что не смог создать backup каталога config на read-only volume. Это предупреждение не свидетельствует об утечке или запросе модели; имелась только фиктивная учетная запись и сеть была выключена. Для работающего gateway предусмотрена собственная запись в закрытый каталог, как и ранее.
7. Новая systemd служба `hermes-agent-sandbox.service` **disabled / inactive**, существующий `hermes-discovery.timer` и `hermes-ops-watch.timer` остались active, resource guard READY.

**Не сделано:** реальный Cloudflare API-запрос, проверка квоты с реального аккаунта, ограниченный доступ в интернет для Hermes, настоящий agent turn, долгосрочный нагрузочный тест, пользовательские уведомления, внешний Research Scout. Отдельный Workers AI Account ID/API token пока не предоставлены, в `/var/lib/hermes-agent/.env` их нет.

## Единственный необходимый шаг владельца

1. Открыть [Cloudflare Dashboard -> Workers AI](https://dash.cloudflare.com/?to=/:account/ai/workers-ai), при необходимости создать бесплатную учётную запись, выбрать **Workers Free**, открыть **Use REST API**.
2. Нажать **Create a Workers AI API Token**. Получить Account ID и созданный отдельный токен, настроить только разрешения Workers AI, не включать платный тариф, prepaid credits и AI Gateway Unified Billing.
3. На компьютере в собственном терминале выполнить `ssh hermes-old` (или подключиться к Hermes VPS) и запустить:

```bash
sudo bash /opt/hermes-agent-owner/deploy/set-cloudflare-free-credentials.sh
```

Если SSH-сессия уже root, используйте `bash` без `sudo`. Скрипт запросит Account ID и токен **в терминале**, токен вводится скрыто, в чате/командах/логах не появляется. Дополнительно нужно подтвердить именно Workers Free. Установка запишет `/var/lib/hermes-agent/.env` с правами 0600, владельцем `hermes-agent`, с атомарной защитой от перезаписи. **Ничего не запускается и не отправляется в Cloudflare до отдельной проверенной сетевой настройки.**

Не присылайте токен в ChatGPT, Telegram, GitHub Issue или скриншоте. После выполнения просто сообщите «Ключ Cloudflare настроен» - без значения ключа и Account ID.

## Следующий технический этап

После появления токена: минимальный egress только к `api.cloudflare.com:443`, без доступа к private hosts/YFC/Second Brain, первый ограниченный текстовый запрос, затем read-only agent tool call и фактический счётчик Neurons. Ошибки 402/403/429 и неизвестная модель - отказ без fallback. Настоящая служба остаётся disabled до успешных negative tests, подтверждения лимитов и готовности.

Источники: [Cloudflare pricing](https://developers.cloudflare.com/workers-ai/platform/pricing/), [API tokens](https://developers.cloudflare.com/workers-ai/get-started/rest-api/), [GPT-OSS 20B](https://developers.cloudflare.com/workers-ai/models/gpt-oss-20b/), [Hermes plugin catalog](https://hermes-agent.nousresearch.com/docs/plugins/cloudflare-workers-ai-provider).
