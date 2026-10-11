# Безопасность Hermes

## Защищаемые активы

YFC production data, Telegram bot credentials, provider keys, GitHub permissions, Second Brain private vault, рабочие машины, GitHub Actions credentials и авторитетность опубликованных материалов.

## Основные угрозы и меры

| Угроза | Обязательная мера | Проверка перед runtime |
|---|---|---|
| Prompt injection из RSS/web/Issues | Недоверенные тексты только как данные; модель не может повышать собственные права | Вредоносная фикстура не вызывает запрещённый tool |
| Секреты в запросах/отчётах | Изоляция секретов по агентам, логирование только очищенных событий | Красные тесты на токены, HMAC, конфиги |
| Доступ к YFC или vault | Separate identity, scoped tool/API authorization, egress network ACL | Явный deny-test на private filesystem, DB, Docker socket |
| Неограниченные LLM-запросы/платные расходы | Жёсткая квота и fail-closed при исчерпании | Overflow и no-provider не переходят в платный fallback |
| Сбой новостного канала из-за агентов | Изолированные процессы, CPU/RAM/time лимиты и мониторинг | Отказ нового агента не влияет на таймер и editorial worker |
| Ложная публикация | Owner review в YFC; одна каноническая точка publish | Прямой outbound publish отклонён |
| Supply-chain, внешний SKILL.md | Exact tag/SHA, просмотр лицензии и содержимого, блокировать произвольную установку | Изменённый digest отклонён; SBOM/сканер при runtime |
| Ошибочный auto-deploy/merge | Нет workflows с write permissions/production secrets в bootstrap | CI имеет только `contents: read` |

## Правило по умолчанию

Нет tool = нет возможности вызвать его; **но декларативный файл не ограничивает реальный доступ автоматически**. Для полного Hermes Agent требуются доказанные runtime-проверки + ограничения ОС/сети. Любая внешняя интеграция проходит отдельный owner approval. Не использовать неофициальные OAuth subscription gateway.

## Что не происходит в этом репозитории

В bootstrap не создаются secrets, сервисные учётные записи, сетевые ACL, провайдеры, полномочия YFC или токены Second Brain. Эти действия не считаются выполненными.
