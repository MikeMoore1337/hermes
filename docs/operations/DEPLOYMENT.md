# CI и будущий deployment

## Сейчас

Этот репозиторий не подключён к production. Единственный workflow `.github/workflows/quality.yml` выполняет статическую проверку файлов и unittest на GitHub-hosted runner. В нём нет production secrets, Docker socket, SSH, моделей, API или сервисных ключей.

## Когда появится runtime (после H-00 и отдельного owner GO)

- Зафиксировать версию/commit upstream Hermes и SBOM/подписи; не использовать `latest`.
- Отдельные OS user, data dir, секреты, ограничение egress и resources; не менять news worker как побочный эффект.
- CI соберёт и проверит кандидат; deployment допускается только отдельным утверждённым механизмом и после контроля изменений.
- Проверить failure/restart/idempotency, алерты, snapshot, clean shutdown и rollback.
- Релиз Hermes не должен запускать релиз YFC; обратное также недопустимо без явного совместимого контракта.
- В документации раскрывать только идентификаторы утверждённых версий и безопасные метаданные, не адреса серверов или токены.

## GitHub settings

Включить защиту основной ветки/required CI, если функция доступна для приватного репозитория; проверить через GitHub API и задокументировать результат. До проверки защиты правило no-direct-push является организационным, а не технически принудительным.

Использовать scoped token только при реальном CI/CD-переходе; в bootstrap токены не нужны.

## Подтверждённые ограничения GitHub (2026-10-11)

- Репозиторий **private**, основная ветка `main`.
- `delete_branch_on_merge=true`, `allow_squash_merge=false`, `allow_auto_merge=false` проверены через GitHub API.
- Попытка настроить защиту `main` с обязательным `static-and-tests` получила HTTP 403: **«Upgrade to GitHub Pro or make this repository public to enable this feature.»**. Защита ветки **не включена и не считается действующей**. Для приватности репозиторий публичным не делали; переход на платный тариф без разрешения не выполняли.
- До появления доступной GitHub branch protection соблюдать Issue -> branch -> PR -> CI -> ручное слияние организационно. Статус required check не является техническим запретом прямого push.
