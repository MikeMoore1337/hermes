# H-01 #33 - ограниченная наблюдаемая CycloneDX-инвентаризация v0.22.1

Дата: 15.10.2026. Хост проверки: отдельный Windows Docker Desktop, production VPS не менялся.

## Фактическая проверка

- Исходный immutable Linux/AMD64 Docker image: sha256:cd9cb455576d27c9b6311de1104494ad7e221b6e68dc77e9ac2a8af661a4dc21.
- Встроенный source commit: 297552a9d646119871391d202509822cd86330df.
- Реальный изолированный инспектор: 274 dpkg entries, 146 Python metadata entries, 1 повтор одинаковой канонической идентичности, 419 уникальных компонентов.
- Создан файл docs/sbom/hermes-v0221-amd64-observed.cdx.json в CycloneDX 1.5, SHA256: 45f52a61878f892bc3d0d420b1504d3356ed1a06a8d008069ed1c66b896bb48c.
- Отрицательные тесты: иной digest, неверный source stamp, изменившееся количество пакетов, конфликтующие версии, повтор JSON-ключа и отказ перезаписывать доказательства.

## Воспроизведение

Из корня репозитория на отдельной машине с уже установленным pinned image:

~~~sh
python -m scripts.export_v0221_observed_sbom
python -m scripts.export_v0221_observed_sbom --execute --output docs/sbom/new-review.cdx.json
~~~

Первый вызов ничего не запускает. Второй намеренно возвращает exit 2 даже при успешном сборе, потому что частичный BOM не даёт разрешение на постоянный AI Agent. Указанный выходной файл должен отсутствовать до запуска.

Инспектор использует существующие неизменённые Docker-команды verify_v0221_local_image: --pull=never, --network none, --read-only, --cap-drop ALL, no-new-privileges, непривилегированный пользователь 65534, 0.25 CPU, 256 MiB RAM, 25 PID, максимум 30 секунд; ни токенов, ни подключений к приватным томам, ни запросов модели. Проверяются stamp и идентичность закреплённого образа. Только локально наблюдаемые dpkg и основная virtualenv.

## Что именно НЕ доказано

- Это не полная SBOM: не охвачены содержимое встроенных Python/Node/npm runtimes, файлы вне package-manager, отношения зависимостей и все исполняемые файлы.
- Нет независимого подтверждения лицензий, анализа уязвимостей, подписанной цепочки source-to-build-to-image и аттестации поставщика.
- Никаких живых проверок биллинга, безопасности полномочий/сети в resident-режиме и нагрузочного burn-in этот тест не проводит.
- Парная запись hermes-agent в metadata уже ранее была признана физически одним каталогом, но этот BOM сам по себе не проверяет inode.

**Итог: наблюдаемая частичная инвентаризация PASS; полный source/image provenance NO_DATA; постоянный AI Agent NO-GO.**

## Проверки 15.10.2026

- Отдельный Windows Python 3.14: 6/6 новых тестов PASS.
- Отдельный offline Linux-контейнер pinned v0.22.1 с read-only bind /work, no network, 0.5 CPU, 768 MiB RAM, no-new-privileges: **676/676 PASS**, exit 0.
- scripts/validate_repo.py: PASS, 188 required files.
- JSON parser: PASS; git diff --check: PASS.
- Полный набор на Windows напрямую НЕ прошёл из-за POSIX-only модулей fcntl/os.geteuid/O_NOFOLLOW; результаты Linux-тестов относятся к реально поддерживаемой платформе.

## Ревью P0-A от 15.10.2026

- Исправлен риск неограниченной буферизации `stdout` и `stderr`: новый общий `scripts/bounded_subprocess.py` читает оба потока параллельно с лимитами байтов, принудительно прекращает процесс и его дочерние процессы при переполнении или таймауте и не отражает сырой stderr. `CompletedProcess.args` очищен, чтобы не раскрывать аргументы с возможными секретами.
- Реальные Windows Python 3.14 тесты ограниченного процесса: 13/13 PASS. Linux офлайн Docker: 690/690 PASS.
- Официальная JSON Schema CycloneDX 1.5 из `CycloneDX/specification` tag `1.5`, SHA256 `067f7824b08653839ea050ae9e09ca48375eadc2652b0e2a299476e7db90335b`: формальная проверка jsonschema в изолированном Docker PASS, 419 компонентов, 0 ошибок.
- На Windows checkout Git преобразовывал LF в CRLF, меняя SHA готового JSON. Добавлена `.gitattributes` с LF для `docs/sbom/*.json`; нормализованный файл совпал с заявленным SHA256 `45f52a61878f892bc3d0d420b1504d3356ed1a06a8d008069ed1c66b896bb48c`.
- Отношения зависимостей, PURL, лицензии, хеши установленных пакетов не измышлялись. Документ остаётся частичной наблюдаемой инвентаризацией, **не** удостоверением происхождения и **не** разрешением resident Agent.
