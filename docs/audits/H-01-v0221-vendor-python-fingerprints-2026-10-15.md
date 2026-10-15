# H-01 #33 - SHA256 отпечатки встроенных vendor Python-файлов

Дата: 15.10.2026. Изолированный Windows Docker Desktop, работающий VPS не изменялся.

## Результат

- Проверен конкретный immutable Linux/AMD64 image sha256:cd9cb455576d27c9b6311de1104494ad7e221b6e68dc77e9ac2a8af661a4dc21.
- Встроенный source stamp: 297552a9d646119871391d202509822cd86330df, Hermes v0.22.1.
- Проверены и записаны SHA256 и размер каждого из 1176 Python-файлов во встроенных runtime: Python 3.14.7 = 1059, Node 26.7.0 = 59, npm 12.0.2 = 58.
- Общий размер измеренных исходных файлов: 19 252 785 байт.
- Детерминированный JSON: docs/sbom/hermes-v0221-vendor-python-sha256.json, SHA256 29a5d3bc3b84c0ac2d974d6d3369820817a0eb2d551e494b49744fe086cafe08.

## Выполнение

~~~sh
python -m scripts.verify_v0221_vendor_fingerprints
python -m scripts.verify_v0221_vendor_fingerprints --execute --output docs/sbom/new-vendor-review.json
~~~

Первый вызов NOT_EXECUTED; второй на уже загруженном pinned image ожидаемо возвращает exit 2 и блокирует resident GO. Результат создаётся только при отсутствии целевого файла.

Наследуются ограничения Docker из scripts.verify_v0221_core_python: --pull=never, --platform linux/amd64, --network none, --read-only, --cap-drop ALL, no-new-privileges, непривилегированный пользователь, 256 MiB RAM, 0.25 CPU, 25 PID. Нет host mounts, токенов, доступа к YFC, вызовов модели, публикаций и сервиса.

На стороне Python отвергаются неожиданный immutable digest, неверный stamp, symlink или ошибка инспектора, смена количества файлов, повтор пути, выход из разрешённых каталогов, неверный SHA256/размер и чрезмерный объём данных. Отчёт не печатает содержимое файлов.

## Ограничения

Это инвентаризация 1176 наблюдаемых Python-файлов, **не подтверждение upstream-происхождения содержимого**. Дополнительно не охвачены vendor executable/JS binaries, прочие файлы embedded runtimes, оригинальные подписанные дистрибутивы, лицензии, CVE/OSV, supplier attestation и source-to-build-to-image provenance. Не применяется как разрешение на постоянный запуск агента. Следующий независимый шаг - сверка SHA/дистрибутивов с официальными upstream release источниками и инспекция остальных файлов. Статус NO-GO.

## Проверки

- 6/6 новых unittest PASS в Windows Python 3.14.
- 676/676 offline Linux Docker unittest PASS с исходниками только для чтения; exit 0.
- scripts/validate_repo.py PASS (188 required files); JSON parse PASS.

## Ревью P0-A 15.10.2026

- PR #133 теперь зависит от PR #132: для обеих веток используется **один** `scripts/bounded_subprocess.py`, без второго механизма. `verify_v0221_vendor_fingerprints.collect()` больше не использует необязанный `subprocess.run(capture_output=True)` по умолчанию; лимиты `stdout=400000`, `stderr=16384`, отдельно идентификация image (8192 байт) и timeout 10/90 секунд.
- В реальном Docker Desktop повторно считаны все 1176 vendor Python файлов; канонический SHA256 JSON `29a5d3bc3b84c0ac2d974d6d3369820817a0eb2d551e494b49744fe086cafe08` совпал. LF зафиксирован правилами `.gitattributes` зависимого PR #132.
- Недоверенный stdout/stderr не попадает в исключения или отчёты; запрет `resident_agent_allowed=false` и ожидаемый код выхода 2 сохранены.
