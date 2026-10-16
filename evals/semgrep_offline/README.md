# H-21 / #188 — изолированный Semgrep CE pilot

Пять узких Python-правил и синтетические пары `*.yaml` + `*.py`.
Они НЕ защищают runtime Hermes и не заменяют OS-level ограничения
инструментов / network egress / P0 #33. К ним не подключены никакие
продуктовые секреты, API-ключи, сервисы и сторонние облачные проверки.

Проверяются: `subprocess.run/Popen/call(shell=True)`, `os.system`,
`requests.get/post/request(verify=False)`, `httpx.Client(verify=False)`,
`jwt.decode(... verify_signature=False)` и прямой вывод переменных
`os.environ` с чувствительными названиями в print/logger.
Каждый пример содержит `ruleid:` и `ok:`. Это **pattern-based**
проверки, не taint-анализ: алиасы, динамические kwargs и несколько
разнесённых по файлам вызовов могут остаться незамеченными.
`jwt.decode(... verify_signature=False)` иногда используется
для *неавторизованной диагностики после отказа проверки*; для такого
контекста правило может давать ложные срабатывания. Любое совпадение
требует анализа, а не автоматического блокирования сборки.

## Verified local pilot, 16.10.2026

- Semgrep CE CLI `1.181.0`, Docker image exact Linux/AMD64:
  `semgrep/semgrep@sha256:c47e426f7f0cfa19af6d7877560d0a7135f683b8090ad0efc97c4ec7810dc435`.
  Image manifest digest наблюдался через `docker buildx imagetools inspect`
  официального `semgrep/semgrep:1.181.0`; версия CLI проверена реальным
  запуском. Независимая подпись/SLSA-происхождение image НЕ проверены.
- Реальный `semgrep test /work`: **5/5 tests passed**, exit 0,
  строка вывода: `5/5: ✓ All tests passed`.
  с тем же pinned image digest.
- Вызов выполнялся на отдельном Windows Docker Desktop, без VPS,
  `--network none`, `--pull=never`, `--read-only`, `--user 65534`,
  `--cap-drop ALL`, `--security-opt no-new-privileges`,
  CPU/RAM/PIDs ограничены; synthetic fixture смонтирован только для чтения.
- Воспроизводимость `semgrep test` - не security attest.
  Полный scanner supply chain (включая зависимости Docker image)
  не сертифицирован.

Пример команды на Linux, при уже проверенном локальном образе:

```bash
IMAGE='semgrep/semgrep@sha256:c47e426f7f0cfa19af6d7877560d0a7135f683b8090ad0efc97c4ec7810dc435'
docker run --rm --pull=never --network none --read-only \
  --user 65534:65534 --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 80 \
  --cpus 1 --memory 1024m --memory-swap 1024m \
  --tmpfs /tmp:rw,nosuid,nodev,size=160m \
  -e HOME=/tmp -e SEMGREP_SEND_METRICS=off \
  --mount type=bind,src="$PWD/evals/semgrep_offline",dst=/work,readonly \
  --entrypoint semgrep "$IMAGE" test /work
```

В GitHub Actions Hermes нет auto-install Semgrep, внешнего rule registry,
`semgrep ci`, auto-upload или сканирования приватных исходников.
`python3 -m unittest tests.test_h21_semgrep_fixtures` лишь проверяет
локальный контракт файлов без выполнения Semgrep. Настоящие результаты
отдельного Docker-пилота находятся в
[аудите](../../docs/operations/H-21-SEMGREP-OFFLINE-EVIDENCE.md).

Прежде чем переносить правило в YFC, нужно доказать дополнительную пользу
относительно **уже работающих CodeQL и Trivy** и оценить ложные
срабатывания. Second Brain можно рассматривать позже только в рамках
публичного кодового репозитория, не private vault, с отдельным PR и GO.
Никакой prod deploy, webhook, GitHub token, cloud model или лицензия
стороннего SaaS для этого пилота не нужны.
