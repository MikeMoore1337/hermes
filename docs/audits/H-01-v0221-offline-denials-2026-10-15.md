# H-01 #33 - реальные отрицательные испытания OS/container на v0.22.1

Дата: 15.10.2026. Только изолированный Windows Docker Desktop с локальным immutable image `sha256:cd9cb455576d27c9b6311de1104494ad7e221b6e68dc77e9ac2a8af661a4dc21`. Без запуска Hermes CLI/LLM, без доступа к YFC/Second Brain, без production systemd/network changes.

## Воспроизведение

~~~sh
python -m scripts.verify_v0221_isolated_denials
# NOT_EXECUTED
python -m scripts.verify_v0221_isolated_denials --execute
# OFFLINE_SANDBOX_DENIALS_PASS_SHELL_AVAILABLE, exit 2
~~~

Инспектор в pinned Docker наследует `--pull=never --network none --read-only --cap-drop ALL --security-opt no-new-privileges --user 65534:65534 --cpus 0.25 --memory 256m --memory-swap 256m --pids-limit 25`, без host mounts или credentials. Ограниченный по stdout/stderr/времени хостовый вызов.

## Реально измерено

| Сценарий | Итог |
|---|---|
| UID/EUID 65534, не root | PASS |
| Linux CapEff=0 | PASS |
| Cgroup CPU <= 0.25, RAM <= 256 MiB, PIDs <= 25 | PASS |
| Запись в /opt/hermes | DENIED / PASS |
| Docker socket | отсутствует / PASS |
| Подключение к TEST-NET 192.0.2.1 | DENIED / PASS |
| Подключение к metadata 169.254.169.254 | DENIED / PASS |
| Известные сервисные токены отсутствуют в окружении | PASS |
| Безвредный дочерний процесс /bin/sh -c true | **EXECUTABLE** |

8/8 наблюдаемых OS-инвариантов PASS. Но **Shell реально запускается** в таком контейнере. Это не доказательство того, что полный Hermes Agent выдаст доступ к shell tool; это доказательство, что Docker ограничения не запрещают запуск произвольного дочернего процесса. Права tools/hooks/plugins, prompt injection, SSRF в настоящей сети, Cloudflare billing gate, production изоляция, длительная устойчивость - NOT_RUN/NO_DATA.

Скрипт намеренно возвращает exit 2 и resident_agent_allowed=false даже при PASS. При `--network none` отказы в соединениях не означают доказательство правильности nft allowlist с разрешённым Cloudflare egress. Никаких опасных действий или изменений рабочих сервисов нет.
