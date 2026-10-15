# H-01 - повторяемая локальная инвентаризация установленного образа

**Назначение:** восполнить критический пробел в старой проверке image: `dpkg-query` учитывал 274 системных пакета, но исключал отдельную Python virtualenv основного Hermes. Проверка на VPS 15.10.2026 обнаружила `/opt/hermes/.venv/bin/python` Python 3.14.7 с **146 Python-дистрибутивами**. Отдельный системный `/usr/bin/python3` видел только один дистрибутив и **не репрезентативен** для основного приложения.

## Как выполнять

```bash
cd /opt/hermes-agent-owner
python3 scripts/image_local_inventory.py
# {"status":"NOT_EXECUTED"}

# Только после утверждённого GitHub CI и проверки точных source SHA на VPS:
sudo python3 scripts/image_local_inventory.py --execute
```

Инструмент допускает только существующий, закреплённый image digest `sha256:32d095e84190ae7266afbb361579e6921f2c633e899f5eacfb88111b9c851a22`, архитектуру amd64 и только read-only `docker image inspect` плюс **один** `docker run` с `--pull=never --network none --read-only --cap-drop ALL --security-opt no-new-privileges`, `--cpus .25 --memory 256m --memory-swap 256m --pids-limit 25`. Без network, host mounts, секретов, моделей, shell/MCP и запуска Hermes gateway.

Внутри контейнера фактическая virtualenv читает `importlib.metadata.distributions()`, а локальная система образа - `dpkg-query -W`. На хост возвращаются лишь минимальные пары название/версия. Проверяются форма, лимиты, уникальность и типы; порядок нормализуется, вычисляется воспроизводимый SHA256 сводного списка.

Результат сохраняется в `/var/lib/hermes-image-audit/local-components.json` (каталог `0700 root:root`, файл `0600 root:root`) с полями `os_packages_count`, `python_venv_packages_count`, `inventory_sha256`, `components` и флагами недоказанности.

## Что означает такой список

**Это не проверенная полная SBOM, не подпись издателя, не supply-chain provenance и не сканирование уязвимостей.** Установленные Python packages и dpkg packages могут не покрывать исполняемые файлы, npm/Node и иные среды, сторонние бинарники, контейнерные слои, vendored код, дерево зависимостей и происхождение build. Результат пригоден для сравнения составов конкретных image по immutable digest и выявления необычных пакетов.

В отчёте принудительно `supplier_sbom_verified=false`, `source_release_parity_verified=false`, `signature_verified=false`, `vulnerability_scan_complete=false`. Никакой единичный `PASS` **не разрешает** постоянную модельную службу. Текущий официальный `v0.21.6` Docker image совпал с embedded Git commit `a28a5d03` в четырёх пробных файлах, но по двум отличается от Git release tag `818c13be`; это остаётся серьёзным вопросом на P0.

### Приёмка

- Unit tests обязаны доказать отсутствие сети, pull, mounts, privileged и обработки raw package output без ограничений.
- Реальный запуск на VPS с подтверждённой venv 3.14.7, числом пакетов и hash; никакой замены image или systemd timers.
- Отдельно сравнить официальный release-tag source ↔ image и получить полный подписанный SBOM/provenance через издателя или независимую воспроизводимую сборку и проверку. Без этого H-01 #33 остаётся OPEN.
