# H777 - управляемая изоляция оригинального ECC в Hermes

**Область:** исходный код и изолированная приёмка. Это **не разрешение** на production-релиз, резидентный Hermes Agent, Windows native, MCP, хуки, Memory Vault или доступ к YFC/Second Brain.

## Решение вместо ожидания upstream

Оригинал [affaan-m/ECC](https://github.com/affaan-m/ECC) закреплён на SHA `b38be6a7f6350964d59328b52f0624e1d1d552d1` (MIT, ecc-universal 2.2.3). Его штатный `scripts/uninstall.js --target hermes` оставляет `.claude/ecc/state.db` и может создать этот файл при uninstall в пустом HOME. Дефект независимо подтверждён [H777 upstream regression](https://github.com/MikeMoore1337/hermes/actions/runs/42019864256) и описан в [ECC#3559](https://github.com/affaan-m/ECC/issues/3559#issuecomment-6150025865).

Мы **не исправляем** чужие исходники и **не удаляем** state.db в общем HOME. `scripts/h777_ecc_isolated_lifecycle.py` создаёт **новый приватный HOME**, устанавливает в него неизменённый ECC, а после его штатного деинсталлятора удаляет **только созданный им каталог** при успешной проверке содержимого. Это `MANAGED_ISOLATED_ROLLBACK`, а не `UPSTREAM_NATIVE_EXACT_ROLLBACK=PASS`.

## Модель безопасности

- Только unprivileged Linux. Отдельный приватный каталог-родитель, owned by current UID, без записи для группы/остальных. Не использовать `/`, `~`, `~/.hermes`, `~/.claude`, существующий Hermes runtime, YFC или приватный vault. Родитель и предки не могут быть symlink.
- Для каждой установки создаётся `h777-ecc-<uuid>` с правами 0700, уникальной меткой `.h777-ecc-owned.json` и `flock`. Записывается UID, device/inode, parent, SHA ECC, pin Docker, перечень и SHA256 всех файлов. Каталог с неверным маркером, именем или inode не принимается.
- Оригинальные команды `install.sh`, `doctor.js` и `uninstall.js` выполняются **только внутри** pinned `node:22.16.0-bookworm-slim@sha256:048ed02c5fd52e86fda6fbd2f6a76cf0d4492fd6c6fee9e2c463ed5108da0e34` с `--network none --read-only --cap-drop ALL --security-opt no-new-privileges:true`, непривилегированным UID, ограничениями CPU/memory/PID и лишь двумя монтированиями: source ECC read-only + новый HOME read-write.
- Оригинальный checkout должен быть exact `ECC_SHA`, clean Git worktree, MIT; зависимости подготовлены по lockfile командой `npm ci --omit=dev --ignore-scripts --no-audit --no-fund` *вне* networkless контейнера. Никаких слепых обновлений SHA, выполнения новых remote skills или платных API.
- План оригинального установщика ограничен `/test-home/.hermes`. Инвентарь должен совпадать с планом + `.hermes/ecc-install-state.json` и `.claude/ecc/state.db`. Повторная установка и `doctor` обязательны.
- `retire` проверяет уникальный owner marker, состояние root, хеши файлов, symlink/hardlink/special-file, неизвестные каталоги и защиту от повторного выполнения. Если файл изменён или появился чужой файл, **нет ни штатного uninstall, ни cleanup** до исправления состояния.
- Затем `retire` выполняет **оригинальный** `uninstall.js --target hermes`. Все управляемые файлы обязаны исчезнуть. Проверяется SQLite integrity/schema и отсутствие непроизводных записей (в таблицах кроме `schema_migrations` должно быть ноль строк). Если SQLite содержит чужие данные, посторонние таблицы, неожиданные файлы или ссылки - **отказ в удалении** с сохранением HOME.
- При успешном подтверждении остаточный `state.db` уходит *вместе с единственным собственным изолированным HOME* посредством symlink-safe `shutil.rmtree`; каталог-родитель никогда не удаляется. После прерывания предусмотрена повторная попытка `retire` в фазе `RETIRING` при повторной проверке инвентаря; без доказательств - fail closed.

**Ограничение:** CLI не предназначен для работающего совместно с ним резидентного агента и не доказывает безопасную production-активацию. Устойчивость к произвольному конкурентному процессу с тем же UID/FS отдельно не гарантируется. Этот контур не применяется к существующему общему HOME.

## Команды для явно разрешённой тестовой Linux-среды

Подготовить проверенный источник ECC на закреплённом SHA и зависимости; заранее скачать pinned Docker image. Создать **приватный отдельный** каталог для изолятов:

~~~bash
umask 077
mkdir -m 700 /tmp/h777-owner-isolates-TEST-ONLY
python3 -m scripts.h777_ecc_isolated_lifecycle provision \
  --ecc-root /path/to/reviewed-ECC-checkout \
  --base /tmp/h777-owner-isolates-TEST-ONLY
~~~

Результат `provision` возвращает JSON с точным `home` - сохранить его, не подставлять путь к обычному Hermes HOME:

~~~bash
python3 -m scripts.h777_ecc_isolated_lifecycle inspect \
  --home /tmp/h777-owner-isolates-TEST-ONLY/h777-ecc-<uuid>

python3 -m scripts.h777_ecc_isolated_lifecycle retire \
  --ecc-root /path/to/reviewed-ECC-checkout \
  --home /tmp/h777-owner-isolates-TEST-ONLY/h777-ecc-<uuid>
~~~

Если `inspect` сообщает `BLOCKED` или `retire` отказывает в очистке, не удалять каталог вручную без отдельной проверки. Команды не являются свидетельством запуска на VPS/Windows и не предназначены для миграции существующей установки.

## Приёмка

- Unit и отрицательные проверки: `python3 -m unittest discover -s tests -p 'test_h777_ecc_isolated_lifecycle.py' -v`.
- Реальные оригинальные install/reinstall/doctor/uninstall и управляемый rollback: [H777 CI](../../.github/workflows/h777-ecc-managed-isolation.yml) на одноразовом GitHub-hosted runner, Docker без сети и с точными SHA. Обязательно проверяется отказ удалить HOME с синтетическим чужим файлом и сохранность контрольного файла вне HOME. Артефакт `h777-owned-original-ecc-lifecycle` не содержит секретов или абсолютных путей.
- Независимая проверка известного upstream FAIL остаётся в [original regression CI](../../.github/workflows/h777-ecc-upstream-native-rollback.yml). Зелёный regression job доказывает воспроизведение бага, **а не** исправление.
- GO для **source-only managed lifecycle**: `ISOLATED_PROVISION=PASS`, `MANAGED_ROLLBACK=PASS`, `OWNER_DATA_PRESERVED=PASS`, `ORIGINAL_ENTRYPOINTS=PASS`.
- Отдельный результат: `UPSTREAM_NATIVE_EXACT_ROLLBACK=FAIL_KNOWN_CACHE` до исправления самого ECC. Production/runtime/Windows интеграция `NOT_RUN` и требует самостоятельного разрешения.
- Merge в `main` только после точных CI и ревью. Merge не устанавливает ECC в production и не активирует резидентный Hermes.

Связанные источники: [Hermes #777](https://github.com/MikeMoore1337/hermes/issues/777), [#632](https://github.com/MikeMoore1337/hermes/issues/632), [обзор ECC](ecc-upstream-as-is.md).
