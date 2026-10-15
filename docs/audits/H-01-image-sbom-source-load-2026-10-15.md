# H-01 #33 - инвентаризация образа, соответствие Git и ограниченная нагрузка

Наблюдение на VPS 15.10.2026 около 03:21–03:40 UTC. Это **доказательства текущего установленного immutable image**, а не разрешение на круглосуточного агента. Не менять YFC news, не загружать иной Docker-образ и не использовать платные модели для повторения проверки.

## Официальный образ и SBOM

- Установлен `nousresearch/hermes-agent@sha256:32d095e84190ae7266afbb361579e6921f2c633e899f5eacfb88111b9c851a22`; локальный OCI image ID и опубликованная AMD64 запись `nousresearch/hermes-agent:v0.21.6` совпадают. Два platform manifest entries, media type `application/vnd.docker.distribution.manifest.list.v2+json`.
- Read-only `docker buildx imagetools inspect nousresearch/hermes-agent:v0.21.6 --format '{{json .Manifest}}'`: **0 записей** с аннотацией `vnd.docker.reference.type=attestation-manifest`. `{{json .Provenance}}` и `{{json .SBOM}}` не вернули соответствующий объект. **Не обнаружены опубликованные в данном OCI index attestation**, а не доказано, что где-то ещё не существует SBOM/подписи.
- Локальное чтение `dpkg-query -W` внутри pinned image с `--network none --read-only --cap-drop ALL --security-opt no-new-privileges --cpus .25 --memory 256m --pids-limit 30`: **274 системных пакета**, SHA-256 текстовой инвентаризации `f017ae2f917d706553138c6741b6c35b2d68fade9058511c9c9bed1f7d8a3e5f`. Ни одной внешней программы не устанавливали. Список dpkg - **не полная SBOM и не аттестация поставщика**: он не доказывает наличие Python-пакетов, npm зависимостей, связей сборки, внешних библиотек и их происхождения.
- [Документация Docker по provenance/SBOM](https://docs.docker.com/build/metadata/attestations/) и [проверка в реестре](https://docs.docker.com/reference/cli/docker/buildx/imagetools/inspect/) разделяют опубликованный OCI digest и доказательства состава сборки.

## Содержимое исходников внутри официального образа

Отдельно запускали `/usr/bin/git hash-object` на файлах внутри **не сетевого, read-only, без capabilities** контейнера, сопоставили exact Git blob SHA, полученные из upstream GitHub API по двум ревизиям.

| Путь | Blob внутри image | Embedded Git commit `a28a5d03` | Release tag commit `818c13be` | Вывод |
| --- | --- | --- | --- | --- |
| `run_agent.py` | `371cfff6b2a5469f0120420a26fe2323b90ca6e4` | совпадает | `4e615e54f8ca5b8b2f8e12b95875486aa8bbd4b5` | код образа соответствует старой ревизии |
| `tools/approval.py` | `6d4402db744d12b88d596372fc8a7e8efdc29998` | совпадает | совпадает | общая часть не менялась |
| `gateway/run_turn.py` | `671d5e1093c2ce7ec7e31707227c964019eb3fd4` | совпадает | `8c5728884d020b408e2a0d39d0adabd5820ea71a` | код образа соответствует старой ревизии |
| `pyproject.toml` | `648a597cad21b14c94782dca09d9d0db3bf54c2a` | совпадает | совпадает | общая часть не менялась |

Дополнительно файл `tools/approval_yolo.py` в контейнере отсутствует, но появился в Git release tag. Четыре совпадения **не удостоверяют всё дерево исходников**, однако дают прямое, независимое от меток Docker доказательство, что опубликованный `v0.21.6` на AMD64 включает более ранний код, чем одноимённый Git tag. Это основание **не** предполагать, будто Git release tag автоматически представляет точную сборку.

## Проверка ограниченного Agent-turn

- Код на VPS `scripts/agent_turn_probe.py` совпал по Git blob с `c6384abea7636dc5aad6c0f9243975a945491d5b`.
- Перед тестом: `load1=0.52`, `MemAvailable≈2074 MiB`, swap 0, news/ops timers active; `ensure_cloudflare_egress.py --check` вернул `verified, changed=null`. Прокси и AI Agent были inactive; unit прокси disabled.
- Явный ограниченный вызов `--execute` завершился **PASS**: exit_code 0, продолжительность **113.4 с**, точный `OK`, ни одного признака ошибок auth/quota/network/HTTP400. Запуск был **разовым**, не 24/7.
- Не открывали shell/browser/Git/MCP для агента; не выдавали права публикации или записи YFC.

## Изолированная нагрузка и пределы

Отдельно выполнялся **45-секундный** CPU stress в pinned Docker-образе, без сети, данных/томов/секретов, capabilities, с ограничением `--cpus .25 --memory 128m --memory-swap 128m --pids-limit 20`. 48 последовательных чтений /proc показали:
- минимальная доступная память **2059 MiB**;
- использование swap максимум **0 MiB**;
- максимальная 1-минутная средняя нагрузка **1.61**;
- news timer, Ops collector, sender и firewall guard **оставались active**; контейнер закончил с `BOUNDED_OFFLINE_STRESS_EXIT_OK`.

**Важно:** нагрузка `1.61` превышает защитный порог Agent `MAX_LOAD_DURING=1.30`; если аналогичное условие возникнет во время модельного вызова, штатный контракт должен **отменять его**, а не продолжать работу. Мы не запускали модель одновременно с CPU-стрессом, поэтому это **не проверка** отмены живого модельного запроса или работы в пиковый час discovery. Автономный resident Agent пока **NO-GO**.

## Что нужно для полноценного допуска

1. Либо получить от издателя подтверждённую цепочку **release source -> build -> digest**, проверяемую SBOM и attestation/подпись, либо построить собственный pinned candidate из закреплённого Git commit в изолированном CI с проверяемым SBOM, не меняя рабочий образ без rollback. Ни один путь сейчас не завершён.
2. Изолировать инструменты агента по фактической полезной роли: read-only анализ без привилегий OS и без автоматического подтверждения опасных действий. Проверить сохранение `/yolo` после restart/branch и запрещённые инструменты в реальном образе.
3. Подтвердить через независимую проверку Workers Free и отсутствие риска затрат при будущих изменениях тарифа. Не расширять `-z` вне todo-only bounded probes.
4. Отдельный контролируемый **burn-in на фоне пикового news load** с отказом при high load, измерением времени, RAM/swap, ошибками Cloudflare и проверяемым откатом. 113.4 секунды и 45 секунд CPU stress не доказывают сутками стабильный агент.

Связанные [предыдущая матрица прав](H-01-upstream-security-diff-2026-10-14.md), [Issue #33](https://github.com/MikeMoore1337/hermes/issues/33). Текущие новости и Ops Watch оставлены включёнными; никакой новый resident service не создавался.
