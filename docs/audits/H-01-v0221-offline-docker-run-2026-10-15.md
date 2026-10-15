# H-01 #33 - фактическая изолированная инспекция Hermes v0.22.1

Дата проверки: **15.10.2026**. Область: отдельный компьютер `DESKTOP-U6JEQP9`, **не** production VPS. Исходники owner-repo: `main@f2ef4e739d4c793f76ec90b283ea3eddb0b73ecd`. Задача: [#33](https://github.com/MikeMoore1337/hermes/issues/33).

## Доказанный bounded run

- Docker Desktop server/client `29.8.0`, Linux engine `x86_64`, локально уже загружен immutable `nousresearch/hermes-agent@sha256:cd9cb455576d27c9b6311de1104494ad7e221b6e68dc77e9ac2a8af661a4dc21` из официальной [v0.22.1 release receipt](H-01-new-release-v0221-candidate-2026-10-15.md). Новый `docker pull` не выполнялся.
- Выполнено `py -3.14 -m scripts.verify_v0221_local_image --execute` из чистого клона owner-repo с точно указанным коммитом. Скрипт проверяет локальные Docker `RepoDigests` и `amd64`, затем создаёт **единственный** непривилегированный контейнер с `--pull=never --platform linux/amd64 --network none --read-only --cap-drop ALL --security-opt no-new-privileges --user 65534:65534 --cpus 0.25 --memory 256m --memory-swap 256m --pids-limit 25`. Не монтируются каталоги, secrets, Docker socket; нет model calls, outbound публикаций, сетевых запросов и доступов к YFC или Second Brain.
- Фактический результат: `EMBEDDED_STAMP_MATCH_IMAGE_UNATTESTED`; `embedded_stamp_matches_release_commit=true` (source `297552a9d646119871391d202509822cd86330df`), OS/dpkg **274**, Python-venv **146** записей; повторяющееся каноническое имя `python-venv:hermes-agent`; SHA256 отсортированного нормализованного локального списка **`f42cbae3102e5d56f7ca64f6239af1425e29ff58366f2674ca9759f272acd48f`**.
- `duplicate_canonical_package_names` означает повторяющиеся *метаданные имени*, а не две физические установки. Для другого образа v0.21.6 ранее показана одна физическая запись по inode; новый v0.22.1 отдельно по inode не проверялся. Не переносить старое заключение автоматически.
- Возврат кода **2** для успешно прочитанной метаинформации ожидаем по контракту: инструмент умышленно оставляет `resident_agent_allowed=false`, `source_to_image_parity_verified=false`, `complete_sbom_verified=false`, `supplier_signature_verified=false`, `model_executed=false`.

## Дополнительные офлайн-проверки регрессий

- Windows Python 3.14: **8/8** специальных `tests.test_v0221_local_image` - PASS.
- Полный набор тестов в нативном Windows Python запускать как кроссплатформенный нельзя: обнаружены `fcntl`, `os.geteuid`, `os.O_NOFOLLOW` (78 ошибок импорта/исполнения, не 78 доказанных регрессий). Этот запуск не считать успешным CI.
- Отдельный Linux-контейнер из **уже загруженного** `mcr.microsoft.com/playwright:v1.62.1-noble`, Python 3.12.3, `--pull never --network none --read-only --cap-drop ALL --security-opt no-new-privileges --user 65534:65534 --cpus 1 --memory 768m --pids-limit 96`, source tree только bind readonly, `/tmp` tmpfs: **563 теста, OK (4.193 s)**. Команда: `python3 -B -m unittest discover -s tests -p 'test_*.py' -q`. Ни одна рабочая systemd-служба при этом не изменялась.

## Границы вывода и оставшиеся блокировки

Этот успешный offline inspection подтверждает только наличие локально зафиксированного образа, прочитанный им embedded source stamp и ограниченный перечень локальных пакетов. **Не получены** независимая полная source-to-image parity, подписанная supplier attestation, полноценная проверенная SBOM/лицензии, функциональный и нагрузочный model-run **именно этого образа**, техническая гарантия отсутствия платных вызовов и burn-in совместно с production news.

**H-01 resident agent: NO-GO.** Не включать Cloudflare proxy или постоянный AI Agent; не выполнять автоматический cutover, изменения production VPS, публикацию или работу с персональными данными без соответствующих отдельных условий допуска. Связанные основания: [release candidate](H-01-new-release-v0221-candidate-2026-10-15.md), [CI исходников и Docker release](H-01-upstream-release-ci-2026-10-15.md), [протокол](../operations/H-01-V0221-OFFLINE-IMAGE.md).
