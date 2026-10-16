# H-18 / #199 — статическая сверка JWT исходников из реального immutable Docker image

**Дата:** 16.10.2026. **Контур:** отдельный Windows Docker Desktop, **не VPS**. **Вердикт:** `AUTH_SUBSET_PARITY_OBSERVED`, `resident_agent_allowed=false`, P0 **NO-GO**. Это частичный byte-level comparison, **не подписанная upstream provenance**.

## Конкретный объект и метод

- Официальный локально имеющийся Linux/AMD64 image:
  `nousresearch/hermes-agent@sha256:a11574b7fe8e1631d7d88d556677dac693bc058abf558cdeb899155688c1bf05`.
  `docker image inspect` вернул `Id=sha256:a11574b7...`, `Os=linux`, `Architecture=amd64`, `WorkingDir=/opt/hermes`.
- Проверенный внешний upstream source: `NousResearch/hermes-agent` tag `v0.22.2`, peeled commit `d923a5eb487a17c0a68801bba9ef0f56c81040a8`. Предыдущий PR #201 независимо установил Git blob IDs пяти файлов.
- Источники извлечены **из файла контейнера**, без вызовов Python приложения: `docker create` exact image с `--pull never --network none --read-only --entrypoint /bin/true --user 65534 --cap-drop ALL --security-opt no-new-privileges` и ограничениями PIDs/RAM; `docker cp` пяти allowlisted путей из `/opt/hermes/`; затем `docker rm` в `finally`.
- **Не выполнялись** `docker start`, `docker run`, `docker exec`, shell из контейнера, network/Cloudflare/LLM, синтетическая «эксплуатация» CVE, VPS/systemd deployment и доступ к приватным данным. Временный созданный контейнер **удалён**.
- Хеши: Git blob SHA1 по Git-формуле `SHA1("blob " + file_size + NUL + content)` плюс самостоятельный SHA256 каждых фактически извлечённых bytes. Вложенные Python-файлы в рабочий репозиторий Hermes **не копировались и не коммитились**. В новом reproducible варианте `scripts/verify_v0222_image_jwt_subset.py` временный каталог очищается автоматически.

## Измеренные пять файлов

| Пути внутри `/opt/hermes/` | Git blob SHA1; совпадение с tag v0.22.2 | SHA256 извлечённых bytes |
| --- | --- | --- |
| `plugins/cron_providers/chronos/verify.py` | `2503f4a1a8cd21ad28bc1717c2f92494186103d6` = **MATCH** | `f710652019f36e8f901707a8e7957f282c10527dc257f7af54c7f6ae9d96e8ee` |
| `plugins/dashboard_auth/_shared.py` | `e12fb5896c51096589b25172468d413ce22eef5d` = **MATCH** | `c2cf34a356b2bdcf0d30debafa21378b8658ea21f53338ea063eaa69360685b4` |
| `plugins/dashboard_auth/nous/__init__.py` | `66723b5a75e481d6f5936a354245c1beef639915` = **MATCH** | `f4265267fc4a5358da003586f925b959544a6b28723f65d5856982cc10e5df74` |
| `plugins/dashboard_auth/self_hosted/__init__.py` | `f65a24ec34882687bc6558410f882c2d4479fb3e` = **MATCH** | `445da06266065691d4936688812cd6787736cb4a4775dce196e15e62973ccb5b` |
| `pyproject.toml` | `5145f275d14a0ab119802821c715a33123b15551` = **MATCH** | `ff41b097147124ff2eb51a437d5f44eddea35104900c1c79c7edfb8b7352d901` |

После первого ручного извлечения было выполнено независимое **повторение** через новый скрипт:

```bash
python3 -m scripts.verify_v0222_image_jwt_subset
# NOT_EXECUTED; exit 0, Docker не вызывается

python3 -m scripts.verify_v0222_image_jwt_subset --execute
# AUTH_SUBSET_PARITY_OBSERVED; source_files_checked=5
# source_files_matching_upstream=5; temporary_container_removed=true
# resident_agent_allowed=false; exit 2 (P0 fail closed)
```

Скрипт не принимает произвольную модель, образ, путь контейнера или команду; пять путей и digest закреплены в коде. Он проверяет `docker image inspect` и разрешает **только** `docker create/cp/rm` с фиксированными параметрами, возвращает фиксированное `INCONCLUSIVE` при ошибках, не публикует raw bytes. Docker daemon на выделенном хосте всё равно представляет собой привилегированный компонент; эта проверка НЕ является независимой attestation сборочного конвейера.

## Что теперь установлено по CVE-2026-102268

Зависимость `PyJWT[crypto]==2.13.0` в точно совпавшем `pyproject.toml`; ранее фактический SBOM указал установленный `PyJWT 2.13.0`. Три пути проверки JWT из **байтов тех же файлов в реальном образе** прошли предыдущий `scripts.audit_v0222_critical_jwt --execute --source-dir`: `mixed_hmac_asymmetric=false` для Chronos/Nous/Self-hosted, статус `P0_REVIEW_REQUIRED`, exit 2.

Это повышает доверие к **локальному составу этих пяти файлов**: они идентичны закреплённому upstream source. Однако динамическая конфигурация, плагины вне выбранных файлов, криптографическая цепочка origin->build, полный состав vendor wheels/native libs, право всех tools и фактические уязвимости *не установлены* и не считаются исправленными. PyJWT `2.13.0` уязвим, а `2.14.0` содержит upstream correction ([GHSA](https://github.com/advisories/GHSA-ffc3-869f-jxw9)).

## Жёсткие оставшиеся gates

- [ ] **Новый immutable v0.22.2 derivative или официальный релиз** с исправлением PyJWT и CI; пересоздать Syft/Trivy SBOM/CVE отчёт и проверить без in-place changes.
- [ ] Независимая подписанная source->build->image attestation и supplier authorization.
- [ ] Исправить/подтвердить достижимость остальных CRITICAL/HIGH CVE, включая XML/SSH, и проверить OS/native tools/egress deny-by-default в реальном ограниченном runtime.
- [ ] Provider billing hard stop, peak burn-in, rollback и отдельное решение владельца.

**Промышленный допуск по #33 не выдан. Пилот ограничен чтением пяти открытых исходных файлов, не изменяет ни Hermes Agent, ни VPS, ни YFC, ни Second Brain.**
