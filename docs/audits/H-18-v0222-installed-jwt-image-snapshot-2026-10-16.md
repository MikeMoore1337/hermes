# H-18 / #199: проверка установленного Python JWT-кода в pinned image

**16 октября 2026.** Контур: Windows Docker Desktop, уже доступный локальный immutable image **linux/amd64** `nousresearch/hermes-agent@sha256:a11574b7fe8e1631d7d88d556677dac693bc058abf558cdeb899155688c1bf05`. Это отдельный офлайн-аудит к [#199](https://github.com/MikeMoore1337/hermes/issues/199) и [#33](https://github.com/MikeMoore1337/hermes/issues/33).

## Воспроизводимость и источник

1. `docker image inspect` показал exact `linux/amd64` `RepoDigests` и локальный image ID равный закреплённому `sha256:a11574b7...`. **Docker registry signature и source-to-build provenance этим не подтверждаются**.
2. Создан **остановленный** container filesystem reference с `docker create --network none --read-only --entrypoint /bin/true`; контейнер **не запускался**, ни один process внутри не исполнялся, agent не активировался. `docker cp` скопировал только `agent`, `hermes_cli`, `gateway`, `cron`, `plugins`, `tools`, `acp_adapter`, `pm` и `pyproject.toml` в локальный закрытый каталог **вне Git**. Не копировались `.env`, vault, токены, Docker socket или чужие проекты; никаких сетевых обращений к registry/LLM не выполнялось.
3. Скрипт `scripts/audit_v0222_installed_jwt_callsites.py` - только Python stdlib, `ast.parse` для установленного Python source, **не импортирует, не компилирует в исполняемый код и не запускает** Hermes/image. Контролирует размер файлов, симлинки, фиксированные root-пути и лимит суммарного чтения. Без `--execute --source-dir` сообщает `NOT_EXECUTED`. Любая ошибочная фикстура или несовпавшая source SHA - `INCONCLUSIVE`, не PASS.
4. **Пять установленных security-critical файлов** побайтно совпали с Git blob SHA1 exact release commit `d923a5eb487a17c0a68801bba9ef0f56c81040a8`, как в [предшествующем аудите](H-18-v0222-four-critical-cve-applicability-2026-10-16.md). Это сравнение Git blob объектов, а не криптографический image attestation.

## Фактическое измерение

`2962` Python файлов успешно разобраны (включая пустые `__init__.py`). В указанных восьми first-party roots найдены **3 прямых PyJWT decode calls** (путь/строка из установленного image, без печати source):

| Путь | Строка | Синтаксический классификатор | Ограничение |
| --- | ---: | --- | --- |
| `plugins/cron_providers/chronos/verify.py` | 63 | `DYNAMIC_KWARGS` | Проверить структуру `decode_kwargs` и источники ключа; [#201](https://github.com/MikeMoore1337/hermes/pull/201) локально подтвердил статический RS/ES allowlist для этого вызова |
| `plugins/dashboard_auth/_shared.py` | 248 | `DYNAMIC_OR_MISSING_ALGORITHMS` | `algorithms` - аргумент функции; три известных вызывающих пути используют RS/ES по #201, но полный динамический call graph не доказан |
| `plugins/dashboard_auth/_shared.py` | 263 | `UNVERIFIED_DECODE` | Выполняется в обработчике *проваленной* `jwt.InvalidTokenError` аутентификации; недоверенные `iss/aud` из токена попадают в диагностический `ProviderError`. Не доказан authentication bypass, но нужно отдельно оценить redaction/утечки и небезопасные символы в диагностике |

**Скрипт анализирует AST-формы** `import jwt`, `import jwt as ...`, `from jwt import decode`, `decode_complete`; фиксирует литералы опасного `HS*+RS*/ES*/PS*`, `verify_signature=False`, `**kwargs`/динамические алгоритмы. Без подстановки секретов или моделирования exploit. Дополнительно 14/14 синтетических unittest PASS (в том числе mixed-algorithms, aliases, source drift, неверные данные, отсутствие ложного разрешения). 

**Вывод:** по извлечённому Python source не обнаружены новые *прямые* PyJWT calls в восьми каталогах, но это **НЕ исчерпывающий доказанный список всех возможных runtime JWT-путей**: прочие каталоги и site-packages, динамические импорты/атрибуты, compiled extensions, runtime plugin injection, альтернативные JWT библиотеки и фактические credentials/config не исследованы. Значение `3` не относится к другим upstream коммитам/образам. `tag_blob_parity_checked=true` относится **только к пяти файлам**, не ко всем 2962.

## Ограничения и решения

- Для `CVE-2026-102268` исходная версия PyJWT **2.13.0** по Trivy, fixed **2.14.0**; условия mixed symmetric/asymmetric + raw PEM в известных проверяемых путях не подтверждены. **Глобальная применимость остаётся INCONCLUSIVE**, не `NOT_AFFECTED`.
- `CVE-2026-6653`, `CVE-2026-60002`, `CVE-2026-43185` оцениваются отдельной матрицей #199; данный скрипт на них не распространяется.
- Исходное содержимое image, любые приватные абсолютные пути и raw SBOM **не коммитить**. JSON-протокол содержит только пути **внутри выбранных публичных first-party roots** и структурные признаки, не содержимое токенов/строк.
- Любой потенциальный PyJWT upgrade, удаление диагностического блока либо patch потребует **нового pinned derivative с отдельным source-to-image provenance**, полного регресса и QA; «лечить» текущий immutable runtime in-place запрещено.
- Статус **`P0_REVIEW_REQUIRED`**, код возврата 2; `resident_agent_allowed=false`. Никаких изменений production, Caddy, системных служб, OAuth, платных провайдеров, YFC и Second Brain.

### Запуск для отдельного уже подготовленного offline snapshot

```bash
python3 -m unittest discover -s tests -p 'test_h18_installed_jwt_callsites.py' -v
python3 -m scripts.audit_v0222_installed_jwt_callsites
python3 -m scripts.audit_v0222_installed_jwt_callsites --execute --source-dir /local/verified/image_source
```

Первый CLI вызов сообщает `NOT_EXECUTED`; второй возвращает JSON со статусом P0 и exit 2 при успешном чтении. CLI **никогда не создаёт контейнер и не вызывает Docker/network**, не может запустить сканирование скрыто. Подготовка filesystem snapshot - отдельное одобренное действие оператора.
