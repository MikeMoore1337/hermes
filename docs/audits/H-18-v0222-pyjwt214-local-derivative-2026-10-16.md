# H-18 #199 — локальный производный образ с PyJWT 2.14.0 и native-tool guard

**Дата:** 2026-10-16. **Доказано только:** локально собран и проверен **offline candidate**, не production release. **Резидентный Hermes #33 остаётся NO-GO**: это не signed upstream image, не полное исправление четырех CRITICAL или 270 HIGH.

## Исходник и корректность security upgrade

База — уже имеющийся на выделенном Windows Docker Desktop pinned **linux/amd64** образ:
`nousresearch/hermes-agent@sha256:a11574b7fe8e1631d7d88d556677dac693bc058abf558cdeb899155688c1bf05`, upstream `v0.22.2` commit `d923a5eb487a17c0a68801bba9ef0f56c81040a8`. Оригинальный образ **не модифицировался**, другой образ на VPS не устанавливался.

- Публичный [GitHub Advisory CVE-2026-102268 / GHSA-ffc3-869f-jxw9](https://github.com/advisories/GHSA-ffc3-869f-jxw9) указывает PyJWT `<=2.13.0` как затронутый и **2.14.0** как первую исправленную версию. Это **исправление конкретной библиотеки/CVE, не заявление NOT_AFFECTED для всех поверхностей**.
- С официального [PyPI PyJWT 2.14.0](https://pypi.org/project/PyJWT/2.14.0/) получен **единственный** `pyjwt-2.14.0-py3-none-any.whl` (**32 896 байт**). На Windows `pip download --no-deps --only-binary=:all: --index-url https://pypi.org/simple` скачал public wheel. Затем отдельным запросом к `https://pypi.org/pypi/PyJWT/2.14.0/json` подтверждено полное совпадение SHA256:
  `ad0cef71c756a56e74863c2919cf0985f72decbcfcb550ee2f422e7c62b5eedc`. Пакет `pyjwt` был опубликован 2026-09-11. На странице PyPI опубликована provenance/Trusted Publishing информация; **отдельная криптографическая проверка PyPI attestation не проводилась**.
- Для ранее реально проверенного [native-tool policy patch](../audits/H-01-v0222-pinned-runtime-native-policy-2026-10-16.md) использовался уже отслеживаемый `patches/upstream/hermes-v0.22.1-native-tool-policy.patch`, SHA256 `e7157fd4831b32670d418a5eec675a8cab8318a49e5c1df94e33da7e9d3a2016`. Это тестовый patch overlay **не принятый upstream**, не полный hardening OS/MCP.
- Python runtime остаётся **3.14.7** вместо уже доступного [3.14.8](https://www.python.org/downloads/release/python-3148/), который исправляет отдельные security issues. Бинарные/native OS dependencies, libxml2/SSH, source-to-build provenance и SBOM этого кандидата **не аттестованы**.

## Реально выполненная сборка

Локальный контекст состоит **только из трёх файлов**: Dockerfile из `docker/v0222-pyjwt-fixed-candidate/Dockerfile`, pinned уже проверенный native guard patch и проверенный публичный wheel. Wheel хранится **вне Git**, он не включён в PR/CI. Помощник `scripts/prepare_v0222_pyjwt_candidate.py` строго проверяет обе SHA256, точную `FROM` базу и выходной каталог, не обращается к сети и **не запускает Docker по умолчанию или по флагу**.

Реально выполнена сборка:

```bash
# Сначала подготовить context вне репозитория через verify-only helper:
python3 -m scripts.prepare_v0222_pyjwt_candidate --execute \
  --wheel /absolute/private/local/pyjwt-2.14.0-py3-none-any.whl \
  --output-dir /absolute/private/local/new-build-context
# Возвращает OFFLINE_CONTEXT_PREPARED_NO_GO, exit 2.

# Явно запускается оператором на выделенном хосте, НЕ в CI/VPS:
docker build --pull=false --network none --platform linux/amd64 --no-cache \
  --progress plain -t hermes-v0222-pyjwt214-toolguard-candidate:20261016 \
  /absolute/private/local/new-build-context
```

**Наблюдение:** `docker build` SUCCESS. Внутри `RUN` network отключён, wheel сначала сверен `sha256sum -c`; `ensurepip` из встроенного Python установил `pip 26.2.1` и локально `pip install --no-index --no-deps --force-reinstall` заменил `PyJWT 2.13.0 → 2.14.0` во встроенной `.venv`. Применение tool-policy patch через `git apply --unidiff-zero --check` + `git apply` succeeded. `pyproject.toml` также изменён на точное `PyJWT[crypto]==2.14.0`. Это **слой нового производного образа**, не in-place patch оригинального контейнера. На шаге сборки pip сообщил **предупреждение о некорректных optional-dependency metadata hermes-agent/kittentts** — не считать полноценную совместимость wheel resolution проверенной.

**Уточнение сетевой изоляции:** `--network none` действует на Dockerfile `RUN` и `--pull=false` не выполняет принудительный pull образа. Однако BuildKit показал отдельный шаг `load metadata for docker.io/...`. Поэтому не утверждаем, что весь build process полностью network-air-gapped; это требует отдельного builder-контроля. В рантайм-тестах установлен `--network none`.

Локальная метка `hermes-v0222-pyjwt214-toolguard-candidate:20261016`, по `docker image inspect`/synthetic compare image ID:
`sha256:5f1a86dcb7b4f202e45358dec3b473dadec482bd6e2031cce30cb60cb9e47482`.
**Этот ID - локальная Docker identity, не publisher signature.** Образ не пушился ни в один registry.

## Фактически пройденные испытания

1. В `docker run --pull never --network none --read-only --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges` новый образ с entrypoint **не Hermes Agent**, а встроенный Python `-m pip show PyJWT` подтвердил `Version: 2.14.0` и install location `/opt/hermes/.venv/lib/python3.14/site-packages`. Провайдер/LLM/секрет/сеть не использовались.
2. Внешний проверенный `scripts.verify_v0222_immutable.compare_patched()` повторно запущен на исходном exact image и **новом локальном derivative image** в bounded synthetic probe. Получен результат `PATCHED_NATIVE_TOOL_POLICY_BOUNDED_PASS`: `original_gap_reproduced=true`, `patched_checked_paths_blocked=true`, `allowed_synthetic_paths_work=true`, `model_executed=false`, `real_tool_executed=false`, `resident_agent_allowed=false`. Все реальные dangerous tool executors заменены на фиктивные заглушки *до диспетчеризации*.
3. Дополнительно проверен настоящий PyJWT 2.14.0 в изолированном Docker-контейнере: синтетический временный ключ RSA-2048 (в памяти) подписал RS256 JWT, проверка RS256 успешно приняла валидную подпись, а модифицированный payload со старой подписью вызвал `jwt.InvalidSignatureError`. Наблюдаемый JSON: `rs256_signed_token_accepted=true`, `tampered_signature_denied=true`, `version=2.14.0`, exit 0. Тестовый код — `scripts/h18_pyjwt_candidate_crypto_smoke.py`, он исполняется **только отдельно** из разрешённого локального контейнера; без реальных ключей, модели, сети и токенов.
4. Новый helper проверен реальным запуском: staged 3/3 файлов в отдельный context, обе SHA256 PASS, возвращает exit 2 и **никакого GO**. Дополнительные 12/12 синтетических tests проверяют отказ при неверном wheel/patch, неподходящем source image, write-to-repo, существующем output, потере input, сохранении секретных путей и ложном PASS.
5. **Не проводились:** реальные agent/tool/model turns с исправленной PyJWT, CVE PoC/exploitation, полный Python 3.14.8 upgrade, Trivy/Syft repeat scan derived image, vendor-backed OCI attestation, provider billing/Free hard stop, load/burn-in и внешняя публикация.

## Release decision

`LOCAL_PYJWT_DEPENDENCY_FIXED / RUNTIME_NO_GO`.

**Следующие P0:** (a) обновить Python 3.14.7 → ≥3.14.8 с отдельной цепочкой поставки и тестами, (b) реальные Syft/Trivy и vendor CVE для производного образа, (c) независимая signed builder/source attestation для exact digest, (d) OS/native/MCP deny-by-default вне замоканных путей, (e) provider hard limit + нагрузка/rollback, (f) отдельный owner GO на конкретный образ и production. `#199` и `#33` остаются OPEN; никаких systemd, Caddy, OAuth, YFC/Second Brain или VPS изменений.
