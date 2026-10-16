# H-18: изолированная сверка Syft/Trivy для immutable v0.22.2


> **Обновление 16.10.2026:** после первоначального mock-only PR #194 был
> выполнен настоящий локальный scan pinned v0.22.2 на отдельном Windows Docker
> host. Syft и Trivy сформировали независимые отчёты, обнаружены HIGH/CRITICAL
> findings, но signed provenance и production GO остаются закрыты.
> [Точный отчёт с хешами и ограничениями](../audits/H-18-v0222-syft-trivy-local-evidence-2026-10-16.md).
> Слова «не запускался» ниже описывают **состояние первоначального PR #194**,
> а не актуальный результат нового аудита.


Связано: [#185](https://github.com/MikeMoore1337/hermes/issues/185), [P0 #33](https://github.com/MikeMoore1337/hermes/issues/33).

## Что реально реализовано

`scripts/review_syft_trivy_evidence.py` **только читает** три локальных JSON-артефакта, созданных **вне** Hermes другим, явно утверждённым процессом. Он ничего не скачивает, не запускает scanner/Docker, не монтирует хост, не обращается к API и не создаёт файлы. Он использует только стандартную библиотеку Python.

Проверяемая цель жестко закреплена на **AMD64 platform digest**:
`nousresearch/hermes-agent@sha256:a11574b7fe8e1631d7d88d556677dac693bc058abf558cdeb899155688c1bf05`.
Это наблюдавшийся digest официального v0.22.2, но не доказательство signed source-to-image provenance. Для другого digest нужен reviewed code change. Старые v0.22.1 SBOM/доказательства нельзя переиспользовать.

Проверки: хеши сканерных файлов, явно объявленные версии Syft/Trivy, идентичность образа и платформы, формат native Syft JSON и native Trivy JSON, self-reported manifest digest, валидность и диапазон self-reported даты БД, число найденных пакетов, отдельный подсчёт HIGH/CRITICAL, отсутствие дублирующихся JSON-ключей, ограничения размеров/ссылок.

**Внимание:** `descriptor.version` Syft и версии в manifest не удостоверяют исполняемые файлы. `trivy_db_sha256` и времена БД в manifest тоже не являются подтверждёнными внешними аттестациями. Отчёт намеренно никогда не возвращает production GO или `exit=0` для `--execute`.

## Как использовать

Без параметра `--execute` возвращает `NOT_EXECUTED` и exit 0.

```bash
python3 -m scripts.review_syft_trivy_evidence
python3 -m scripts.review_syft_trivy_evidence \
  --execute \
  --manifest /path/to/local/manifest.json \
  --syft-json /path/to/local/syft.json \
  --trivy-json /path/to/local/trivy.json
```

При `--execute`: `UNATTESTED_REVIEW_REQUIRED` (нет обнаруженных HIGH/CRITICAL), `HIGH_CVE_REVIEW` (найдены HIGH/CRITICAL) либо `INCONCLUSIVE` (недостаточные/несовместимые входные данные). **Во всех случаях exit 2 и `resident_agent_allowed=false`.**

Входные `syft.json` и `trivy.json` должны быть native JSON-отчётами инструментов (не CycloneDX-конверсия). Syft `source.target.userInput` должен содержать именно указанный выше immutable ref, `source.target.manifestDigest` - platform manifest digest. Trivy `ArtifactName` должен совпадать с immutable ref и `ArtifactType=container_image`. Если вывод конкретной версии инструмента отличается, проверка останется `INCONCLUSIVE`; нельзя исправлять несовпадения вручную, выдавая файл за подлинный скан.

Стороннее сканирование - отдельный шаг после фиксации версии/хеша исполняемых файлов и разрешённого локального доступа к **точному** образу; нужны локальная БД Trivy с известным происхождением, запрещённая сеть на уровне ОС, жёсткие CPU/RAM/временные лимиты. **Не запускать эти сканеры на production VPS, не устанавливать с `curl | sh`, не подтягивать mutable tag.** Проверка `--offline-scan` сама по себе не доказывает отсутствия сетевого egress.

Manifest должен иметь ровно перечисленные поля:

```json
{
  "schema": "hermes-h18-scan-evidence-v1",
  "image": "nousresearch/hermes-agent@sha256:a11574b7fe8e1631d7d88d556677dac693bc058abf558cdeb899155688c1bf05",
  "platform": "linux/amd64",
  "syft_sha256": "REPLACE_WITH_64_LOWERCASE_HEX_SHA256",
  "trivy_sha256": "REPLACE_WITH_64_LOWERCASE_HEX_SHA256",
  "syft_version": "1.42.0",
  "trivy_version": "0.69.0",
  "trivy_db_sha256": "REPLACE_WITH_64_LOWERCASE_HEX_SHA256",
  "trivy_db_updated_at": "2026-10-15T12:00:00Z",
  "scanner_run_at": "2026-10-16T12:00:00Z"
}
```

**Пример manifest не является реальным свидетельством сканирования.** Его значения версий и времени условны, хеши нужно сформировать из действительно полученных файлов (без загрузки отчётов в GitHub). Проверяемый digest, подтверждённые версии Syft/Trivy, DB manifest, файлы scanner JSON и подписанная provenance должны храниться в отдельном закрытом evidence-хранилище с правами доступа и политикой retention.

## Что ещё не завершено по #185 / #33

- Не установлен и не запускался ни Syft, ни Trivy; нет реальной полной SBOM, подтверждённой базы CVE, лицензий или актуальной vulnerability coverage.
- Нет независимого доказательства соответствия source -> build -> image digest, подписанной attestations издателя, верификации binary provenance и release receipt.
- Нет доказательств native-tool permission enforcement, runtime burn-in и no-paid-fallback. Все GO-гейты остаются закрыты.

Для самопроверки из корня репозитория:

```bash
python3 -m unittest tests.test_h18_syft_trivy_evidence -v
python3 -m unittest discover -s tests -v
```
