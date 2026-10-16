# H-18 / #185 / #33 - независимая локальная SBOM/CVE-инвентаризация v0.22.2

**Дата:** 16.10.2026. **Контур:** отдельный Windows 11 Docker Desktop (не VPS), только уже имеющийся immutable AMD64 image. **Статус:** `HIGH_CVE_REVIEW`, `resident_agent_allowed=false`, **production NO-GO**. Отчёт - описание наблюдений, а не подписанный supplier attestation.

## 1. Точные объекты и средства

- Образ: `nousresearch/hermes-agent@sha256:a11574b7fe8e1631d7d88d556677dac693bc058abf558cdeb899155688c1bf05`, platform `linux/amd64`. Локальное `docker images --digests` подтвердило наличие RepoDigest до сканирования. Не применялся `docker pull`.
- Syft `1.54.1` от `https://github.com/anchore/syft/releases/tag/v1.54.1`. Архив `syft_1.54.1_windows_amd64.zip`: SHA256 `8b56e8285e295e0bbed26eeea9b16ed51c493be97ccdf42dae6326c84fe8e19f`. Распакованный `syft.exe`: SHA256 `b7e78564e72dc550301ff221c9e034d9ece77d16f8e5cc0f7782caa302addbc6`.
- Trivy `0.76.0` от `https://github.com/aquasecurity/trivy/releases/tag/v0.76.0`. Архив `trivy_0.76.0_windows-64bit.zip`: SHA256 `7b4762a5a5326cb4b83dfd2bb5d9aaf15a1ed867c75cad7dd8b38840a28e7be6`. Распакованный `trivy.exe`: SHA256 `51e50a34f8739424bc88282602d10945b25249ffdb51703fe3c9453c20217c42`.
- Архивы получены по точным официальным release asset URL; SHA256 сверены с `digest` GitHub Release API. **Отдельной Sigstore signature verification, бинарной аттестации и независимого source-to-binary proof не было.** Сканеры не установлены системно.
- Trivy DB из `ghcr.io/aquasecurity/trivy-db:2`: версия схемы 2, `UpdatedAt=2026-10-16T01:13:54.947090392Z`, `DownloadedAt=2026-10-16T14:38:05.2287834Z`. Локальный `trivy.db` - 1,628,446,720 байт, SHA256 `bf1f1b29d76cae9ff085d418cb4bfdb3906b6069f837abdef06558b8102dd1db`. OCI DB tag не закреплён immutable digest/signature; этот файл **наблюдение**, не независимая подписанная база.

## 2. Что действительно запускалось

Сначала уже имеющийся Docker daemon проверен на `linux/amd64`, затем в отдельном локальном каталоге `.artifacts`:

```powershell
$img = 'nousresearch/hermes-agent@sha256:a11574b7fe8e1631d7d88d556677dac693bc058abf558cdeb899155688c1bf05'
& .\syft\syft.exe scan "docker:$img" -o 'json=observed-v0222.syft.json'
& .\syft\syft.exe convert 'observed-v0222.syft.json' -o 'cyclonedx-json=observed-v0222.cdx.json' -o 'spdx-json=observed-v0222.spdx.json'
# DB скачана ОТДЕЛЬНО; в следующем вызове запрещено обновление:
& .\trivy\trivy.exe image --image-src docker --skip-db-update --skip-java-db-update --skip-check-update --skip-version-check --offline-scan --scanners vuln --cache-dir '.\trivy-cache' --timeout 160s --format json --output 'observed-v0222.trivy.json' $img
```

**Ограничение:** `docker:` и `--image-src docker` исключают remote image fallback; Trivy `--offline-scan` и `--skip-*-update` предотвращают соответствующие сетевые операции. Однако на самом Windows-хосте сетевой egress **не был аппаратно/на уровне ОС заблокирован**. Нельзя выдавать эту проверку за доказательство network air-gap. Доступ к Docker daemon был только на выделенном Windows-хосте. Внешняя LLM, Telegram, production VPS, YFC и Second Brain не вызывались.

## 3. Полученные артефакты (только в локальном закрытом каталоге)

| Файл | Размер | SHA256 |
| --- | ---: | --- |
| Native Syft JSON | 11,218,445 B | `42ef71ed3a5bcdc4d54a0fc7da09ca7fa05fe5fb5f94add598bcc7d3b4c05cd0` |
| CycloneDX JSON (1.7) | 4,877,242 B | `632bcafe252dee43a6f99c30445cc3a3ba8145e006a63f175606d81a640b6ca4` |
| SPDX JSON (2.3) | 8,470,651 B | `0d6684d8a3f5c26f7ce290b63c8a7d2b348764e47161ea8cc19f35802eb9913d` |
| Native Trivy JSON | 10,923,517 B | `327322f3ce83049977be859c51d152a45851d00627549b264d37bcb61bfec90d` |
| Local review manifest (UTC-normalized) | создан | `e3809137c4ed6acc98e8b5bc4ee0ba579f87f44ae59067d4aa0e7a139de4cc20` |

Syft распознал **2 080** package artifacts (1 038 Rust crates, 412 npm, 317 Python, 281 Debian, 30 binary, 2 Go modules). `syft convert` сообщил 4 205 компонентов CycloneDX и 2 081 пакетов SPDX; это **разные представления**, не независимая идентификация дополнительных пакетов. Отчёты не прошли внешнюю проверку полной JSON Schema или подписанную publisher attestation. Raw SBOM и CVE JSON **не коммитились** во избежание неуместной публикации полного инвентаря.

Syft `1.54.1` пишет источник в `source.metadata` (не `source.target`). `metadata.repoDigests` и `source.version` соответствуют pinned RepoDigest. Однако локально восстановленный `metadata.manifestDigest=sha256:6ba8a846b9179ad61c85fd8aff77750d6e5c177e40dbf2ed444988f905fd524d` **НЕ совпал** с `a11574b7...`. Новый валидатор показывает `syft_local_manifest_matches_pinned_repo_digest=false`, вместо ложного происхождения сборки. Причина несовпадения отдельно не доказана.

## 4. CVE-находки Trivy (НЕ заключение об эксплуатируемости)

| Severity | Raw findings |
| --- | ---: |
| CRITICAL | 4 |
| HIGH | 270 |
| MEDIUM | 1 173 |
| LOW | 1 055 |
| UNKNOWN | 20 |
| **Всего** | **2 522** |

Всего **1 496 уникальных идентификаторов уязвимостей** в 2 522 записях. Одна CVE может присутствовать в нескольких пакетах; сканер использует severity разных источников и предупреждает о возможных неточностях Third-party SBOM. Это данные Trivy на дату указанной DB.

Четыре пометки `CRITICAL`:

| ID | Компонент | Installed | FixedVersion в Trivy |
| --- | --- | --- | --- |
| `CVE-2026-6653` | libxml2 | `2.12.7+dfsg+really2.9.14-2.1+deb13u3` | нет в отчёте |
| `CVE-2026-43185` | linux-libc-dev | `6.12.111-1` | нет в отчёте |
| `CVE-2026-60002` | openssh-client | `1:10.0p1-7+deb13u4` | нет в отчёте |
| `CVE-2026-102268` | PyJWT | `2.13.0` | `2.14.0` |

Ни одна запись не означает автоматического remote exploit: нужны vendor advisories, сопоставление фактических используемых функций и исправленной upstream версии. Не менять пакеты внутри официального образа «на месте»: это изменит digest и обнулит прежние evidence.

## 5. Строгая машинная проверка

До этого этапа `scripts/review_syft_trivy_evidence.py` ожидал устаревший `source.target` и не принял бы настоящий Syft JSON. В этом PR добавлена поддержка `source.metadata` с обязательным совпадением `source.name/version`, `metadata.userInput/repoDigests`, OS/architecture, локального manifest hash/id; если локальный hash отличен, этот факт остаётся явно в отчёте. Дополнительно Trivy `Metadata.Reference/RepoDigests` и `Trivy.Version` сверяются с input manifest, результаты агрегируются в фиксированные поля без сырых описаний.

С фактическими тремя локальными JSON файлами валидатор вернул:

```json
{
  "status": "HIGH_CVE_REVIEW",
  "syft_artifact_count": 2080,
  "syft_local_manifest_matches_pinned_repo_digest": false,
  "trivy_vulnerability_count": 2522,
  "trivy_high_critical_count": 274,
  "trivy_unique_vulnerability_ids": 1496,
  "scanner_reports_hash_checked": true,
  "complete_sbom_verified": false,
  "source_to_image_provenance_verified": false,
  "scanner_binary_provenance_verified": false,
  "vulnerability_coverage_verified": false,
  "resident_agent_allowed": false
}
```

Код завершения **2**, даже при валидном входе. Значения SHA256 файлов в manifest проверены, но manifest сам по себе не подписан издателем. Данные **не** передавались на VPS и не были подключены к working Ops/QA/Research pipelines.

## 6. Решение и дальнейшие gates

**H-18 = PARTIAL EVIDENCE, HIGH_CVE_REVIEW. H-01 #33 = NO-GO.** Для эксплуатационного допуска обязательны независимые signed source -> build -> image provenance, подтверждение scanner/DB supply-chain signatures, CVE applicability и исправлений (особенно CRITICAL), проверка complete SBOM/лицензий, реальные native tool security boundaries, load burn-in/rollback и подтверждённые fail-closed запреты платных API. Отсутствие любого элемента означает `INCONCLUSIVE`/NO-GO, не фиктивный PASS.

Следующий отдельный шаг - расследование каждой CRITICAL с официальными vendor advisories и проверка fixed upstream image/действительного mitigations, без production deploy.
