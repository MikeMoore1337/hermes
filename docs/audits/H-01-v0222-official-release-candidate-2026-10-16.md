# H-01 #33 - новый upstream Hermes v0.22.2: кандидат, не допуск к запуску

> **Позднейшая отдельная проверка того же дня:** pinned Docker-образ был
> загружен и проверен в изолированном Windows Docker Desktop. На исходном
> официальном v0.22.2 подтверждён native tool-scope gap; локальная derivative
> с ограниченным патчем дала bounded synthetic PASS. Читайте
> [последующий аудиторский акт](H-01-v0222-pinned-runtime-native-policy-2026-10-16.md).
> Ни один результат не разрешает resident Agent или production runtime.

Дата проверки: 16.10.2026. Контур: отдельный Windows ПК, **только read-only
GitHub/Git metadata и Docker Hub manifest metadata**, без загрузки Docker image,
контейнера, моделей или изменений VPS.

## 1. Обнаруженный release-риск

Официальная страница [NousResearch v0.22.2](https://github.com/NousResearch/hermes-agent/releases/tag/v0.22.2)
датирует выпуск 15.10.2026 и **прямо сообщает**, что v0.22.1 был собран
из неверного commit; в нём попала ещё не выпущенная gateway-работа.
v0.22.2 исправляет эту release-ошибку и отказ gateway после reboot.
Отмечено ограничение на удаление sessions, созданных под 0.22.1.

Это означает, что предыдущая проверка exact v0.22.1
`sha256:cd9cb455576d27c9b6311de1104494ad7e221b6e68dc77e9ac2a8af661a4dc21`
остаётся доказательством **только для того образа**. Она не переносится на новый.

## 2. Read-only идентичности нового кандидата

- Официальная annotated tag reference `refs/tags/v0.22.2`:
  `7b77e29eedd85a8497ce2821448dac7964dc46f6` (через git ls-remote).
- Peeled source commit `refs/tags/v0.22.2^{}`:
  `d923a5eb487a17c0a68801bba9ef0f56c81040a8`.
- Docker Hub `nousresearch/hermes-agent:v0.22.2`, наблюдаемый
  multi-platform manifest list digest:
  `sha256:36099926da316742423544e055d4734777105ffe6341873af5459b957d0c2919`.
- Наблюдаемый **AMD64** platform manifest:
  `sha256:a11574b7fe8e1631d7d88d556677dac693bc058abf558cdeb899155688c1bf05`.
- Наблюдаемый ARM64 platform manifest:
  `sha256:6793b8c89a44872fc9a5ef135ac0c28bf0a7b9caf4968278195b14e43919aef5`.

Docker manifest получен через `docker buildx imagetools inspect` **без pull**.
Значения наблюдены в указанное время, но НЕТ сверки с подписанным official
release receipt, source-to-build attestation, vulnerability report или локальным
запуском exact digest. Совпадение номера v0.22.2 само по себе не проверка.

## 3. Транзитивная runtime-уязвимость не устранена сменой release

У официального upstream source `pm/lock.json` **в обоих** exact commits
`297552a9...` (v0.22.1) и `d923a5eb...` (v0.22.2):

- Python: **3.14.7+20260901**, linux-x64 archive SHA256
  `0ab3305457051cd3e7c031857e005f1bda17c218a1990567dacaaac6dd1d14f0`;
- Node: **26.7.0**, linux-x64 SHA256
  `982aa24dd8be4c889c6a8ab337ddff3b0896645b20f4239356e80552c16277ee`;
- npm: **12.0.2**.

Официальный [Python 3.14.8 security release](https://www.python.org/downloads/release/python-3148/)
от 30.09.2026 устраняет в том числе CVE-2026-15310
(zipfile memory exhaustion), CVE-2026-19672 (tarfile filter bypass),
CVE-2026-15806 (HTTPPasswordMgr credential scheme), CVE-2026-19445,
CVE-2026-19553 и CVE-2026-17084. В текущем upstream pin 3.14.7 эти
исправления **не подтверждены**. Эксплуатируемость конкретного пути Hermes
не оценена; CVE impact remains `POTENTIALLY_AFFECTED`, не объявлять
эксплуатацию доказанной или опровергнутой.

## 4. Следующая проверка в отдельном непроизводственном Docker

1. Получить/проверить официальный signed receipt / source-image provenance
   и сравнить с immutable AMD64 manifest `a11574b7...`.
2. Проверить exact embedded source commit, OS/Python/Node/npm inventories,
   полный SBOM, лицензии/CVE; только после проверки ресурсоёмкости и на
   **отдельной Windows Docker Desktop**, без нагрузки на production VPS.
3. На новом official source повторить negative native-tool policy tests,
   выяснить применимость [локального v0.22.1 patch](../../patches/upstream/hermes-v0.22.1-native-tool-policy.patch)
   и отдельно проверить full tool/MCP boundaries. Старый patched PASS нельзя
   считать новым PASS.
4. Повторить тесты устойчивости, квот Cloudflare/биллинга и нагрузки.
   Окончательный GO - только после owner approval и выполнения #33/#62.

## Статусы

- `RELEASE_TAG_AND_MANIFEST_METADATA_OBSERVED`: **PASS**.
- `SOURCE_TO_BUILD_PROVENANCE_VERIFIED`: **NO_DATA**.
- `COMPLETE_SBOM_AND_CVE_CLOSED`: **NO_DATA / POTENTIALLY_AFFECTED**.
- `V0222_NATIVE_TOOL_SCOPE_VERIFIED`: **NOT_RUN**.
- `V0222_RESIDENT_LOAD_BURN_IN`: **NOT_RUN**.
- `PRODUCTION_DEPLOYED`: **NO**.
- `resident_agent_allowed`: **false / NO-GO**.

Эта запись не изменяет production, systemd, токены, платные API или
средства защиты. Никакой новый image не скачивался и не исполнялся.
