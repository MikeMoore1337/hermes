# H-470 - точные upstream источники, лицензии, границы безопасности

Проверено 2026-11-05 по публичному GitHub API, для [итоговой матрицы 20 направлений](H-470-final-independent-acceptance-2026-11-05.md). HEAD в таблице - **текущая ревизия публичного источника**, не новый разрешённый к установке pin и не замена ранее проверенным SHA в дочерних документах. License metadata означает только метаданные **репозитория**, не права на любой конкретный файл. UNKNOWN и NOASSERTION не считать MIT по умолчанию. Новых upstream-файлов в Hermes **не копировали**; у действительно исполняемых оригинальных native-probes проверялись отдельные pinned исходники v0.22.2 в #474/#475.

## Реестр источников для направлений 1-20

| № | NousResearch | Проверенный HEAD / release pin | Repo-level license и принятое использование |
|---|---|---|---|
| 1 | [hermes-toolperf-evals](https://github.com/NousResearch/hermes-toolperf-evals) | 4e13ec24fafe94f48c9d96f4bdadb6b5577ebc02 | UNKNOWN, только методика |
| 2, 7 | [hermes-agent](https://github.com/NousResearch/hermes-agent) | **pinned v0.22.2** d923a5eb487a17c0a68801bba9ef0f56c81040a8 | root MIT; live delegation/real memory не разрешены |
| 3 | [kanban-video-pipeline](https://github.com/NousResearch/kanban-video-pipeline) | a464bdda58d9d7784225d972668129323de519a3 | UNKNOWN; методика, без второго DAG |
| 4 | [hermes-paperclip-adapter](https://github.com/NousResearch/hermes-paperclip-adapter) | 937ea71a34f5efcaa3834b11fdd08cfc1c99cb2c | MIT, DEFER |
| 5a | [hermes-example-plugins](https://github.com/NousResearch/hermes-example-plugins) | fb6726740efccccd56ddb117c25f1d1f3d4edd65 | MIT, synthetic review |
| 5b | [hermes-official-plugins](https://github.com/NousResearch/hermes-official-plugins) | 83f0a896b3518c7131181838e340c9a80c79524d | MIT, repo обновился со времени исследования; плагины не ставить |
| 6 | [agent-governance-toolkit](https://github.com/NousResearch/agent-governance-toolkit) | d93e32c526ef1a7282cfb3508665e8293cf05800 | MIT, только подход к проверке owner permissions |
| 8 | [hermes-compression-eval](https://github.com/NousResearch/hermes-compression-eval) | b65773b401874863b3dab94d6b0bd3d19fd95688 | UNKNOWN, только методика |
| 9 | [hermes-agent-self-evolution](https://github.com/NousResearch/hermes-agent-self-evolution) | 0a929e3aa20e15cf04dc7c28492a7d41a5139125 | license metadata UNKNOWN, README заявляет MIT; код не переносился |
| 10, 16a | [autoreason](https://github.com/NousResearch/autoreason) | 538f8817550e7c76c92355a967c5363d55ef9659 | UNKNOWN, только A/B/AB методика |
| 16b | [nomos](https://github.com/NousResearch/nomos) | f7008a065072d11088878e2f499776a5ae4b5c95 | MIT, только методика |
| 11 | [Open-Reasoning-Tasks](https://github.com/NousResearch/Open-Reasoning-Tasks) | 35df7000b8f636178e303add868415b30f92cad0 | Apache-2.0, без копирования датасетов |
| 12a | [Gym](https://github.com/NousResearch/Gym) | 2d538be189de0e21c21b85af05acf7646b1b092f | Apache-2.0, не устанавливался |
| 12b | [harbor](https://github.com/NousResearch/harbor) | 783b9670dfe5573930c590a3b4971371a31af4b4 | Apache-2.0, не устанавливался |
| 13 | [Hermes-Function-Calling](https://github.com/NousResearch/Hermes-Function-Calling) | ea3c4723e4cefdac760d483ccac6c8a428c95ab8 | MIT, методика |
| 14 | [hermes-labs-plugins](https://github.com/NousResearch/hermes-labs-plugins) | a6c7854f6fbd8ec8109199d5ded0c9c871c069d6 | MIT, только концепция Inbox |
| 15 | [TextArena](https://github.com/NousResearch/TextArena) | 2f20590f0993255221975cffa1890dcc550bf6a5 | MIT, игровой сервер не нужен |
| 17 | [autonovel](https://github.com/NousResearch/autonovel) | d165f267a0ffd34f3b0a70a8a72ac38cb8e4a542 (branch master) | UNKNOWN, только методика |
| 18a | [creative-writing-bench](https://github.com/NousResearch/creative-writing-bench) | e7ab00917c96aeae577e3eeea15eba882be9d5e0 | UNKNOWN, методика |
| 18b | [longform-writing-bench](https://github.com/NousResearch/longform-writing-bench) | d1c625505b1cf8baf32a49c8e21a9cf93a254044 | UNKNOWN, методика |
| 19 | [litellm](https://github.com/NousResearch/litellm) | 1e6c1f84c782f63fea90f6fbc0781d552ec01de2 | NOASSERTION, не переносить |
| 20 | [iroh](https://github.com/NousResearch/iroh) | d915bfdff45235f90e06e7a8502bebebd6621857 | Apache-2.0; решение #479 бумажное NO_GO |

**Compatibility scope:** исходники offline-инструментов Hermes написаны отдельно, без новой обязательной запускаемой зависимости от этих upstream-проектов. Для настоящих native tools, MCP, Paperclip, стороннего plugin, FTS5 ingest, P2P и модельной оценки **нет** текущего общего integration/API/license GO. Разные лицензии отдельных файлов, транзитивных зависимостей и supply-chain должны проверяться **до** отдельного разрешённого переноса, не выводиться из этой таблицы.

## Обновление решения по Hermes Agent upstream: v0.22.2 -> v0.22.7

Предыдущий исторический [аудит v0.22.4](H-470-upstream-v0222-v0224-decision-2026-10-23.md) и [PR #531](https://github.com/MikeMoore1337/hermes/pull/531) остаются корректной квитанцией **на дату 23.10**. Новый [официальный стабильный релиз v0.22.7](https://github.com/NousResearch/hermes-agent/releases/tag/v0.22.7) опубликован **2026-11-03**, commit **b200f5bc60e31588ba2cb60e288029c4a54ba5fa**. В нём, по release notes, изменения после v0.22.6 многочисленны; release notes для полной серии обещаны в v0.23.0 и пока не являются полным контрактным аудитом.

Проверка реальных GitHub objects у v0.22.2 и v0.22.7:

| Артефакт | v0.22.2 | v0.22.7 | Следствие |
|---|---|---|---|
| Base commit | d923a5eb487a17c0a68801bba9ef0f56c81040a8 | b200f5bc60e31588ba2cb60e288029c4a54ba5fa | не тот же source tree |
| root LICENSE blob | 75410e73319c72cd3e991a501c5455eb78f38375 | тот же | MIT root unchanged |
| root Dockerfile blob | e3d11031c8d65e5bf047d25b2cc224cf757988b1 | d51e9774d1a827d3dc88d2c785fde7670c205e14 | container recipe CHANGED |
| pyproject.toml blob | 5145f275d14a0ab119802821c715a33123b15551 | ee469ebe183308f4885dc0ec449c43a181fca71c | metadata/deps CHANGED |
| uv.lock blob | 765bf23d7c90461d60497e268932f518d880ea47 | 7688ebfc4b0078bf266c5b47d8078487bd81e36e | full dependency diff NOT_RUN |
| requires-python metadata | >=3.11,<3.15 | >=3.11,<3.15 | не подтверждает runtime/ABI PASS |

GitHub compare [v0.22.2...v0.22.7](https://github.com/NousResearch/hermes-agent/compare/v0.22.2...v0.22.7) возвращает **7362 commits ahead, 0 behind**, а файл-список усечён до 300. Считать эту выборку полным аудиторским diff нельзя. Новые API/MCP/plugin contracts, native tool guards, CI, lock/dependency delta, image builds, SBOM/CVE, Docker rollback и живой low-memory smoke **NOT_RUN / NOT_VERIFIED**. Вся дальнейшая runtime-проверка принадлежит [#33](https://github.com/MikeMoore1337/hermes/issues/33) / [#199](https://github.com/MikeMoore1337/hermes/issues/199), а не #470.

В действующем Hermes [deploy/require-patched-agent-image.sh](../../deploy/require-patched-agent-image.sh) требует неизменных **hermes.base.commit=d923a5eb487a17c0a68801bba9ef0f56c81040a8** и **hermes.native.tool.policy=bounded-v0222**, плюс локальный exact sha256 image ID. Любой непроверенный новый базовый образ **FAIL CLOSED**. **KEEP_PINNED / DEFER_UPGRADE**, никакого lockfile edit, загрузки образа или смены production в исследовательской #470. Возможное обоснованное обновление - лишь отдельное техническое предложение и explicit owner GO.

## Безопасность и качество доказательств

| Контроль из #470 | Итог на уровне этого read-only/source review |
|---|---|
| 1. Несанкционированные платные модели/API | **PASS** (в этой проверке model/API calls=0). Исторические списания и токены **NOT_MEASURED**, не $0 measured |
| 2. Tool permissions | **PASS** synthetic/isolated #350; реальные resident OS/MCP rights **NOT_VERIFIED** |
| 3. Synthetic / real separation | **PASS**: автономные fixtures, фиктивные SHA/approval, честный no-live |
| 4. Private Second Brain | **PASS** для проверенного source data scope; реальная OS segregation **NOT_VERIFIED** |
| 5. Hermes BRC isolation | **NOT_APPLICABLE** к этой приёмке: BRC не вызывали и не изменяли; его безопасность не оценивали |
| 6. Непроверенные production scripts | **PASS** для этой docs-only поставки: никаких VPS команд, изменений services или установки |
| 7. Ограничение ресурсов | **PASS** для synthetic limits; real VPS CPU/RSS **NOT_MEASURED** |
| 8. Защита от ложного PASS | **PASS** на офлайн-oracles; не распространяется на реальные agent/tool effects |
| 9. Доказуемое происхождение | **PARTIAL**: source SHA, CI и часть исторических CD проверены; live host подтверждений недостаточно |
| 10. Нет новых полномочий | **PASS**: этот раунд не выдавал grants и не менял runtime |

**Overall security: PARTIAL** для Hermes production. Выбор «не интегрировать» не равен «уязвимостей нет». В будущем нужны отдельные owner gates и конкретные негативные E2E для any live native/MCP/models.

## Известные ограничения

- Неподтверждённые repo-level лицензии для методических источников **не означают** разрешение копировать код. Копирования в эту приёмку не было, при фактическом переносе права пересмотреть.
- PR/CI HEAD и merge commit могут отличаться. Исторический source-only CD не устанавливает runtime capability. Оценка сокращения расхода/токенов/латентности не выполнялась.
- #478 закрыт только в пределах offline 26 synthetic RU cases; real blinded independent expert review, scientific facts, author voice, semantic fidelity - NOT_RUN/NOT_VERIFIED.
- #474 may inherit effective parent toolsets: модельная роль/текст политики не являются OS/MCP enforcement. Не разрешать real delegate_task до независимого scope proof и owner GO.
- До завершения отдельно утверждённых испытаний #33/#454/#291 и применения будущих ограничений #350 состояние реального агентного E2E - NOT_VERIFIED. Они **не** являются условиями закрытия исследовательской программы #470.

Изменения этой приёмки ограничены документацией и статусными квитанциями. Production changed: **NO**.
