# Hermes - original Harness² upstream (optional developer integration)

This is a **thin bridge to the unmodified upstream**, not another optimizer, agent executor, importer, skill manager or Hermes runtime service. Dependency: [Toolkit #421](https://github.com/MikeMoore1337/ai-development-toolkit/issues/421), original [google-research/harness2](https://github.com/google-research/harness2) `main@1cfe254e8d25b15f37048c3730134686abe60335` (Apache-2.0).

## Required installation

On a separate **unprivileged Linux/WSL2 developer environment** install the original Harness² using Toolkit `integrations/harness2/install.sh install`. Do **not** install into production Hermes, VPS, BRC/Commander or a folder with project credentials. Do not add Python 3.12 packages to Hermes runtime. This integration does not download, modify or fork upstream.

Use only the official upstream CLI through the Hermes source-only helper:

```bash
bash scripts/harness2_upstream.sh status
bash scripts/harness2_upstream.sh setup-preview lab
# If upstream LAB setup was separately authorized and completed:
# bash scripts/harness2_upstream.sh check --bench lab
# If official upstream has already generated and judged results:
# bash scripts/harness2_upstream.sh report --bench lab --k 1 --mode parallel
```

The helper *only* checks pinned SHA/origin/marker and forwards to official `harness2-setup --dry-run`, `harness2-check` and read-only `harness2-report`. No `harness2` optimization run, `harness2-judge` (which can call a model), model calls, benchmark jobs or production activity can be launched through this integration. It does not parse or ingest agent transcripts, save credentials, write Hermes database or approve a new skill. A configured benchmark may perform preflight/network checks; never interpret that as a completed evaluation.

Source compatibility is limited to original JobBench, LAB and WorkBuddy-Bench. Hermes #465/#349 evaluation evidence remains independent and **not** an official Harness² benchmark. To use Hermes tasks directly as an upstream benchmark requires additional supported upstream development, **not** a replacement optimizer in Hermes.

This repo does **not** contain Harness² source. If the external installation is absent, all Hermes CI/release/runtime functions remain unchanged. When an official upstream benchmark is explicitly run later, preserve its original `runs/` outside Hermes; a useful read-only report requires actual official `judged.json` rows, and no improvement, safety or cost claims are inferred without those data.

Owner restrictions: no incremental spend, no paid API, no Codex/Claude CLI, no disabled-sandbox Codex runner. Nothing in this helper removes `eval_lane/owner_spend_lock.py` or authorizes model-backed execution.


## Чтение штатных результатов Harness² как внешних метаданных

Для **настоящего** `runs/.../summary.json`, сформированного официальной версией
Harness² в отдельной пользовательской установке, предусмотрен read-only импорт
`scripts/harness2_upstream_manifest.py` (добавлено по #629):

```bash
# Сначала проверь официальную установку.
bash scripts/harness2_upstream.sh status

# Только если существует настоящий результат, сгенерированный original upstream:
python3 scripts/harness2_upstream_manifest.py runs/<namespace>/<task>/summary.json
```

Путь должен находиться **строго внутри** pinned checkout и `runs/`; запрещены
symlink, path traversal, крупные/неизвестные JSON, произвольные корневые каталоги
и неподтверждённый SHA источника. Из исходного `summary.json` выдаются только
проверенные на формат метаданные, собственный SHA256 файла и фиксированные флаги
`model_efficacy_verified=false`, `native_execution_observed=false`,
`review_status=SOURCE_METADATA_ONLY`. Не импортируются модельные тексты,
деливераблы, логи и секреты. Наличие файла не доказывает настоящий модельный
запуск и не означает согласия на использование выводов.

Этот JSON можно **вручную** приложить к существующим механизмам evidence Hermes.
Никакой автоматической записи в БД, обхода owner gate или новой системы
самообучения нет. Синтетические unittest проверяют только формат и отказы.
