# Hermes #468 · Operator Inbox / combined Atlas design

**Visual gate:** the owner approved a **combined** concept on 22.10.2026:
retain graphite/blue Atlas, add a justified high-level summary and cards,
then a filterable operator queue with right-side source status and event
evidence. Approval is for **this design scope**, not for new tool or runtime
authority. [Issue #468](https://github.com/MikeMoore1337/hermes/issues/468)
remains the single owner of feature behavior.

## Implementation boundary

The existing Control Center React navigation gets an `Operator Inbox` view;
other views, authentication/login and navigation styling are unchanged.
A dedicated `/api/operator/inbox` (+ existing `/control-center/api/` alias)
uses the same owner session (GitHub OAuth mode) or the existing Caddy
Basic Auth proxy boundary, fixed loopback server and CSP. The route is **GET /
HEAD only**. No command, retry, acknowledge, write or publication buttons.

### Layout, responsive and states

The approved mixed composition contains:

1. Title, fixed read-only disclosure and refresh (fetch only).
2. Four overview cards: events; critical; needs review; available/total sources.
3. Coverage notice if any source is not fully supported.
4. Category filters for failure / needs review / blocked / in progress,
   a bounded text search and a chronological/source-aware event queue.
5. Independent right-side source coverage panel and read-only selected-event
   detail. Mobile stacks the same content; no hidden table requiring lateral scroll.

Loading hides historical numbers; API errors hide all event rows; empty queue
states **explicitly warn** that missing sources do not imply health.
Buttons and source links never perform remote actions.
Screenshots and browser QA use **synthetic fixtures**, not real owner data.
No synthetic screenshot can prove the state of any live service.

## Source inventory

| Source | Availability in this issue | Data used | Not claimed |
| --- | --- | --- | --- |
| systemd overview | **SUPPORTED** only for recent complete exact allowlisted snapshot | Fixed labels, state, generated timestamp | Successful agent outputs or healthy BRC |
| Codex scheduler | **PARTIAL** if existing read-only queue DB is configured | Aggregate *blocked* and *deferred* counts only | Individual job approval, success or receipt |
| Hermes BRC | **NOT_AVAILABLE** | No device lookups | Online/offline inventory, lost ACK or expired session |
| Production delivery | **NOT_AVAILABLE** | No release log reader | CI as delivery proof |
| Ops Watch incident log | **NOT_AVAILABLE** | No incident DB access | Incident stream or activity history |

`STALE` is separate from `SUPPORTED`. A missing snapshot leaves source
`NOT_AVAILABLE`, while an expired one yields a stale warning event.
`active` means only a systemd state, never successful task execution;
restricted full-Agent `blocked` is not an incident.

Read-only event schema:
`source`, `event_id`, `status`, `severity`, `category`,
`observed_at`, `last_verified_at`, `action_hint`,
`evidence_link`, `scope` plus fixed short title and detail. Unknown
verification time uses `null`, never fabricated UTC; source links are fixed
existing protected APIs. Event dedup by `source:event key`, up to 24 items;
no storage, no external link from user fields.

## Trust, privacy and budgets

- Only `snapshot_path` and `scheduler_path` already passed to the existing
  handler; no arbitrary file paths, shell, subprocess or new data connector.
- The overview reader limits payload to 128 KiB and rejects symlinks.
  Fixed unit IDs and systemd states are checked; name/agent_policy from the
  overview and scheduler job IDs/error codes are not forwarded.
- Never expose private notes, BRC tokens or arbitrary CI log/error text.
- Existing OAuth owner session or proxy Basic Auth boundary retained.
  Do not claim the loopback `proxy` mode alone authenticates users;
  the existing Caddy policy is essential in production.
- 60s refresh only while the view is mounted and document visible; no service,
  background polling process, model, paid API or new terminal command.
- No alert acknowledgments or source mutation. User exploration is only
  local React state plus GET of allowed API.

## Reproducible QA

```bash
python3 -m unittest tests.test_control_center_operator_inbox tests.test_control_center_inbox_http -v
cd control_center/frontend
npm ci --ignore-scripts --no-fund --no-audit
npm run build
npm run test:e2e
```

CI must validate all existing Python, PWA/OAuth and Playwright cases on
the exact PR SHA. The #468 Playwright suite tests 320/393/768/1440 px,
desktop/mobile event filtering, keyboard selection, empty/stale/error
states, redirects and absence of write or external API calls.

**Release:** `SOURCE_ONLY` until existing protected GitHub Actions quality
and UI jobs finish, `control_center/web` build matches source,
a clean reviewed PR merges and the verified production job logs installed SHA.
Actual owner BRC/deployment status remains `NOT_VERIFIED` even if the UI
source is successfully delivered.

**Visual source:** chat approval of the combined concept (the three-sketch
Toolkit/Impeccable comparison and the two Atlas mockups), not GitHub's prior
screenshot assets. Read-only generated CI screenshots are solely regression
evidence; production data and actual authenticated UI screenshots are not
included.


## Дополнение #717: GitHub Observe как шестой источник

В существующий одобренный Operator Inbox добавлена **только проекция
метаданных**, без редизайна, нового компонента React или CSS. Источник
\`github_observe\` отображается через действующую разметку и
\`/api/operator/inbox\`; статусы \`PARTIAL/STALE/NOT_AVAILABLE\` не
подменяют успешное выполнение агента. События: новые Issues, комментарии,
изменения PR, проблемы quality CI; успешный CI не создает задачу на проверку.

Доставка из GitHub Actions использует прежнюю периодическую службу QA
Watcher (одно дополнительное обращение к строго зафиксированному
Actions endpoint) и root-owned защищённый снимок, затем существующий
Control Center snapshot collector. Сам owner-only веб-сервер **ничего
не запрашивает в GitHub** и не читает исходный токен/закрытую
директорию QA. Внешних ссылок из недоверенных payload не передаётся:
наблюдения показывают только числовые идентификаторы и фиксированные
русские рекомендации. Функциональный объём #468 и ранее
утверждённая композиция/цвета остаются прежними.

Эксплуатационные ограничения: интервал QA 15 минут; 12 самых свежих
workflow runs, окно 24 часа, снимок свеж до 45 минут; \`NO_DATA\` не
означает отсутствие незавершённых дел. Склейка повторов выполняется
по типу события и номеру Issue/PR; это **не гарантированная
exactly-once-доставка** и не долговременный журнал. Состояние
сохраняется в прежней корневой директории, отдельной базы/сервиса нет.
CLI и GitHub Actions по-прежнему запрещают execution, owner approval
не выводится из текста наблюдения. Реальную доступность после доставки
подтверждать чтением owner-only API либо независимым evidence receipt;
зелёный CI не равен подтверждённой production-панели.
